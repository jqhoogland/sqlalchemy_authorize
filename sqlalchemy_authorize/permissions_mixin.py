from contextlib import contextmanager
from typing import List, Union, Optional

from sqlalchemy_authorize.constants import CRUD
from sqlalchemy_authorize.utils import classproperty, is_dunder


class BasePermissionsMixin:
    """BaseClass to add a field-level authorization policy to a ``db.Model``

    E.g.::

        class BaseUser(BasePermissionsMixin, db.Model):
            __permissions__ = BasePermissionsMixin.load_permissions(
                # Public permissions
                read=["id", "username"],

                # Role-based permissions
                self=[
                    # The user can provide ``username`` and ``fullname``
                    # to ``__init__`` (as keyword args) and to ``__setattr__``.
                    (["create", "update"], ["username", "fullname"]),

                    # The user can read/delete the entire model.
                    "read",
                    "delete"
                ],
                friend=[("read", ["fullname"])],  # (in addition to public "read")
                admin="*"  # i.e., all actions on all fields
            )

            id = db.Column(db.String(128), primary_key=True)
            username = db.Column(db.String(128), nullable=False)
            fullname = db.Column(db.String(128), nullable=False)
            ssn = db.Column(db.String(10), nullable=True)

    Permission is denied by default (unlike other flask-authorization
    libraries, where you typically have to wrap functions for
    authorization to be checked). Also unlike other libraries,
    permissions are at the field level. That's key to interoperability
    with libraries like :mod:`graphene_sqlalchemy`.

    Field-level permissions imply row-level permissions. If you are
    allowed to update ``BaseUser.username``, then you are assumed to
    have the update permission on ``BaseUser``.

    This assumes CRUD actions by default ("create", "read", "update",
    "delete"), where:

    - "read" fields: columns, composites, properties, relationships, *and methods/functions*.
    - "create" & "update" fields: columns or settable properties.
    - "delete" usually isn't concerned with individual fields.
       TODO: This will still currently fail if the method requires additional permissions.

    Using :class:`BaseUser`.

    >>> user = BaseUser(id="123")
    >>> sorted(user.roles)
    ['admin', 'public', 'self']
    >>> sorted(user.actions)
    ['create', 'delete', 'read', 'update']
    >>> user._protected
    True

    .. field-level authorization policy: <https://docs.osohq.com/guides/enforcement/field.html>`_.
    """
    __permissions__ = None

    DEFAULT_ACTIONS = [e.value for e in CRUD]
    PUBLIC_ROLE = "public"  # The name of the "public" / fallback role.

    def __init__(self, *args, protected=True, check_create=False, **kwargs):
        """Checks create permissions on each of the kwargs
        before initializing the model if ``check_create``.

        >>> BaseUser(id="123", check_create=True) # the current user doesn't have create permissions
        Traceback (most recent call last):
        PermissionError: ...
        >>> BaseUser(id="123", check_create=False)
        <BaseUser 123>

        The reason we can't check create permissions by default is that
        it disrupts the relational part of the ORM.

        """
        # ``self.__setattr__`` requires ``_protected`` to resolve.
        # This gets around that circular dependency.
        super().__setattr__("_protected", False)
        super().__setattr__("actions", self.__class__.actions)

        # For use with :meth:`Wrapper.allow` and :meth:`Wrapper.deny`
        self._allowed_fields = {action: [] for action in self.actions}
        self._forbidden_fields = {action: [] for action in self.actions}

        if check_create:
            with self.protected():
                for key in kwargs.keys():
                    self.authorize("create", key)

        # This requires this mixin to be included before SQLAlchemy's declarative base.
        # TODO: Filter kwargs for those with ``create`` permissions.
        super().__init__(*args, **kwargs)

        self._protected = protected

    @classmethod
    def load_permissions(cls, *, actions=None, **kwargs):
        r"""Convenience method for creating a ``__permissions__``
        dict. (You can also just pass a completed dictionary directly.)

        Final permissions dictionary is of the shape::

             {"<role>": {"<action>": ["field_1", "field_2"], ...}}

        where passing an empty list of field is equivalent to
        denying that action on the entire model.

        E.g.:

        >>> from pprint import pprint
        >>> pprint(BasePermissionsMixin.load_permissions(
        ...     read=["id", "username"],
        ...     self=[
        ...         (["create", "update"], ["username", "fullname"]),
        ...         "read",
        ...         "delete",
        ...         "custom_action"
        ...     ],
        ...     friend=[("read", ["fullname"])],
        ...     admin="*"
        ... ))
        {'admin': {'create': ['*'],
                   'custom_action': ['*'],
                   'delete': ['*'],
                   'read': ['*'],
                   'update': ['*']},
         'friend': {'read': ['fullname', 'id', 'username']},
         'public': {'read': ['id', 'username']},
         'self': {'create': ['username', 'fullname'],
                  'custom_action': ['*'],
                  'delete': ['*'],
                  'read': ['*'],
                  'update': ['username', 'fullname']}}


        :param actions: a list of actions to include (needed to
            expand wildcards like ``admin="*"``.)

            Defaults to CRUD + any custom actions found in
            the role fields.

        :param read: "public" read permissions. Defaults to None,
            i.e., not included / forbidden at row & field levels.
            If provided, this is copied into all other "read"
            permissions and to a new "public" role.

        :param create: "public" create permissions. Should typically
            not be used.

        :param update: "public" update permissions. Should typically
            not be used.

        :param delete: "public" delete permissions. Should typically
            not be used.

        :param kwargs: pairs of roles and permissions. E.g.::

            - ``"<role>": { "read": ["field_1", ...]}``  (leave as is)
            - ``"<role>": "*"`` (grant all permissions)
            - ``"<role>": [ "read", ("update", "id") ]`` (expand and fill
                          defaults).

        :return:
        """
        permissions = {}

        for action_name in cls.DEFAULT_ACTIONS:
            action = kwargs.pop(action_name, None)
            if type(action) is list:
                permissions["public"] = {action_name: action}

        # Get a list of all available actions
        # Do this before reading permissions in order to expand wildcards.
        if type(actions) is not list:
            actions = set(cls.DEFAULT_ACTIONS)

            for (role, permission) in kwargs.items():
                if type(permission) is str:  # "*"
                    continue

                for rule in permission:
                    if type(rule) is str:
                        # "<action>"
                        actions.add(rule)

                    elif type(rule) is tuple:
                        # (("<action>" | ["<action_1>", ...]), ["<field_1>", ...])
                        rule_actions, _ = rule

                        if type(rule_actions) is str:
                            # ("<action>", ["<field_1>", ...])
                            rule_actions = [rule_actions]

                        # (["<action_1>", ...], ["<field_1>", ...])
                        actions |= set(rule_actions)

            actions = list(actions)

        for (role, permission) in kwargs.items():
            permissions[role] = {}

            if type(permission) is dict:
                # Skip expansion & leave as is.
                # (``"friend": {"read": ["id", "username", "fullname"]}"``)
                permissions[role] = permission
            elif permission == "*":
                # Allow all actions. (``{"admin": "*"}``)
                permissions[role] = {action: ["*"] for action in actions}
            else:
                # Expand list rule into dict.
                for rule in permission:
                    if type(rule) is str:
                        # Allow this action on all fields.
                        # (``"self": ["read"]``)
                        permissions[role][rule] = ["*"]
                    else:
                        assert (
                            type(rule) is tuple and len(rule) == 2
                        ), "Invalid permission shorthand."

                        role_actions, fields = rule

                        if type(role_actions) is str:
                            role_actions = [role_actions]

                        # Our ``actions, fields`` tuple now has a form like:
                        # ``(["create", "update"], ["username", "fullname"])``
                        for action in role_actions:
                            # Copy over default read permissions from public (if there are any)
                            fields += permissions.get("public", {}).get(action, [])

                            permissions[role][action] = fields

        return permissions

    @property
    def permissions(self) -> dict:
        """Proxy for interacting with permissions dictionary."""
        return self.__permissions__

    @permissions.setter
    def permissions(self, value: dict) -> dict:
        """Setter for permissions dictionary proxy."""
        self.__permissions__ = self.load_permissions(**value)

    @property
    def exempted_fields(self):
        return (
            list(BasePermissionsMixin.__dict__.keys()) +
            [
                # Attributes that are set in ``__init__``.
                "_protected",
                "_allowed_fields",
                "_forbidden_fields",
                # SQL Alchemy generics.
                "_sa_instance_state",
                "_sa_class_manager",
                "_sa_registry",
                "_decl_class_registry",
                "permissions",
                "metadata",
                "registry"
                # You'll have to use another solution (like ``oso``)
                # if you want row-level authorization in queries.
                "query",
                "query_class",
            ]
        )

    # noinspection PyMethodParameters
    @classproperty
    def roles(cls) -> List[str]:
        """The roles that are included in ``self.__permissions__``."""
        return list(cls.__permissions__.keys())

    # noinspection PyMethodParameters
    @classproperty
    def actions(cls) -> List[str]:
        """The actions that are included in ``self.__permissions__``."""
        return list(
            set(
                [
                    action
                    for permission in cls.__permissions__.values()
                    for action in permission.keys()
                ]
            )
        )

    @property
    def always_allowed_fields(self) -> List[str]:
        """Attributes that do not require authorization.

        This is the opposite of :meth:``authorizable_fields``.
        """
        return [key for key in dir(self) if not self.requires_authorization(key)]

    @property
    def authorizable_fields(self) -> List[str]:
        """Attributes that should be checked for authorization

        This is the opposite of :meth:``always_authorized_fields``.

        For attributes that have been check for authorization,
        see :meth:`authorized_fields` or :meth:`authorized_fields_for`.
        """
        return [key for key in dir(self) if self.requires_authorization(key)]

    def authorized_fields_for(self, role: str, action: str) -> List[str]:
        """The fields that an actor with ``role`` is allowed to perform
        ``action`` on.

        This is a subset of ``authorizable_fields`` and won't include
        fields that are in ``always_allowed_fields``.
        """
        fields = self.permissions.get(role, {}).get(action, [])
        return fields

    def authorized_fields(self, action):
        """Returns all the ``authorizable_fields`` that the
        current user is allowed to perform ``action`` on."""

        fields = []

        for field in self.authorizable_fields:
            # noinspection PyBroadException
            try:
                self.authorize(action, field)
            except:
                # The exceptions will vary depending on how you implement
                # :meth:`authorize_field`.
                continue

            fields.append(field)

        return field

    def requires_authorization(self, key):
        """Checks whether an attribute ``key`` should be authorized.

        Exempted attributes include:

        - Methods/attributes on this mixin (``authorizable_fields``,
          ``always_allowed_fields``, etc.).
        - Dunder methods/attributes (i.e., ``__some_method__``).
        - SQLAlchemy generics (``_sa_class_manager``, ``_sa_instance_manager``).

        .. DANGER::
          You can still expose sensitive information through these
          unauthorized fields! This project bears no liability if
          you forget to be careful.

        """
        return (
            not is_dunder(key)  # E.g.: "__dict__"
            and key != "exempted_fields"
            and key not in self.exempted_fields
            and self._protected
        )

    def protect(self):
        """Turns on authorization."""
        self._protected = True
        return self

    def expose(self):
        """Turns off authorization.

        .. NOTE::
           It's recommended that you keep on authorization by default,
           and turn it off selectively with a context manager like
           :meth:`exposed` or (even better) :meth:`allowed`.
        """
        self._protected = False
        return self

    @contextmanager
    def protected(self):
        """Turns on authorization during the current context.

        When the context exits, returns to the prior ``_protected``.

        >>> user = BaseUser(id="123", protected=False)
        >>> user.id
        '123'
        >>> user.id = "456"
        >>> user.id
        '456'
        >>> with user.protected():
        ...     user.id = "123"
        Traceback (most recent call last):
        PermissionError: ...
        >>> user.id
        '456'

        .. NOTE::
           It's recommended that you keep on authorization by default,
           and turn it off selectively with a context manager like
           :meth:`exposed` or (even better) :meth:`allowed`.
        """
        was_protected = self._protected
        self.protect()

        try:
            yield
        finally:
            self._protected = was_protected

    @contextmanager
    def exposed(self):
        """Turns off authentication during the current context.

        .. NOTE::
           When possible, consider more granularly relaxing permissions
           via :meth:`allowed` to relax particular actions on
           particular fields.

        """
        was_protected = self._protected
        self.expose()

        try:
            yield
        finally:
            self._protected = was_protected

    def allow(
        self,
        action: Union[str, List[str]],
        field: Optional[Union[str, List[str]]] = None,
    ) -> List[str]:
        """Allow ``action`` (s) on ``field`` (s).

        .. NOTE::
           Consider using :meth:`allowed` instead, to restrict
           additional permissions to a ``with`` statement.

        :param action: The action(s) to allow.
        :param field: Which field(s) to allow ``action``(s) on,
            defaults to allow ``action`` on all fields.
        :return: ``action`` as list.
        """
        if field is None:
            field = self.authorizable_fields
        elif type(field) is str:
            field = [field]

        if type(action) is not list:
            action = [action]

        for a in action:
            self._allowed_fields[a] = field

        return action

    def deny(
        self,
        action: Union[str, List[str]],
        field: Optional[Union[str, List[str]]] = None,
    ) -> List[str]:
        """Deny ``action`` (s) on ``field`` (s).

        :param action: The action(s) to deny.
        :param field: Which field(s) to deny ``action``(s) on,
            defaults to deny ``action`` on all fields.
        :return: ``action`` as list.
        """
        if field is None:
            # Allow action on all fields
            field = self.authorizable_fields
        elif type(field) is str:
            field = [field]

        if type(action) is not list:
            action = [action]

        for a in action:
            self._forbidden_fields[a] = field

        return action

    @contextmanager
    def allowed(
        self,
        action: Union[str, List[str]],
        field: Optional[Union[str, List[str]]] = None,
    ):
        """Allow ``action`` (s) on ``field`` (s) during the
        current context.

        >>> user = BaseUser(id="123")
        >>> user.id = "456"
        Traceback (most recent call last):
        PermissionError: ...
        >>> user.id
        '123'
        >>> with user.allowed(CRUD.UPDATE.value):
        ...     user.id = "456"
        >>> user.id
        '456'
        >>> with user.allowed(CRUD.UPDATE, "fullname"):
        ...     user.fullname = "John Doe"
        ...     user.username = "jdoe"
        Traceback (most recent call last):
        PermissionError: ...
        >>> with user.allowed(CRUD.READ, ["fullname", "username"]):
        ...     print(user.fullname)
        ...     print(user.username)
        John Doe
        None

        :param action: The action(s) to allow.
        :param field: Which field(s) to allow ``action``(s) on,
            defaults to allow ``action`` on all fields.
        """
        actions = self.allow(action, field)

        try:
            yield
        finally:
            for a in actions:
                self._allowed_fields[a] = []

    @contextmanager
    def denied(
        self,
        action: Union[str, List[str]],
        field: Optional[Union[str, List[str]]] = None,
    ):
        """Temporarily deny ``action``(s) on ``field``(s)
        (optionally restricted to ``field``).

        >>> user = BaseUser(id="123")
        >>> user.id
        '123'
        >>> with user.denied(CRUD.READ, "id"):
        ...     user.id
        Traceback (most recent call last):
        PermissionError: ...

        :param action: The action(s) to deny.
        :param field: Which field(s) to deny ``action``(s) on,
            defaults to deny ``action`` on all fields.
        """
        actions = self.deny(action, field)

        try:
            yield
        finally:
            for a in actions:
                self._forbidden_fields[a] = []

    # noinspection PyMethodMayBeStatic
    def error(self, action: str):
        """Returns an appropriate exception for the action.

        This method expects to be overloaded. E.g.:
        :class:`OsoPermissionsMixin` will raise a
        :exec:`ForbiddenError` for create/update/delete, but a
        :exec:`NotFoundError` for reads.

        :returns: Permission Error (does not raise this error!)
        """

        return PermissionError(f"Current user is not allowed to perform '{action}'.")

    def authorize_field(self, action: str, key: str):
        """This is where you actually implement the check.
        For an example, see :class:`OsoPermissionsMixin`.

        Usually, you can rely on this being called indirectly
        (when setting/getting/deleting attributes).

        This is meant as a placeholder method, not a working
        example, that authorizes only public actions. In practice,
        you'll want to implement your role-based / relation-based
        / attribute-based access control here (or use a solution
        like :mod:`oso`).

        :param action: One of CRUD or a custom action.
        :param key: The attribute/field to authorize.
        :returns: ``None`` if the action is allowed.
        :raises: :exec:`PermissionError` (or some custom error like
            :exec:`oso.ForbiddenError`) if not allowed.
        """

        if key in self.authorized_fields_for("public", action):
            return

        raise self.error(action)

    def authorize(self, action, key):
        """Check whether the current user is allowed to perform
        ``action`` on ``self.model.<key>``.

        First checks for exceptions to normal ``oso`` rules due
        to :meth:`allow` or :meth:`deny`, otherwise passes
        the authorization request on to ``oso``.

        """
        if key == "requires_authorization" or not self.requires_authorization(key):
            return

        if key in self._forbidden_fields.get(action, []):
            if action == "read":
                raise self.error("read")

            # If we're not even allowed to read the currently model,
            # throw a not found error, otherwise fallback to a
            # forbidden error.
            self.authorize("read", key)
            raise self.error(action)

        elif key in self.authorizable_fields and key not in self._allowed_fields.get(
            action, []
        ):
            # Required to avoid sending oso into a self-referential death spiral.
            with self.exposed():
                self.authorize_field(action, key)

            return None

    def __setattr__(self, key, value):
        """Checks whether the current user is allowed to
        set the current attribute before setting."""
        self.authorize(CRUD.UPDATE, key)
        return super().__setattr__(key, value)

    def __getattr__(self, item):
        # Pre-initialized, these fields haven't yet been defined
        if item in ["_allowed_fields", "_forbidden_fields"]:
            return {}
        elif item == "_protected":
            return False
        elif item == "__name__":
            return type(self).__name__
        elif item in dir(self):
            # TODO: Don't know why we sometimes end up here.
            self.authorize(CRUD.READ, item)
            return self.__dict__[item]

        raise AttributeError(f"'{self.__name__}' has no attribute '{item}'")

    def __getattribute__(self, item):
        """Checks with authorizer whether the current user is allowed
        to read the current attribute before returning the value."""
        if item != "authorize":
            self.authorize(CRUD.READ, item)

        return object.__getattribute__(self, item)

    def __delattr__(self, item):
        """Checks with authorizer whether the current user
        is allowed to delete the current attribute before returning
        the value.

        .. NOTE::
           This shouldn't be necessary very often, as we're typically
           more interested in protecting rows from being deleted than
           pseudocolumns in the ORM super().
        """

        self.authorize(CRUD.DELETE, item)

        super().__delattr__(item)

