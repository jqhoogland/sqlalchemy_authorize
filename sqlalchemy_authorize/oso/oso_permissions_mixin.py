from dataclasses import dataclass
from contextlib import contextmanager

from sqlalchemy_authorize.permissions_mixin import BasePermissionsMixin


class OsoPermissionsMixin(BasePermissionsMixin):
    """Authorize your fields using Oso_.

    E.g. (using the ``User`` model defined in :ref:`conftest.py`
    and the polar policy provided in
    ``sqlalchemy_authorize.oso.rbac.polar``):

    >>> admin = User(id="1", username="root", is_admin=True)
    >>> john_doe = User(username="john_doe", check_create=True)
    Traceback (most recent call last):
    oso.exceptions.ForbiddenError: ...
    >>> with user_set(app, admin):  # A context to set `flask.g.user`
    ...     john_doe = User(username="john_doe", check_create=True)
    ...     john_doe.id = "2"
    >>> john_doe.username, john_doe.id
    ('john_doe', '2')
    >>> with user_set(app, john_doe):
    ...     john_doe.username = "doe_john"
    ...     john_doe.id = "3"
    Traceback (most recent call last):
    oso.exceptions.ForbiddenError: ...
    >>> john_doe.username, john_doe.id
    ('doe_john', '2')

    .. _Oso: <https://www.osohq.com/>
    """

    @staticmethod
    def get_oso():
        """Function to get the current oso instance.

        By default assumes you've attached ``oso`` to the ``app``
        during setup.
        """

        from flask import current_app
        return current_app.oso

    @staticmethod
    def get_anonymous_user():
        """Returns a mock anonymous user.

        You'll probably want to overload this with a method that
        creates an anonymous instance of your `User` model.
        (You need to call ``oso.register_classes``).

        But if all you're checking in your polar policies is your
        ``user.id``, then this may suffice.
        """

        return UserMock(id="anon")

    def get_user(self):
        """Function to get the current user (which will get passed as
        the actor to ``oso.authorize_fields`` ).

        By default assumes a user in ``g.user``.
        """
        from flask import g
        return getattr(g, "user", self.get_anonymous_user())

    def error(self, action: str):
        """Returns an appropriate exception for the action.

        :returns:

            - :exec:`ForbiddenError` for create/update/delete, or a
            - :exec:`NotFoundError` for reads.

        """
        if action == "read":
            return self.get_oso().not_found_error()

        return self.get_oso().forbidden_error

    def authorize_field(self, action, key):
        # To avoid self-referential death spiral if oso needs to read actor
        # attributes.
        user = self.get_user()

        if user is None:
            self.get_oso().authorize_field(user, action, self, key)
        else:
            with user.exposed():
                self.get_oso().authorize_field(user, action, self, key)


@dataclass
class UserMock:
    id: str

    @staticmethod
    @contextmanager
    def exposed():
        yield
