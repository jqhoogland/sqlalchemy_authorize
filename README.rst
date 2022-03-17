=====================
SQL Alchemy Authorize
=====================

.. image:: https://img.shields.io/pypi/v/sqlalchemy_authorize.svg
        :target: https://pypi.python.org/pypi/sqlalchemy_authorize

.. image:: https://readthedocs.org/projects/sqlalchemy-authorize/badge/?version=latest
        :target: https://sqlalchemy-authorize.readthedocs.io/en/latest/?version=latest
        :alt: Documentation Status


.. image:: https://pyup.io/repos/github/jqhoogland/sqlalchemy_authorize/shield.svg
     :target: https://pyup.io/repos/github/jqhoogland/sqlalchemy_authorize/
     :alt: Updates


An unopinionated extension to enforce field-level access control.

For Documentation: https://sqlalchemy-authorize.readthedocs.io.

How to use
----------

Just insert the appropriate ``PermissionsMixin`` in your model definition. For now,
that means the ``OsoPermissionsMixin`` (put it before ``db.Model`` / ``Base``).

Let's look at an easy role-based example.

In your ``models.py``::

    class User(OsoPermissionsMixin, db.Model):
        __tablename__ = 'user'

        # ``load_permissions`` is a convenience method for creating a
        # permissions dictionary of the shape:
        # {"role_1": {"action_1": ["field_1", "field_2", ...], ...}, ...}
        __permissions__ = OsoPermissionsMixin.load_permissions(
            read=["id", "username"],
            self=[
                (["create", "update"], ["username", "fullname"]),
                "read",
                "delete"
            ],
            admin=[
                (["create", "update", "read", "delete"], ("id", "username", "fullname", "is_admin")
            ]
        )

        id = sa.Column(sa.String(128), primary_key=True)
        username = sa.Column(sa.String(128), nullable=False)
        fullname = sa.Column(sa.String(128), nullable=False)
        ssn = sa.Column(sa.String(10), nullable=True)
        is_admin = sa.Column(sa.Boolean, default=False)

Then, in your `polar policy`_, write something like::

    has_role(user: User, "self": other: User) if user.id == other.id;
    has_role(user: User, "admin": _resource) if user.is_admin;

    # OsoPermissionsMixin provides `.role` and `.authorized_fields`
    allow_field(user: User, action, resource, field) if
        role in resource.roles and
        has_role(user, role, resource) and
        (f in resource.authorized_fields(role, action) and
        (f = "*" or f = field)); # to match a wildcard

    # ...

For the full example, check out ``rbac.polar``.

Now, we can start having fun::

    admin = User(id="1", username="root", is_admin=True)

    # This won't work because the current user is anonymous
    # and has no create permissions on `User.username`
    john_doe = User(username="john_doe", check_create=True)  # oso.exceptions.ForbiddenError

    with user_set(app, admin): # A helper context that sets `flask.g.user`
        john_doe = User(username="john_doe", check_create=True)
        john_doe.id = "2"

    john_doe.username, john_doe.id  # ('john_doe', '2')

    with user_set(app, john_doe):
        john_doe.username = "doe_john"

        # This won't work because John only has update permissions on `username` and `fullname`
        john_doe.id = "3"   # oso.exceptions.ForbiddenError

    john_doe.username, john_doe.id # ('doe_john', '2')

For more details and options, check out ``BasePermissionsMixin`` and ``OsoPermissionsMixin``.
Rationale
---------

``sqlalchemy_authorize`` is a sqlalchemy extension designed to complement `sqlalchemy-oso`_.
Where `sqlalchemy-oso`_ provides authorization at the *row level* in the *data-access layer*
(it modifies your queries so you pull only authorized entries from your database),
``sqlalchemy_authorize`` operates at the *field level* in the `ORM layer` (it checks
whether users have permission before invoking ``__setattr__``, ``__getattribute__``,
and ``__delattr__`` on your models).

The use I originally had in mind was to separate authorization from graphql in
`Graphene-SQLAlchemy`_: to make it easier to create graphql-queryable models without
substantial authorization boilerplate in the resolvers (`which is not recommended`_).

Really though, the use is broader than both `Graphene-SQLAlchemy`_ and `sqlalchemy-oso`_.
Yes, there a bunch of other libraries for enforcing authorization with SQLAlchemy
(and you should take a look at them before deciding to use this):

* `Flask-Authorize <https://github.com/bprinty/Flask-Authorize>`_
* `Flask Principal <https://pythonhosted.org/Flask-Principal/>`_
* `Flask ACL <https://mikeboers.github.io/Flask-ACL/>`_
* `Flask RBAC <https://flask-rbac.readthedocs.io/en/latest/>`_
* `Flask Allows <https://github.com/justanr/flask-allows>`_
* `Flask Bouncer <https://github.com/bouncer-app/flask-bouncer>`_

Still, I decided to go ahead and throw together this library because:

*    These options are Flask-specific and check permissions via decorators.
     I wanted an option that isn't opt-in but opt-out, i.e., authorization by default.
*    Many of these options assume you'll be authorizing at the *row level*, and (especially for the graphql use case) I needed field-level permissions.
*    Many of the solutions are pretty opinionated about how you should be authorizing (and assume role-based access control).
     I wanted a less opinionated "real-world" solution that lets me pick and choose from `role-, relation- and attribute-based access control`_.

If any of that resonates with you, glad you're here.

This is still a very early-stage library, and I discourage you from using it in production
until I've tested in more thoroughly. Let me modify that: you're more than welcome to use it,
since, if there is one thing you should be testing anyway, it's authorization.

Go ahead, just be very careful.

Misc
----

* Free software: MIT license
* Documentation: https://sqlalchemy-authorize.readthedocs.io.


Timeline
--------

- [ ] More testing.
- [ ] Flesh out the oso example.
- [ ] Implement a non-oso role-based extension.
- [ ] Check row-level create/delete permissions. (This is currently only on the field level).

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
.. _`sqlalchemy-oso`: https://github.com/osohq/oso/tree/main/languages/python/sqlalchemy-oso
.. _`Graphene-SQLAlchemy`: https://docs.graphene-python.org/projects/sqlalchemy/en/latest/
.. _`which is not recommended`: https://graphql.org/learn/authorization/
.. _`role-, relation- and attribute-based access control`: https://www.osohq.com/academy
.. _`polar policy`: https://docs.osohq.com/guides/policies.html
