from sqlalchemy_authorize.permissions_mixin import BasePermissionsMixin


class OsoPermissionsMixin(BasePermissionsMixin):
    """Authorize your fields using Oso_.

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
    def get_user():
        """Function to get the current user (which will get passed as
        the actor to ``oso.authorize_fields`` ).

        By default assumes a user in ``g.current_user``.
        """
        from flask import g
        return g.current_user

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
        with self.get_user().exposed():
            self.get_oso().authorize_fields(self.get_user(), action, self, key)
