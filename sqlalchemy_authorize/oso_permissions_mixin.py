from sqlalchemy_authorize.permissions_mixin import BasePermissionsMixin


class OsoPermissionsMixin(BasePermissionsMixin):
    """Authorize your fields using Oso_.

    .. _Oso: <https://www.osohq.com/>
    """
    
    def get_oso(self):
        """Function to get the current oso instance.

        By default assumes you've attached ``oso`` to the ``app``
        during setup.
        """

        from flask import current_app
        return current_app.oso

    def get_user(self):
        """Function to get the current user (which will get passed as
        the actor to ``oso.authorize_fields`` ).

        By default assumes a user in ``g.current_user``.
        """
        from flask import g
        return g.current_user

    def authorize_field(self, action, key):
        return self.get_oso().authorize_fields(self.get_user(), action, self, key)
