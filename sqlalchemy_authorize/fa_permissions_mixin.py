from sqlalchemy_authorize import BasePermissionsMixin


class FAPermissionsMixin(BasePermissionsMixin):
    """A field-level permissions mixin inspired by `Flask-Authorize`_.

    Assumes your ``User`` model has two ``db.relationship``, one called
    ``roles`` and the other ``groups``.

    .. _Flask-Authorize: <https://github.com/bprinty/Flask-Authorize>

    """

    # TODO: Finish this up.
    pass
