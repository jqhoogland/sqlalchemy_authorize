class classproperty(object):
    """@property meets @classmethod

    Source: http://stackoverflow.com/a/13624858
    """

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, owner):
        return self.f(owner)


def is_dunder(name: str) -> bool:
    """Check if ``name`` is wrapped in double underscores.

    >>> is_dunder("__some_dunder__")
    True
    >>> is_dunder("_some_not_dunder")
    False

    :param name:
    :return:
    """
    return len(name) > 5 and (name[:2] == name[-2:] == "__")
