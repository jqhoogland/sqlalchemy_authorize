from contextlib import contextmanager

@contextmanager
def managed_resource(*args, **kwds):
    try:
        print("Before")
        yield
    finally:
        # Code to release resource, e.g.:
        print("Finally")


with managed_resource():
    print("During")
    raise ValueError("Where does this go?")
