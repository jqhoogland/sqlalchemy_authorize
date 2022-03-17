"""
.. conftest.py:

Most of the tests are currently doctests. Have patience.
"""

import sys
from contextlib import contextmanager

import pytest
import sqlalchemy as sa
from flask import Flask, appcontext_pushed, g
from oso import Oso
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from sqlalchemy_oso import register_models

from sqlalchemy_authorize import OsoPermissionsMixin

Base = declarative_base()
engine = create_engine('sqlite:///:memory:', echo=False)
sess = Session(engine)


# -- Models -------------------------------------------------------------------


class BaseModel(OsoPermissionsMixin, Base):
    __abstract__ = True
    pass


class User(BaseModel):
    __tablename__ = 'user'
    __repr_attrs__ = ['name']
    __permissions__ = OsoPermissionsMixin.load_permissions(
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
        admin="*"  # i.e., all actions on all fields
    )

    id = sa.Column(sa.String(128), primary_key=True)
    username = sa.Column(sa.String(128), nullable=False)
    fullname = sa.Column(sa.String(128), nullable=False)
    ssn = sa.Column(sa.String(10), nullable=True)
    is_admin = sa.Column(sa.Boolean, default=False)

    def __repr__(self):
        return f"<User {self.id}>"


# -- Fixtures -----------------------------------------------------------------


@pytest.fixture(scope="session")
def session():
    sess.rollback()

    BaseModel.__class__._session = None
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    BaseModel.__class__._session = sess
    return sess


@pytest.fixture(scope="session")
def app(oso):
    app = Flask(__name__, instance_relative_config=True)
    app.oso = oso

    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture(scope="session")
def oso():
    oso = Oso()
    register_models(oso, User)

    from sqlalchemy_authorize.oso.oso_permissions_mixin import UserMock
    oso.register_class(UserMock)

    oso.load_files(["./sqlalchemy_authorize/oso/rbac.polar"])

    return oso


@contextmanager
def user_set(app, user):
    g.user = user
    yield


# -- Doctest Namespace --------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def add_app(doctest_namespace):
    doctest_namespace["app"] = app


@pytest.fixture(scope="session", autouse=True)
def add_User(doctest_namespace):
    doctest_namespace["User"] = User


@pytest.fixture(scope="session", autouse=True)
def add_oso(doctest_namespace):
    doctest_namespace["oso"] = oso


@pytest.fixture(scope="session", autouse=True)
def add_user_set(doctest_namespace):
    doctest_namespace["user_set"] = user_set
