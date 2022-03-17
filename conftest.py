import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import Query, Session

from sqlalchemy_authorize import BasePermissionsMixin

Base = declarative_base()
engine = create_engine('sqlite:///:memory:', echo=False)
sess = Session(engine)


class BaseModel(BasePermissionsMixin, Base):
    __abstract__ = True
    pass


class User(BaseModel):
    __tablename__ = 'user'
    __repr_attrs__ = ['name']

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

    id = sa.Column(sa.String(128), primary_key=True)
    username = sa.Column(sa.String(128), nullable=False)
    fullname = sa.Column(sa.String(128), nullable=False)
    ssn = sa.Column(sa.String(10), nullable=True)

    def __repr__(self):
        return f"<User {self.id}>"


class Post(BaseModel):
    __tablename__ = 'post'
    id = sa.Column(sa.Integer, primary_key=True)
    body = sa.Column(sa.String)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'))
    archived = sa.Column(sa.Boolean, default=False)

    # user = backref from User.post
    comments = sa.orm.relationship('Comment', backref='post')

    @hybrid_property
    def public(self):
        return not self.archived

    @public.setter
    def public(self, public):
        self.archived = not public


class Comment(BaseModel):
    __tablename__ = 'comment'
    __repr_attrs__ = ['body']
    id = sa.Column(sa.Integer, primary_key=True)
    body = sa.Column(sa.String)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'))
    post_id = sa.Column(sa.Integer, sa.ForeignKey('post.id'))

    user = sa.orm.relationship('User', backref='comments')
    # post = backref from Post.comments


@pytest.fixture(scope="session")
def session():
    sess.rollback()

    BaseModel.__class__._session = None
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    BaseModel.__class__._session = sess
    return sess


@pytest.fixture(scope="session", autouse=True)
def add_User(doctest_namespace):
    doctest_namespace["User"] = User
