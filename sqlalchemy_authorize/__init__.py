"""Top-level package for SQL Alchemy Authorize."""

__author__ = """Jesse Hoogland"""
__email__ = 'jesse@jessehoogland.com'
__version__ = '0.1.0'

from sqlalchemy_authorize.permissions_mixin import BasePermissionsMixin
from sqlalchemy_authorize.oso.oso_permissions_mixin import OsoPermissionsMixin
