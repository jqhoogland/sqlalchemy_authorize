from contextlib import contextmanager

import pytest
from flask import appcontext_pushed, g
from oso import Oso
from sqlalchemy_oso import register_models


