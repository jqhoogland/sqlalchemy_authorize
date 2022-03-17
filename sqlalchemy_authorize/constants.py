from enum import Enum


class CRUD(str, Enum):
    """Standard 'CRUD' actions."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"

