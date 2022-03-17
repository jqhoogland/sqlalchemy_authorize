# -- Defining the roles. ------------------------------------------------------
# For this example, we define "self", "owner", and "admin".
# You'll want to add more.

has_role(user: User, "self", other: User) if
    user.id == other.id;

has_role(user: User, "owner": resource) if
    user.id == resource.owner_id;

has_role(user: User, "admin", _resource: Resource) if
    user.is_admin;


# -- Field-level access -------------------------------------------------------


# PermissionsMixin provides `roles` and `authorized_fields`.

allow_field(user: User, action, resource, field) if
    role in resource.roles and
    has_role(user, role, resource) and
    (field_ in resource.authorized_fields(role, action) and
    (field_ = "*" or field_ = field));


# -- Row-level access ---------------------------------------------------------


# Field-level access implies row-level access.

allow(user: User, action: String, resource) if
    action != "delete" and
    role in resource.roles and
    has_role(user, role, resource) and
    len(resource.authorized_fields(role, action)) > 0;

# Accept for "delete". Here, we need delete permissions on all fields to get
# row-level delete access.

allow(user: User, "delete", resource) if
    role in resource.roles and
    has_role(user, role, resource)and
    "*" in resource.authorized_fields(role, "delete");




