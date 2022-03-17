# -- Defining the roles. ------------------------------------------------------
# For this example, we define "public", "self", "owner", and "admin".
# You'll probably want to add more.

has_role(_user, "public", _resource);

has_role(user: User, "self", other: User) if
    user.id == other.id;

has_role(user: User, "owner", resource) if
    user.id == resource.owner_id;

has_role(user: User, "admin", _resource) if
    user.is_admin != nil and user.is_admin;


# -- Field-level access -------------------------------------------------------


# PermissionsMixin provides `roles` and `authorized_fields`.

allow_field(user: User, action, resource, field) if
    role in resource.roles and
    has_role(user, role, resource) and
    (f in resource.authorized_fields_for(role, action) and
    (f = "*" or f = field));


# -- Row-level access ---------------------------------------------------------


# Field-level access implies row-level access.

allow(user: User, action: String, resource) if
    action != "delete" and
    role in resource.roles and
    has_role(user, role, resource) and
    not falsy(resource.authorized_fields_for(role, action));

# Accept for "delete". Here, we need delete permissions on all fields to get
# row-level delete access.

allow(user: User, "delete", resource) if
    role in resource.roles and
    has_role(user, role, resource)and
    "*" in resource.authorized_fields_for(role, "delete");



# == Helpers ==================================================================


falsy(x) if x in [nil, false, []];

