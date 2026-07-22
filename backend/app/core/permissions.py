from enum import Enum

from app.models.enums import UserRole


class Permission(str, Enum):
    DASHBOARD_READ = "dashboard:read"
    NETWORK_READ = "network:read"
    NETWORK_MANAGE = "network:manage"
    USERS_MANAGE = "users:manage"
    SETTINGS_MANAGE = "settings:manage"
    AUDIT_READ = "audit:read"


ROLE_PERMISSIONS: dict[UserRole, frozenset[Permission]] = {
    UserRole.SUPER_ADMIN: frozenset(Permission),
    UserRole.ADMIN: frozenset(
        {
            Permission.DASHBOARD_READ,
            Permission.NETWORK_READ,
            Permission.NETWORK_MANAGE,
        }
    ),
    UserRole.VIEWER: frozenset(
        {Permission.DASHBOARD_READ, Permission.NETWORK_READ}
    ),
}


def permissions_for(role: UserRole) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[role]


def has_permission(role: UserRole, permission: Permission) -> bool:
    return permission in permissions_for(role)
