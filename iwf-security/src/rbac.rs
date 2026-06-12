//! Role-based access control for the admin API.
//!
//! Roles map 1:1 onto OAuth scopes (`iwf:operator`, `iwf:read`,
//! `iwf:provisioning`); the admin middleware validates the JWT then checks
//! the permission for the route.

use serde::{Deserialize, Serialize};

/// Admin roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Full control: config reload, log level, peer management, drain.
    Operator,
    /// Read-only: status, metrics, rule inspection.
    ReadOnly,
    /// Rule/route provisioning only; no process-level control.
    Provisioning,
}

impl Role {
    /// OAuth scope string carried in admin tokens.
    pub fn scope(&self) -> &'static str {
        match self {
            Role::Operator => "iwf:operator",
            Role::ReadOnly => "iwf:read",
            Role::Provisioning => "iwf:provisioning",
        }
    }
}

/// Permissions checked by admin routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// GET status/health/rules.
    Read,
    /// Update translation rules / routing.
    Provision,
    /// Process-level control (log level, drain, peer admin).
    Operate,
}

/// Does `role` grant `permission`?
pub fn allows(role: Role, permission: Permission) -> bool {
    match (role, permission) {
        (Role::Operator, _) => true,
        (Role::ReadOnly, Permission::Read) => true,
        (Role::ReadOnly, _) => false,
        (Role::Provisioning, Permission::Read | Permission::Provision) => true,
        (Role::Provisioning, Permission::Operate) => false,
    }
}

/// Resolve the strongest role present in a space-separated scope list.
pub fn role_from_scopes(scopes: &str) -> Option<Role> {
    let mut found: Option<Role> = None;
    for s in scopes.split(' ') {
        let role = match s {
            "iwf:operator" => Some(Role::Operator),
            "iwf:provisioning" => Some(Role::Provisioning),
            "iwf:read" => Some(Role::ReadOnly),
            _ => None,
        };
        found = match (found, role) {
            (None, r) => r,
            (Some(Role::Operator), _) | (_, Some(Role::Operator)) => Some(Role::Operator),
            (Some(Role::Provisioning), _) | (_, Some(Role::Provisioning)) => {
                Some(Role::Provisioning)
            }
            (Some(r), None) => Some(r),
            (Some(_), Some(r)) => Some(r),
        };
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_can_do_everything() {
        for p in [Permission::Read, Permission::Provision, Permission::Operate] {
            assert!(allows(Role::Operator, p));
        }
    }

    #[test]
    fn read_only_is_read_only() {
        assert!(allows(Role::ReadOnly, Permission::Read));
        assert!(!allows(Role::ReadOnly, Permission::Provision));
        assert!(!allows(Role::ReadOnly, Permission::Operate));
    }

    #[test]
    fn provisioning_cannot_operate() {
        assert!(allows(Role::Provisioning, Permission::Read));
        assert!(allows(Role::Provisioning, Permission::Provision));
        assert!(!allows(Role::Provisioning, Permission::Operate));
    }

    #[test]
    fn strongest_scope_wins() {
        assert_eq!(role_from_scopes("iwf:read"), Some(Role::ReadOnly));
        assert_eq!(
            role_from_scopes("iwf:read iwf:operator"),
            Some(Role::Operator)
        );
        assert_eq!(
            role_from_scopes("iwf:provisioning iwf:read"),
            Some(Role::Provisioning)
        );
        assert_eq!(role_from_scopes("other:scope"), None);
        assert_eq!(role_from_scopes(""), None);
    }
}
