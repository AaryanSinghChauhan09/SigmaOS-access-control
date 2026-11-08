//! SigmaOS-access-control — comprehensive access control component.
//!
//! Provides access control functionality for resources, including
//! permissions, roles, policies, and access control lists (ACLs).

use std::collections::HashMap;

/// Access control type
#[derive(Debug, Clone, PartialEq)]
pub enum AccessControlType {
    /// Resource-based access control
    Resource,
    /// Role-based access control
    Role,
    /// Attribute-based access control
    Attribute,
    /// Mandatory access control
    Mandatory,
    /// Discretionary access control
    Discretionary,
}

/// Permission type
#[derive(Debug, Clone, PartialEq)]
pub enum Permission {
    /// Read permission
    Read,
    /// Write permission
    Write,
    /// Execute permission
    Execute,
    /// Delete permission
    Delete,
    /// Admin permission
    Admin,
}

/// Access control entry
#[derive(Debug, Clone)]
pub struct AccessControlEntry {
    /// Entry ID
    pub id: String,
    /// Subject (user/group/role)
    pub subject: String,
    /// Subject type
    pub subject_type: SubjectType,
    /// Permissions
    pub permissions: Vec<Permission>,
    /// Access control type
    pub access_type: AccessControlType,
    /// Inheritance flag
    pub inherit: bool,
    /// Deny flag
    pub deny: bool,
}

/// Subject type
#[derive(Debug, Clone, PartialEq)]
pub enum SubjectType {
    /// User
    User,
    /// Group
    Group,
    /// Role
    Role,
    /// Everyone
    Everyone,
}

/// Access control policy
#[derive(Debug, Clone)]
pub struct AccessControlPolicy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Policy description
    pub description: String,
    /// Access control type
    pub access_type: AccessControlType,
    /// Default permissions
    pub default_permissions: Vec<Permission>,
    /// Entries
    pub entries: Vec<AccessControlEntry>,
    /// Enabled flag
    pub enabled: bool,
}

impl Default for AccessControlPolicy {
    fn default() -> Self {
        Self {
            id: "default".into(),
            name: "Default Policy".into(),
            description: "Default access control policy".into(),
            access_type: AccessControlType::Discretionary,
            default_permissions: vec![Permission::Read],
            entries: vec![],
            enabled: true,
        }
    }
}

/// Access control manager
#[derive(Debug, Clone)]
pub struct AccessControlManager {
    /// Policies
    policies: HashMap<String, AccessControlPolicy>,
    /// Resource entries
    resource_entries: HashMap<String, Vec<AccessControlEntry>>,
    /// Statistics
    total_policies: u32,
    /// Total entries
    total_entries: u32,
}

impl Default for AccessControlManager {
    fn default() -> Self {
        Self {
            policies: HashMap::new(),
            resource_entries: HashMap::new(),
            total_policies: 0,
            total_entries: 0,
        }
    }
}

/// Check if entry matches subject (standalone function)
fn matches_entry_standalone(entry: &AccessControlEntry, subject: &str, subject_type: &SubjectType) -> bool {
    // Check subject type
    if entry.subject_type != *subject_type {
        return false;
    }
    
    // Check subject match
    match subject_type {
        SubjectType::Everyone => true,
        SubjectType::User => entry.subject == subject,
        SubjectType::Group => {
            entry.subject == subject
        }
        SubjectType::Role => {
            entry.subject == subject
        }
    }
}

impl AccessControlManager {
    /// Create new access control manager
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Initialize with default policies
    pub fn initialize(&mut self) {
        // Add default policy
        let default_policy = AccessControlPolicy::default();
        self.add_policy(default_policy);
    }
    
    /// Add access control policy
    pub fn add_policy(&mut self, policy: AccessControlPolicy) -> String {
        let id = policy.id.clone();
        self.policies.insert(id.clone(), policy);
        self.total_policies += 1;
        id
    }
    
    /// Remove policy
    pub fn remove_policy(&mut self, policy_id: &str) -> bool {
        if self.policies.remove(policy_id).is_some() {
            self.total_policies = self.total_policies.saturating_sub(1);
            true
        } else {
            false
        }
    }
    
    /// Get policy
    pub fn get_policy(&self, policy_id: &str) -> Option<&AccessControlPolicy> {
        self.policies.get(policy_id)
    }
    
    /// Get policy mutably
    pub fn get_policy_mut(&mut self, policy_id: &str) -> Option<&mut AccessControlPolicy> {
        self.policies.get_mut(policy_id)
    }
    
    /// Get all policies
    pub fn get_all_policies(&self) -> Vec<&AccessControlPolicy> {
        self.policies.values().collect()
    }
    
    /// Add access control entry to policy
    pub fn add_entry_to_policy(&mut self, policy_id: &str, entry: AccessControlEntry) -> bool {
        if let Some(policy) = self.policies.get_mut(policy_id) {
            policy.entries.push(entry);
            self.total_entries += 1;
            true
        } else {
            false
        }
    }
    
    /// Remove entry from policy
    pub fn remove_entry_from_policy(&mut self, policy_id: &str, entry_id: &str) -> bool {
        if let Some(policy) = self.policies.get_mut(policy_id) {
            if let Some(pos) = policy.entries.iter().position(|e| e.id == entry_id) {
                policy.entries.remove(pos);
                self.total_entries = self.total_entries.saturating_sub(1);
                return true;
            }
        }
        false
    }
    
    /// Add resource access control entry
    pub fn add_resource_entry(&mut self, resource_id: &str, entry: AccessControlEntry) -> bool {
        let entries = self.resource_entries.entry(resource_id.to_string()).or_insert_with(Vec::new);
        entries.push(entry);
        self.total_entries += 1;
        true
    }
    
    /// Get resource access control entries
    pub fn get_resource_entries(&self, resource_id: &str) -> Vec<&AccessControlEntry> {
        self.resource_entries.get(resource_id)
            .map(|entries| entries.iter().collect())
            .unwrap_or_default()
    }
    
    /// Check access permission
    pub fn check_access(&self, resource_id: &str, subject: &str, subject_type: &SubjectType, permission: &Permission) -> bool {
        // Check resource-specific entries first - deny entries take precedence
        if let Some(entries) = self.resource_entries.get(resource_id) {
            // First check for deny entries
            for entry in entries {
                if matches_entry_standalone(entry, subject, subject_type) && entry.deny && entry.permissions.contains(permission) {
                    return false;
                }
            }
            // Then check for allow entries
            for entry in entries {
                if matches_entry_standalone(entry, subject, subject_type) && !entry.deny && entry.permissions.contains(permission) {
                    return true;
                }
            }
            // If resource has entries but none match, deny access
            return false;
        }
        
        // Check policy entries - deny entries take precedence
        for policy in self.policies.values() {
            if !policy.enabled {
                continue;
            }
            
            // First check for deny entries
            for entry in &policy.entries {
                if matches_entry_standalone(entry, subject, subject_type) && entry.deny && entry.permissions.contains(permission) {
                    return false;
                }
            }
            // Then check for allow entries
            for entry in &policy.entries {
                if matches_entry_standalone(entry, subject, subject_type) && !entry.deny && entry.permissions.contains(permission) {
                    return true;
                }
            }
            
            // Check default permissions only if no explicit entries exist
            if policy.entries.is_empty() && policy.default_permissions.contains(permission) {
                return true;
            }
        }
        
        false
    }
    
    /// Check if entry matches subject
    fn matches_entry(&self, entry: &AccessControlEntry, subject: &str, subject_type: &SubjectType) -> bool {
        matches_entry_standalone(entry, subject, subject_type)
    }
    
    /// Grant permission
    pub fn grant_permission(&mut self, resource_id: &str, subject: &str, subject_type: SubjectType, permission: Permission) -> bool {
        let entry = AccessControlEntry {
            id: format!("{}-{}", resource_id, subject),
            subject: subject.to_string(),
            subject_type,
            permissions: vec![permission],
            access_type: AccessControlType::Discretionary,
            inherit: false,
            deny: false,
        };
        self.add_resource_entry(resource_id, entry)
    }
    
    /// Deny permission
    pub fn deny_permission(&mut self, resource_id: &str, subject: &str, subject_type: SubjectType, permission: Permission) -> bool {
        let entry = AccessControlEntry {
            id: format!("{}-{}-deny", resource_id, subject),
            subject: subject.to_string(),
            subject_type,
            permissions: vec![permission],
            access_type: AccessControlType::Discretionary,
            inherit: false,
            deny: true,
        };
        self.add_resource_entry(resource_id, entry)
    }
    
    /// Revoke permission
    pub fn revoke_permission(&mut self, resource_id: &str, subject: &str, subject_type: &SubjectType, permission: &Permission) -> bool {
        // Remove matching entries
        if let Some(entries) = self.resource_entries.get_mut(resource_id) {
            let mut to_remove = vec![];
            for (i, entry) in entries.iter().enumerate() {
                if matches_entry_standalone(entry, subject, subject_type) && entry.permissions.contains(permission) {
                    to_remove.push(i);
                }
            }
            // Remove in reverse order to maintain indices
            for i in to_remove.iter().rev() {
                entries.remove(*i);
            }
            return true;
        }
        false
    }
    
    /// Get access control statistics
    pub fn get_statistics(&self) -> AccessControlStatistics {
        let mut user_entries = 0;
        let mut group_entries = 0;
        let mut role_entries = 0;
        
        // Count policy entries
        for policy in self.policies.values() {
            for entry in &policy.entries {
                match entry.subject_type {
                    SubjectType::User => user_entries += 1,
                    SubjectType::Group => group_entries += 1,
                    SubjectType::Role => role_entries += 1,
                    SubjectType::Everyone => {}
                }
            }
        }
        
        // Count resource entries
        for entries in self.resource_entries.values() {
            for entry in entries {
                match entry.subject_type {
                    SubjectType::User => user_entries += 1,
                    SubjectType::Group => group_entries += 1,
                    SubjectType::Role => role_entries += 1,
                    SubjectType::Everyone => {}
                }
            }
        }
        
        AccessControlStatistics {
            total_policies: self.total_policies,
            total_entries: self.total_entries,
            resource_entries: self.resource_entries.len() as u32,
            enabled_policies: self.policies.values()
                .filter(|p| p.enabled)
                .count() as u32,
            user_entries,
            group_entries,
            role_entries,
        }
    }
    
    /// Export access control data
    pub fn export_data(&self) -> AccessControlExport {
        AccessControlExport {
            policies: self.policies.values().cloned().collect(),
            resource_entries: self.resource_entries.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }
    
    /// Import access control data
    pub fn import_data(&mut self, export: AccessControlExport) {
        for policy in export.policies {
            self.policies.insert(policy.id.clone(), policy);
        }
        for (resource_id, entries) in export.resource_entries {
            self.resource_entries.insert(resource_id, entries);
        }
        self.total_policies = self.policies.len() as u32;
        self.total_entries = self.resource_entries.values()
            .map(|v| v.len())
            .sum::<usize>() as u32;
    }
}

/// Access control statistics
#[derive(Debug, Clone)]
pub struct AccessControlStatistics {
    /// Total policies
    pub total_policies: u32,
    /// Total entries
    pub total_entries: u32,
    /// Resource entries
    pub resource_entries: u32,
    /// Enabled policies
    pub enabled_policies: u32,
    /// User entries
    pub user_entries: u32,
    /// Group entries
    pub group_entries: u32,
    /// Role entries
    pub role_entries: u32,
}

/// Access control export data
#[derive(Debug, Clone)]
pub struct AccessControlExport {
    /// Policies
    pub policies: Vec<AccessControlPolicy>,
    /// Resource entries
    pub resource_entries: HashMap<String, Vec<AccessControlEntry>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_access_control_policy_creation() {
        let policy = AccessControlPolicy::default();
        assert_eq!(policy.id, "default");
        assert!(policy.enabled);
        assert_eq!(policy.access_type, AccessControlType::Discretionary);
    }
    
    #[test]
    fn test_add_policy() {
        let mut manager = AccessControlManager::new();
        manager.initialize();
        
        let policy = AccessControlPolicy {
            id: "test".into(),
            name: "Test Policy".into(),
            description: "Test".into(),
            access_type: AccessControlType::Role,
            default_permissions: vec![Permission::Read],
            entries: vec![],
            enabled: true,
        };
        
        manager.add_policy(policy);
        
        assert_eq!(manager.get_all_policies().len(), 2);
        assert!(manager.get_policy("test").is_some());
    }
    
    #[test]
    fn test_add_entry_to_policy() {
        let mut manager = AccessControlManager::new();
        manager.initialize();
        
        let entry = AccessControlEntry {
            id: "entry1".into(),
            subject: "user1".into(),
            subject_type: SubjectType::User,
            permissions: vec![Permission::Read, Permission::Write],
            access_type: AccessControlType::Discretionary,
            inherit: false,
            deny: false,
        };
        
        assert!(manager.add_entry_to_policy("default", entry));
        assert_eq!(manager.get_policy("default").unwrap().entries.len(), 1);
    }
    
    #[test]
    fn test_resource_entries() {
        let mut manager = AccessControlManager::new();
        manager.initialize();
        
        let entry = AccessControlEntry {
            id: "entry1".into(),
            subject: "user1".into(),
            subject_type: SubjectType::User,
            permissions: vec![Permission::Read],
            access_type: AccessControlType::Discretionary,
            inherit: false,
            deny: false,
        };
        
        assert!(manager.add_resource_entry("resource1", entry));
        assert_eq!(manager.get_resource_entries("resource1").len(), 1);
    }
    
    #[test]
    fn test_check_access() {
        let mut manager = AccessControlManager::new();
        manager.initialize();
        
        // Grant read permission
        manager.grant_permission("resource1", "user1", SubjectType::User, Permission::Read);
        
        // Check access
        assert!(manager.check_access("resource1", "user1", &SubjectType::User, &Permission::Read));
        assert!(!manager.check_access("resource1", "user1", &SubjectType::User, &Permission::Write));
        assert!(!manager.check_access("resource1", "user2", &SubjectType::User, &Permission::Read));
    }
    
    #[test]
    fn test_deny_permission() {
        let mut manager = AccessControlManager::new();
        manager.initialize();
        
        // Grant then deny
        manager.grant_permission("resource1", "user1", SubjectType::User, Permission::Read);
        manager.deny_permission("resource1", "user1", SubjectType::User, Permission::Read);
        
        // Should be denied
        assert!(!manager.check_access("resource1", "user1", &SubjectType::User, &Permission::Read));
    }
    
    #[test]
    fn test_revoke_permission() {
        let mut manager = AccessControlManager::new();
        manager.initialize();
        
        // Grant permission
        manager.grant_permission("resource1", "user1", SubjectType::User, Permission::Read);
        assert!(manager.check_access("resource1", "user1", &SubjectType::User, &Permission::Read));
        
        // Revoke permission
        manager.revoke_permission("resource1", "user1", &SubjectType::User, &Permission::Read);
        assert!(!manager.check_access("resource1", "user1", &SubjectType::User, &Permission::Read));
    }
    
    #[test]
    fn test_subject_types() {
        let subject_types = vec![
            SubjectType::User,
            SubjectType::Group,
            SubjectType::Role,
            SubjectType::Everyone,
        ];
        assert_eq!(subject_types.len(), 4);
    }
    
    #[test]
    fn test_access_control_types() {
        let types = vec![
            AccessControlType::Resource,
            AccessControlType::Role,
            AccessControlType::Attribute,
            AccessControlType::Mandatory,
            AccessControlType::Discretionary,
        ];
        assert_eq!(types.len(), 5);
    }
    
    #[test]
    fn test_permissions() {
        let permissions = vec![
            Permission::Read,
            Permission::Write,
            Permission::Execute,
            Permission::Delete,
            Permission::Admin,
        ];
        assert_eq!(permissions.len(), 5);
    }
    
    #[test]
    fn test_statistics() {
        let mut manager = AccessControlManager::new();
        manager.initialize();
        
        manager.grant_permission("resource1", "user1", SubjectType::User, Permission::Read);
        manager.grant_permission("resource1", "user2", SubjectType::User, Permission::Write);
        
        let stats = manager.get_statistics();
        assert_eq!(stats.total_policies, 1);
        assert!(stats.total_entries > 0);
        assert!(stats.user_entries > 0);
    }
    
    #[test]
    fn test_export_import() {
        let mut manager = AccessControlManager::new();
        manager.initialize();
        manager.grant_permission("resource1", "user1", SubjectType::User, Permission::Read);
        
        let export = manager.export_data();
        
        let mut manager2 = AccessControlManager::new();
        manager2.import_data(export);
        
        assert!(manager2.check_access("resource1", "user1", &SubjectType::User, &Permission::Read));
    }
}
