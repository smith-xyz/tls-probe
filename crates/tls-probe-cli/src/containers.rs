//! Container and cgroup attribution from v2 cgroup inode numbers.
//!
//! Resolves cgroup v2 inode IDs to container runtimes (CRI-O, containerd, docker, podman)
//! and extracts container ID + pod UID for Kubernetes-managed containers.

#![allow(dead_code)] // many items are used via public trait/resolver interface

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Container identity: runtime-provided container ID and Kubernetes pod UID (if applicable).
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerIdentity {
    pub container_id: String,
    pub pod_uid: Option<String>,
}

/// Trait for cgroup v2 inode resolution. Fakeable for testing.
pub trait CgroupResolver: Send + Sync {
    /// Resolve a cgroup v2 inode to its path. Returns `None` if unresolvable.
    fn resolve_inode(&self, inode: u64) -> Option<String>;
}

/// Default resolver: walks /sys/fs/cgroup (or a custom root) with lazy caching.
pub struct DefaultResolver {
    cgroup_root: PathBuf,
    cache: std::sync::Mutex<ResolverCache>,
}

struct ResolverCache {
    /// ino -> path; populated on first miss and re-walked on next miss.
    ino_map: HashMap<u64, String>,
    /// Cache of negative lookups (inode not found); TTL 5 seconds.
    negative: HashMap<u64, SystemTime>,
    /// Last time we did a full walk.
    last_walk: Option<SystemTime>,
}

impl DefaultResolver {
    /// Create a new resolver with the given cgroup root (usually `/sys/fs/cgroup`).
    pub fn new(cgroup_root: impl AsRef<Path>) -> Self {
        Self {
            cgroup_root: cgroup_root.as_ref().to_path_buf(),
            cache: std::sync::Mutex::new(ResolverCache {
                ino_map: HashMap::new(),
                negative: HashMap::new(),
                last_walk: None,
            }),
        }
    }

    /// Walk the cgroup tree and populate the inode-to-path cache.
    fn walk_cgroup_tree(&self) -> std::io::Result<HashMap<u64, String>> {
        let mut map = HashMap::new();

        fn recurse(
            dir: &Path,
            map: &mut HashMap<u64, String>,
            cgroup_root: &Path,
        ) -> std::io::Result<()> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                let metadata = entry.metadata()?;

                // Get the inode; on Linux this is the inode of the directory entry.
                // For v2 cgroups, this is the unique cgroup identifier.
                if let Ok(inode) = get_inode_from_stat(&metadata) {
                    if let Ok(rel_path) = path.strip_prefix(cgroup_root) {
                        map.insert(inode, rel_path.to_string_lossy().to_string());
                    }
                }

                // Recurse into subdirectories.
                if metadata.is_dir() && !metadata.is_symlink() {
                    recurse(&path, map, cgroup_root)?;
                }
            }
            Ok(())
        }

        if self.cgroup_root.exists() {
            recurse(&self.cgroup_root, &mut map, &self.cgroup_root)?;
        }

        Ok(map)
    }
}

#[cfg(target_os = "linux")]
fn get_inode_from_stat(metadata: &fs::Metadata) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(metadata.ino())
}

#[cfg(not(target_os = "linux"))]
fn get_inode_from_stat(_metadata: &fs::Metadata) -> std::io::Result<u64> {
    // Non-Linux platforms don't have stable inode semantics for cgroups.
    Ok(0)
}

impl CgroupResolver for DefaultResolver {
    fn resolve_inode(&self, inode: u64) -> Option<String> {
        if inode == 0 {
            return None;
        }

        let mut cache = self.cache.lock().unwrap();

        // Check if we have it in the positive cache.
        if let Some(path) = cache.ino_map.get(&inode) {
            return Some(path.clone());
        }

        // Check if this is a recently-negative-cached miss (TTL 5 seconds).
        if let Some(neg_time) = cache.negative.get(&inode) {
            if neg_time.elapsed().map(|d| d.as_secs() < 5).unwrap_or(false) {
                return None;
            }
            // Expired: allow re-walk.
            cache.negative.remove(&inode);
        }

        // Walk the tree and try again.
        if let Ok(new_map) = self.walk_cgroup_tree() {
            cache.ino_map = new_map;
            cache.last_walk = Some(SystemTime::now());

            if let Some(path) = cache.ino_map.get(&inode) {
                return Some(path.clone());
            }
        }

        // Still not found: negative-cache the miss.
        cache.negative.insert(inode, SystemTime::now());
        None
    }
}

/// Parse a cgroup path to extract container identity if it matches a known runtime.
fn parse_container_path(path: &str) -> Option<ContainerIdentity> {
    // Try each runtime parser in order.
    if let Some(ident) = parse_crio(path) {
        return Some(ident);
    }
    if let Some(ident) = parse_containerd(path) {
        return Some(ident);
    }
    if let Some(ident) = parse_docker(path) {
        return Some(ident);
    }
    if let Some(ident) = parse_podman(path) {
        return Some(ident);
    }
    None
}

/// Parse CRI-O format: `kubepods.slice/kubepods-*.slice/kubepods-*-pod<uid>.slice/crio-<id>.scope`
/// Pod UID has underscores for dashes (normalize them back).
/// The `kubepods` prefix indicates Kubernetes-managed cgroups.
fn parse_crio(path: &str) -> Option<ContainerIdentity> {
    // Look for the crio scope marker.
    if !path.contains("crio-") || !path.ends_with(".scope") {
        return None;
    }

    // Extract container ID from `crio-<64hex>.scope`.
    let scope_part = path
        .split('/')
        .rfind(|p| p.starts_with("crio-") && p.ends_with(".scope"))?;
    let container_id = scope_part
        .strip_prefix("crio-")?
        .strip_suffix(".scope")?
        .to_string();

    // Look for pod UID in parent dirs: `kubepods-*-pod<uid>.slice` (Kubernetes-managed cgroup format).
    let pod_uid = path.split('/').find_map(|segment| {
        if segment.contains("pod") && segment.ends_with(".slice") {
            // Format: `kubepods-*-pod<uid>.slice` or `kubepods.slice`.
            if let Some(pod_part) = segment.strip_prefix("kubepods-") {
                if let Some(uid_part) = pod_part.strip_prefix("pod") {
                    if let Some(uid) = uid_part.strip_suffix(".slice") {
                        // Normalize underscores back to dashes.
                        return Some(uid.replace('_', "-"));
                    }
                }
            }
        }
        None
    });

    Some(ContainerIdentity {
        container_id,
        pod_uid,
    })
}

/// Parse containerd format: `cri-containerd-<id>.scope`
fn parse_containerd(path: &str) -> Option<ContainerIdentity> {
    if !path.contains("cri-containerd-") || !path.ends_with(".scope") {
        return None;
    }

    let scope_part = path
        .split('/')
        .rfind(|p| p.starts_with("cri-containerd-") && p.ends_with(".scope"))?;
    let container_id = scope_part
        .strip_prefix("cri-containerd-")?
        .strip_suffix(".scope")?
        .to_string();

    Some(ContainerIdentity {
        container_id,
        pod_uid: None,
    })
}

/// Parse docker format: `docker-<id>.scope`
fn parse_docker(path: &str) -> Option<ContainerIdentity> {
    if !path.contains("docker-") || !path.ends_with(".scope") {
        return None;
    }

    let scope_part = path
        .split('/')
        .rfind(|p| p.starts_with("docker-") && p.ends_with(".scope"))?;
    let container_id = scope_part
        .strip_prefix("docker-")?
        .strip_suffix(".scope")?
        .to_string();

    Some(ContainerIdentity {
        container_id,
        pod_uid: None,
    })
}

/// Parse podman format: `libpod-<id>.scope`
fn parse_podman(path: &str) -> Option<ContainerIdentity> {
    if !path.contains("libpod-") || !path.ends_with(".scope") {
        return None;
    }

    let scope_part = path
        .split('/')
        .rfind(|p| p.starts_with("libpod-") && p.ends_with(".scope"))?;
    let container_id = scope_part
        .strip_prefix("libpod-")?
        .strip_suffix(".scope")?
        .to_string();

    Some(ContainerIdentity {
        container_id,
        pod_uid: None,
    })
}

/// Resolve a cgroup ID to container identity (if possible).
/// Returns `(container_id, pod_uid)` or `(None, None)` if unresolvable.
pub fn resolve_cgroup_id(
    resolver: &dyn CgroupResolver,
    cgroup_id: u64,
) -> (Option<String>, Option<String>) {
    if cgroup_id == 0 {
        return (None, None);
    }

    if let Some(path) = resolver.resolve_inode(cgroup_id) {
        if let Some(identity) = parse_container_path(&path) {
            return (Some(identity.container_id), identity.pod_uid);
        }
    }

    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake resolver for testing.
    struct FakeResolver {
        mappings: HashMap<u64, String>,
    }

    impl FakeResolver {
        fn new() -> Self {
            Self {
                mappings: HashMap::new(),
            }
        }

        fn with_entry(mut self, inode: u64, path: &str) -> Self {
            self.mappings.insert(inode, path.to_string());
            self
        }
    }

    impl CgroupResolver for FakeResolver {
        fn resolve_inode(&self, inode: u64) -> Option<String> {
            self.mappings.get(&inode).cloned()
        }
    }

    #[test]
    fn test_parse_crio_without_pod() {
        let path = "kubepods.slice/crio-abc123.scope";
        let ident = parse_crio(path).unwrap();
        assert_eq!(ident.container_id, "abc123");
        assert_eq!(ident.pod_uid, None);
    }

    #[test]
    fn test_parse_crio_with_pod_uid() {
        let path = "kubepods.slice/kubepods-pod1234_5678_9abc.slice/crio-def456.scope";
        let ident = parse_crio(path).unwrap();
        assert_eq!(ident.container_id, "def456");
        assert_eq!(ident.pod_uid, Some("1234-5678-9abc".to_string()));
    }

    #[test]
    fn test_parse_containerd() {
        let path = "cgroup.slice/cri-containerd-xyz789.scope";
        let ident = parse_containerd(path).unwrap();
        assert_eq!(ident.container_id, "xyz789");
        assert_eq!(ident.pod_uid, None);
    }

    #[test]
    fn test_parse_docker() {
        let path = "docker/docker-def123.scope";
        let ident = parse_docker(path).unwrap();
        assert_eq!(ident.container_id, "def123");
        assert_eq!(ident.pod_uid, None);
    }

    #[test]
    fn test_parse_podman() {
        let path = "libpod/libpod-abc456.scope";
        let ident = parse_podman(path).unwrap();
        assert_eq!(ident.container_id, "abc456");
        assert_eq!(ident.pod_uid, None);
    }

    #[test]
    fn test_resolve_cgroup_id() {
        let resolver = FakeResolver::new()
            .with_entry(42, "kubepods.slice/kubepods-pod1234.slice/crio-myid.scope");
        let (cid, puid) = resolve_cgroup_id(&resolver, 42);
        assert_eq!(cid, Some("myid".to_string()));
        assert_eq!(puid, Some("1234".to_string()));
    }

    #[test]
    fn test_resolve_cgroup_id_zero() {
        let resolver = FakeResolver::new();
        let (cid, puid) = resolve_cgroup_id(&resolver, 0);
        assert_eq!(cid, None);
        assert_eq!(puid, None);
    }

    #[test]
    fn test_resolve_cgroup_id_unresolvable() {
        let resolver = FakeResolver::new();
        let (cid, puid) = resolve_cgroup_id(&resolver, 999);
        assert_eq!(cid, None);
        assert_eq!(puid, None);
    }

    #[test]
    fn test_non_container_path() {
        let path = "user.slice/user-1000.slice/session-1.scope";
        assert_eq!(parse_crio(path), None);
        assert_eq!(parse_containerd(path), None);
        assert_eq!(parse_docker(path), None);
        assert_eq!(parse_podman(path), None);
    }
}
