use caps::{CapSet, Capability};
use tracing::{info, warn};

use crate::error::ProbeError;

const REQUIRED_CAPS_NEW_KERNEL: &[Capability] = &[
    Capability::CAP_BPF,
    Capability::CAP_NET_ADMIN,
    Capability::CAP_PERFMON,
    Capability::CAP_SYS_RESOURCE,
];

const REQUIRED_CAPS_OLD_KERNEL: &[Capability] = &[
    Capability::CAP_SYS_ADMIN,
    Capability::CAP_NET_ADMIN,
    Capability::CAP_SYS_RESOURCE,
];

fn kernel_version() -> (u32, u32, u32) {
    let mut uname: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uname) } != 0 {
        return (0, 0, 0);
    }

    let release = unsafe { std::ffi::CStr::from_ptr(uname.release.as_ptr()) };
    let release_str = release.to_string_lossy();

    let parts: Vec<u32> = release_str
        .split(|c: char| !c.is_ascii_digit())
        .take(3)
        .filter_map(|s| s.parse().ok())
        .collect();

    match parts.as_slice() {
        [major, minor, patch, ..] => (*major, *minor, *patch),
        [major, minor] => (*major, *minor, 0),
        [major] => (*major, 0, 0),
        _ => (0, 0, 0),
    }
}

fn has_cap_bpf_support() -> bool {
    let (major, minor, _) = kernel_version();
    major > 5 || (major == 5 && minor >= 8)
}

pub fn check_capabilities() -> Result<(), ProbeError> {
    let required = if has_cap_bpf_support() {
        info!("Kernel supports CAP_BPF (5.8+)");
        REQUIRED_CAPS_NEW_KERNEL
    } else {
        warn!("Kernel < 5.8, requires CAP_SYS_ADMIN instead of CAP_BPF");
        REQUIRED_CAPS_OLD_KERNEL
    };

    let mut missing = Vec::new();

    for cap in required {
        match caps::has_cap(None, CapSet::Effective, *cap) {
            Ok(true) => {}
            Ok(false) => missing.push(*cap),
            Err(e) => {
                warn!("Failed to check capability {:?}: {}", cap, e);
                missing.push(*cap);
            }
        }
    }

    if !missing.is_empty() {
        let cap_names: Vec<String> = missing.iter().map(|c| format!("{:?}", c)).collect();
        let suggestion = if has_cap_bpf_support() {
            format!(
                "Run with sudo, or grant capabilities:\n  sudo setcap '{}+ep' <binary>",
                cap_names
                    .iter()
                    .map(|c| c.to_lowercase())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            "Run with sudo (kernel < 5.8 requires CAP_SYS_ADMIN)".to_string()
        };

        return Err(ProbeError::LoadError(format!(
            "Missing required capabilities: {}.\n{}",
            cap_names.join(", "),
            suggestion
        )));
    }

    info!("All required capabilities present");
    Ok(())
}

const MIN_MEMLOCK_BYTES: u64 = 64 * 1024 * 1024;

pub fn ensure_memlock_rlimit() -> Result<(), ProbeError> {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };

    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) } != 0 {
        return Err(ProbeError::LoadError(
            "Failed to get RLIMIT_MEMLOCK".to_string(),
        ));
    }

    info!(
        "Current RLIMIT_MEMLOCK: soft={}, hard={}",
        format_limit(rlim.rlim_cur),
        format_limit(rlim.rlim_max)
    );

    if rlim.rlim_cur >= MIN_MEMLOCK_BYTES || rlim.rlim_cur == libc::RLIM_INFINITY {
        return Ok(());
    }

    let new_limit = if rlim.rlim_max == libc::RLIM_INFINITY {
        libc::RLIM_INFINITY
    } else {
        rlim.rlim_max.min(MIN_MEMLOCK_BYTES)
    };

    rlim.rlim_cur = new_limit;

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        let err = std::io::Error::last_os_error();
        warn!(
            "Failed to raise RLIMIT_MEMLOCK to {}: {}",
            format_limit(new_limit),
            err
        );
        warn!("eBPF map creation may fail. Try: ulimit -l unlimited");
        return Ok(());
    }

    info!("Raised RLIMIT_MEMLOCK to {}", format_limit(new_limit));
    Ok(())
}

fn format_limit(limit: u64) -> String {
    if limit == libc::RLIM_INFINITY {
        "unlimited".to_string()
    } else {
        format!("{}MB", limit / (1024 * 1024))
    }
}
