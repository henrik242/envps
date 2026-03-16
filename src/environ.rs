use libc::{c_int, c_void, sysctl};
use std::ptr;

/// Read environment variables from a process by PID.
///
/// Returns a vector of `KEY=VALUE` strings. Prints to stderr and returns
/// an empty vector on failure, matching the original C++ behavior.
#[cfg(target_os = "linux")]
pub fn from_pid(pid: i32) -> Vec<String> {
    let path = format!("/proc/{pid}/environ");
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("Unaccessible or missing PID: {pid}");
            return Vec::new();
        }
    };

    data.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let s = String::from_utf8_lossy(s).into_owned();
            s.contains('=').then_some(s)
        })
        .collect()
}

#[cfg(target_os = "macos")]
pub fn from_pid(pid: i32) -> Vec<String> {
    const KERN_ARGMAX: c_int = 8;
    const KERN_PROCARGS2: c_int = 49;

    // Get ARGMAX
    let mut argmax: c_int = 0;
    let mut size = size_of::<c_int>();
    let mut mib: [c_int; 2] = [libc::CTL_KERN, KERN_ARGMAX];

    let ret = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            2,
            &raw mut argmax as *mut c_void,
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || argmax <= 0 {
        eprintln!("Unaccessible or missing PID: {pid}");
        return Vec::new();
    }

    // Get PROCARGS2
    let mut buf = vec![0u8; argmax as usize];
    let mut mib: [c_int; 3] = [libc::CTL_KERN, KERN_PROCARGS2, pid];
    size = argmax as usize;

    let ret = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast::<c_void>(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        eprintln!("Unaccessible or missing PID: {pid}");
        return Vec::new();
    }

    buf.truncate(size);
    parse_procargs2(&buf)
}

/// Parse the macOS KERN_PROCARGS2 buffer format:
/// `[nargs: i32][exec_path\0][padding\0*][argv strings\0...][env strings\0...]`
#[cfg(target_os = "macos")]
fn parse_procargs2(buf: &[u8]) -> Vec<String> {
    if buf.len() < 4 {
        return Vec::new();
    }

    let nargs = i32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
    let mut pos = 4;

    // Skip exec path
    while pos < buf.len() && buf[pos] != 0 {
        pos += 1;
    }
    if pos >= buf.len() {
        return Vec::new();
    }

    // Skip null padding
    while pos < buf.len() && buf[pos] == 0 {
        pos += 1;
    }
    if pos >= buf.len() {
        return Vec::new();
    }

    // Parse null-terminated strings: first `nargs` are argv, rest are env vars.
    // Matches C++ behavior: stops on empty string once past all args.
    let mut env_vars = Vec::new();
    let mut count = 0;

    while pos < buf.len() {
        let start = pos;
        while pos < buf.len() && buf[pos] != 0 {
            pos += 1;
        }

        let s = &buf[start..pos];

        if s.is_empty() && count >= nargs {
            break;
        }

        if count >= nargs && !s.is_empty() {
            let s = String::from_utf8_lossy(s).into_owned();
            if s.contains('=') {
                env_vars.push(s);
            }
        }

        count += 1;
        if pos < buf.len() {
            pos += 1; // skip null terminator
        }
    }

    env_vars
}

#[cfg(target_os = "freebsd")]
pub fn from_pid(pid: i32) -> Vec<String> {
    const KERN_PROC_ENV: c_int = 35;

    sysctl_environ(&mut [libc::CTL_KERN, libc::KERN_PROC, KERN_PROC_ENV, pid], pid)
}

#[cfg(target_os = "netbsd")]
pub fn from_pid(pid: i32) -> Vec<String> {
    const KERN_PROC_ARGS: c_int = 48;
    const KERN_PROC_ENV: c_int = 3;

    sysctl_environ(&mut [libc::CTL_KERN, KERN_PROC_ARGS, pid, KERN_PROC_ENV], pid)
}

/// Two-pass sysctl with buffer margin to handle TOCTOU races.
/// Used by FreeBSD and NetBSD implementations.
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
fn sysctl_environ(mib: &mut [c_int], pid: i32) -> Vec<String> {
    // First call: get required buffer size
    let mut size: usize = 0;

    let ret = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        eprintln!("Unaccessible or missing PID: {pid}");
        return Vec::new();
    }

    // Add 25% margin to handle environment growth between calls
    size += size / 4;
    let mut buf = vec![0u8; size];

    let ret = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            buf.as_mut_ptr().cast::<c_void>(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        eprintln!("Unaccessible or missing PID: {pid}");
        return Vec::new();
    }

    buf.truncate(size);
    parse_null_separated(&buf)
}

/// Parse a null-separated buffer of environment variables.
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
fn parse_null_separated(buf: &[u8]) -> Vec<String> {
    buf.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let s = String::from_utf8_lossy(s).into_owned();
            s.contains('=').then_some(s)
        })
        .collect()
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
)))]
compile_error!("unsupported platform: envps supports linux, macos, freebsd, and netbsd");
