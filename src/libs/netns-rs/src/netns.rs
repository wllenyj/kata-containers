// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{setns, unshare, CloneFlags};
use nix::unistd::gettid;

use crate::{Error, Result};

pub trait Env: Default {
    fn netns_run_dir(&self) -> PathBuf;

    fn init(&self) -> Result<()> {
        // Create the directory for mounting network namespaces
        // This needs to be a shared mountpoint in case it is mounted in to
        // other namespaces (containers)
        let run_dir = self.netns_run_dir();
        std::fs::create_dir_all(&run_dir).map_err(Error::CreateNsDirError)?;

        // Remount the namespace directory shared. This will fail if it is not
        // already a mountpoint, so bind-mount it on to itself to "upgrade" it
        // to a mountpoint.
        let mut made_netns_run_dir_mount: bool = false;
        while let Err(e) = mount(
            Some(""),
            &run_dir,
            Some("none"),
            MsFlags::MS_SHARED | MsFlags::MS_REC,
            Some(""),
        ) {
            // Fail unless we need to make the mount point
            if e != nix::errno::Errno::EINVAL || made_netns_run_dir_mount {
                return Err(Error::MountError(
                    format!("--make-rshared {}", run_dir.display()),
                    e,
                ));
            }
            // Recursively remount /var/run/netns on itself. The recursive flag is
            // so that any existing netns bindmounts are carried over.
            mount(
                Some(&run_dir),
                &run_dir,
                Some("none"),
                MsFlags::MS_BIND | MsFlags::MS_REC,
                Some(""),
            )
            .map_err(|e| {
                Error::MountError(
                    format!("-rbind {} to {}", run_dir.display(), run_dir.display()),
                    e,
                )
            })?;
            made_netns_run_dir_mount = true;
        }

        Ok(())
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct DefaultEnv;

impl Env for DefaultEnv {
    fn netns_run_dir(&self) -> PathBuf {
        PathBuf::from("/var/run/netns")
    }
}

#[derive(Debug)]
pub struct NetNs<E: Env = DefaultEnv> {
    file: File,
    path: PathBuf,
    env: Option<E>,
}

impl std::fmt::Display for NetNs {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(meta) = std::fs::metadata(&self.path) {
            write!(
                f,
                "NetNS {{ fd: {}, dev: {}, ino: {}, path: {} }}",
                self.file.as_raw_fd(),
                meta.dev(),
                meta.ino(),
                self.path.display()
            )
        } else {
            write!(
                f,
                "NetNS {{ fd: {}, path: {} }}",
                self.file.as_raw_fd(),
                self.path.display()
            )
        }
    }
}

impl<E: Env> PartialEq for NetNs<E> {
    fn eq(&self, other: &Self) -> bool {
        if self.file.as_raw_fd() == other.file.as_raw_fd() {
            return true;
        }
        let cmp_meta = |f1: &File, f2: &File| -> Option<bool> {
            let m1 = match f1.metadata() {
                Ok(m) => m,
                Err(_) => return None,
            };
            let m2 = match f2.metadata() {
                Ok(m) => m,
                Err(_) => return None,
            };
            println!("{}:{} == {}:{}", m1.dev(), m1.ino(), m2.dev(), m2.ino());
            Some(m1.dev() == m2.dev() && m1.ino() == m2.ino())
        };
        cmp_meta(&self.file, &other.file).unwrap_or_else(|| self.path == other.path)
    }
}

impl<E: Env> NetNs<E> {
    pub fn new_with_env<S: AsRef<str>>(ns_name: S, env: E) -> Result<Self> {
        env.init()?;

        // create an empty file at the mount point
        let ns_path = env.netns_run_dir().join(ns_name.as_ref());
        let _ = File::create(&ns_path).map_err(Error::CreateNsError)?;
        Self::persistent(&ns_path, true).map_err(|e| {
            // Ensure the mount point is cleaned up on errors; if the namespace
            // was successfully mounted this will have no effect because the file
            // is in-use
            std::fs::remove_file(&ns_path).ok();
            e
        })?;
        Ok(Self::get_with_env(ns_path, env)?)
    }

    fn persistent<P: AsRef<Path>>(ns_path: &P, new_thread: bool) -> Result<()> {
        if new_thread {
            let ns_path_clone = ns_path.as_ref().to_path_buf();
            let new_thread: JoinHandle<Result<()>> =
                thread::spawn(move || Ok(Self::persistent(&ns_path_clone, false)?));
            match new_thread.join() {
                Ok(t) => match t {
                    Err(e) => return Err(e),
                    Ok(_) => {}
                },
                Err(e) => {
                    return Err(Error::JoinThreadError(format!("{:?}", e)));
                }
            };
        } else {
            // Create a new netns on the current thread.
            unshare(CloneFlags::CLONE_NEWNET).map_err(Error::UnshareError)?;
            // bind mount the netns from the current thread (from /proc) onto the
            // mount point. This causes the namespace to persist, even when there
            // are no threads in the ns.
            let src = Self::get_current_thread_netns_path();
            mount(
                Some(src.as_path()),
                ns_path.as_ref(),
                Some("none"),
                MsFlags::MS_BIND,
                Some(""),
            )
            .map_err(|e| {
                Error::MountError(
                    format!("-rbind {} to {}", src.display(), ns_path.as_ref().display()),
                    e,
                )
            })?;
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn set(&self) -> Result<()> {
        setns(self.file.as_raw_fd(), CloneFlags::CLONE_NEWNET).map_err(Error::SetnsError)
    }

    pub fn get_with_env<P: AsRef<Path>>(ns_path: P, env: E) -> Result<NetNs<E>> {
        let ns_path = ns_path.as_ref().to_path_buf();
        let file = File::open(&ns_path).map_err(|e| Error::OpenNsError(ns_path.clone(), e))?;
        Ok(Self {
            file,
            path: ns_path,
            env: Some(env),
        })
    }

    pub fn umount(self) -> Result<()> {
        // need close first
        nix::unistd::close(self.file.into_raw_fd()).map_err(Error::CloseNsError)?;
        Self::umount_ns(self.path, self.env)
    }

    fn umount_ns(path: PathBuf, env: Option<E>) -> Result<()> {
        // Only unmount if it's been bind-mounted (don't touch namespaces in /proc...)
        if let Some(env) = env {
            if path.starts_with(env.netns_run_dir()) {
                umount2(&path, MntFlags::MNT_DETACH)
                    .map_err(|e| Error::UnmountError(path.clone(), e))?;
                std::fs::remove_file(&path)
                    .map_err(|e| Error::RemoveNsError(path, e))
                    .ok();
            }
        }
        Ok(())
    }

    pub fn get_from_current_thread() -> Result<NetNs<E>> {
        let ns_path = Self::get_current_thread_netns_path();
        let file = File::open(&ns_path).map_err(|e| Error::OpenNsError(ns_path.clone(), e))?;
        Ok(Self {
            file,
            path: ns_path,
            env: None,
        })
    }

    #[inline]
    pub fn get_current_thread_netns_path() -> PathBuf {
        PathBuf::from(format!("/proc/self/task/{}/ns/net", gettid().to_string()))
    }

    pub fn run_with_env<P, F, T>(ns_path: P, env: E, f: F) -> Result<T>
    where
        P: AsRef<Path>,
        F: FnOnce() -> T,
    {
        // get current network namespace
        let src_ns = Self::get_from_current_thread()?;
        // get new network namespace
        let run_ns = Self::get_with_env(ns_path, env)?;

        // do nothing if ns_path is same as current_ns
        if src_ns == run_ns {
            return Ok(f());
        }
        // enter new namespace
        run_ns.set()?;

        let result = f();
        // back to old namespace
        src_ns.set()?;

        Ok(result)
    }
}

impl NetNs {
    /// Creates a new persistent (bind-mounted) network namespace and returns an object
    /// representing that namespace, without switching to it.
    pub fn new<S: AsRef<str>>(ns_name: S) -> Result<Self> {
        Self::new_with_env(ns_name, DefaultEnv)
    }

    pub fn get<P: AsRef<Path>>(ns_path: P) -> Result<Self> {
        Self::get_with_env(ns_path, DefaultEnv)
    }

    pub fn run<P, F, T>(ns_path: P, f: F) -> Result<T>
    where
        P: AsRef<Path>,
        F: FnOnce() -> T,
    {
        Self::run_with_env(ns_path, DefaultEnv, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::FromRawFd;

    #[test]
    fn test_netns_display() {
        let ns = NetNs::get_from_current_thread().unwrap();
        let print = format!("{}", ns);
        println!("{}", print);
        assert!(print.contains("dev"));
        assert!(print.contains("ino"));

        let ns = NetNs {
            file: unsafe { File::from_raw_fd(i32::MAX) },
            path: PathBuf::from(""),
            env: None,
        };
        let print = format!("{}", ns);
        println!("{}", print);
        assert!(!print.contains("dev"));
        assert!(!print.contains("ino"));
    }

    #[test]
    fn test_netns_eq() {
        let ns1 = NetNs::get_from_current_thread().unwrap();
        let ns2 = NetNs::get("/proc/self/ns/net").unwrap();
        println!("{} == {}", ns1, ns2);
        assert_eq!(ns1, ns2);

        let ns1 = NetNs {
            file: unsafe { File::from_raw_fd(i32::MAX) },
            path: PathBuf::from("aaaaaa"),
            env: None,
        };
        let ns2 = NetNs {
            file: unsafe { File::from_raw_fd(i32::MAX) },
            path: PathBuf::from("bbbbbb"),
            env: None,
        };
        println!("{} == {}", ns1, ns2);
        assert_eq!(ns1, ns2);

        let ns2 = NetNs {
            file: unsafe { File::from_raw_fd(i32::MAX - 1) },
            path: PathBuf::from("aaaaaa"),
            env: None,
        };
        println!("{} == {}", ns1, ns2);
        assert_eq!(ns1, ns2);
    }

    #[test]
    fn test_netns_init() {
        let ns = NetNs::new("test_netns_init").unwrap();
        println!("{}", ns);
        assert!(ns.path().exists());
        ns.umount().unwrap();
        assert!(!Path::new(&DefaultEnv.netns_run_dir())
            .join("test_netns_init")
            .exists());
    }

    #[test]
    fn test_netns_set() {
        let new = NetNs::new("test_netns_set").unwrap();
        println!("new: {}", new);
        assert!(new.path().exists());
        let src = NetNs::get_from_current_thread().unwrap();
        println!("src: {}", src);
        assert_ne!(src, new);

        new.set().unwrap();

        let cur = NetNs::get_from_current_thread().unwrap();
        println!("cur: {}", cur);

        assert_eq!(new, cur);
        assert_ne!(src, cur);
        assert_ne!(src, new);

        new.umount().unwrap();
        assert!(!Path::new(&DefaultEnv.netns_run_dir())
            .join("test_netns_set")
            .exists());
    }
}
