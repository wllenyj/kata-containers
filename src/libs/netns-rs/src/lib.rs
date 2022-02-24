// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

mod netns;
pub use self::netns::*;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("create netns dir failed. {0}")]
    CreateNsDirError(std::io::Error),

    #[error("create netns failed. {0}")]
    CreateNsError(std::io::Error),

    #[error("open netns {0} failed. {1}")]
    OpenNsError(std::path::PathBuf, std::io::Error),

    #[error("close netns failed. {0}")]
    CloseNsError(nix::Error),

    #[error("remove netns {0} failed. {1}")]
    RemoveNsError(std::path::PathBuf, std::io::Error),

    #[error("mount {0} failed. {1}")]
    MountError(String, nix::Error),

    #[error("unmount {0} failed. {1}")]
    UnmountError(std::path::PathBuf, nix::Error),

    #[error("unshare failed. {0}")]
    UnshareError(nix::Error),

    #[error("join thread failed. {0}")]
    JoinThreadError(String),

    #[error("setns failed. {0}")]
    SetnsError(nix::Error),
}
