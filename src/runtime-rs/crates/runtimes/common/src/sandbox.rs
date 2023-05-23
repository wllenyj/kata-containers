// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use async_trait::async_trait;

#[derive(Clone)]
pub struct SandboxNetworkEnv {
    pub netns: Option<String>,
    pub network_created: bool,
}

pub struct SandboxResource {
    pub network: SandboxNetworkEnv,
}

#[derive(Default, Clone, Debug)]
pub struct SandboxStatus {
    pub sandbox_id: String,
    pub pid: u32,
    pub state: String,
    pub info: std::collections::HashMap<String, String>,
    pub create_at: std::time::Duration,
    pub exited_at: std::time::Duration,
}

#[async_trait]
pub trait Sandbox: Send + Sync {
    async fn create(&self, network_env: SandboxNetworkEnv) -> Result<()> {
        Ok(())
    }
    async fn status(&self) -> Result<SandboxStatus> {
        Ok(SandboxStatus::default())
    }
    async fn wait(&self) -> Result<()> {
        Ok(())
    }
    async fn start(
        &self,
        dns: Vec<String>,
        spec: &oci::Spec,
        state: &oci::State,
        network_env: SandboxNetworkEnv,
    ) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn cleanup(&self) -> Result<()>;
    async fn shutdown(&self) -> Result<()>;

    // agent function
    async fn agent_sock(&self) -> Result<String>;

    // utils
    async fn set_iptables(&self, is_ipv6: bool, data: Vec<u8>) -> Result<Vec<u8>>;
    async fn get_iptables(&self, is_ipv6: bool) -> Result<Vec<u8>>;
    async fn direct_volume_stats(&self, volume_path: &str) -> Result<String>;
    async fn direct_volume_resize(&self, resize_req: agent::ResizeVolumeRequest) -> Result<()>;
}
