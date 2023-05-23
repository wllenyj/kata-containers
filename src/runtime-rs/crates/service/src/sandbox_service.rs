// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use async_trait::async_trait;
use containerd_shim_protos::{sandbox_api, sandbox_async};
use protobuf::Message;
use ttrpc::{self, r#async::TtrpcContext};

use runtimes::{manager::CreateOpt, RuntimeHandlerManager};

use crate::protos::api;

pub(crate) struct SandboxService {
    handler: Arc<RuntimeHandlerManager>,
}

impl SandboxService {
    pub(crate) fn new(handler: Arc<RuntimeHandlerManager>) -> Self {
        Self { handler }
    }
}

#[async_trait]
impl sandbox_async::Sandbox for SandboxService {
    async fn create_sandbox(
        &self,
        _ctx: &TtrpcContext,
        req: sandbox_api::CreateSandboxRequest,
    ) -> ttrpc::Result<sandbox_api::CreateSandboxResponse> {
        info!(sl!(), "----> create_sandbox {:?}", req);

        // TODO: api v1alpha2
        if req.options.type_url != "runtime.v1.PodSandboxConfig" {
            return Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(
                ::ttrpc::Code::INVALID_ARGUMENT,
                format!("{} is not supported", req.options.type_url),
            )));
        }
        let config = api::PodSandboxConfig::parse_from_bytes(&req.options.value);
        info!(sl!(), "----> create_sandbox config: {:?}", config);

        let opt = CreateOpt{
            netns_path: Some(req.netns_path.clone()),
        };
        self.handler
            .sandbox_api_create(&opt)
            .await
            .map_err(|err| ttrpc::Error::Others(format!("failed to create: {:?}", err)))?;

        return Ok(sandbox_api::CreateSandboxResponse::new());
    }
    async fn start_sandbox(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        _: sandbox_api::StartSandboxRequest,
    ) -> ::ttrpc::Result<sandbox_api::StartSandboxResponse> {

        let mut resp = sandbox_api::StartSandboxResponse::new(); 
        resp.pid = std::process::id();
        resp.set_created_at(protobuf::well_known_types::timestamp::Timestamp::now());

        Ok(resp)
    }
    async fn platform(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        _: sandbox_api::PlatformRequest,
    ) -> ::ttrpc::Result<sandbox_api::PlatformResponse> {

        let mut resp = sandbox_api::PlatformResponse::new(); 
        resp.mut_platform().set_os("linux".to_string());
        resp.mut_platform().set_architecture("amd64".to_string());
        
        Ok(resp)
    }
    async fn stop_sandbox(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        _: sandbox_api::StopSandboxRequest,
    ) -> ::ttrpc::Result<sandbox_api::StopSandboxResponse> {

        self.handler.sandbox_api_stop().await
            .map_err(|err| ttrpc::Error::Others(format!("failed to stop: {:?}", err)))?;

        Ok(sandbox_api::StopSandboxResponse::new())
    }
    async fn wait_sandbox(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        _: sandbox_api::WaitSandboxRequest,
    ) -> ::ttrpc::Result<sandbox_api::WaitSandboxResponse> {

        self.handler.sandbox_api_wait().await
            .map_err(|err| ttrpc::Error::Others(format!("failed to wait: {:?}", err)))?;

        Ok(sandbox_api::WaitSandboxResponse::new())
    }
    async fn sandbox_status(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        _: sandbox_api::SandboxStatusRequest,
    ) -> ::ttrpc::Result<sandbox_api::SandboxStatusResponse> {

        let status = self.handler.sandbox_api_status().await
            .map_err(|err| ttrpc::Error::Others(format!("failed to status: {:?}", err)))?;

        let mut ret = sandbox_api::SandboxStatusResponse::new();
        ret.sandbox_id = status.sandbox_id;
        ret.pid = status.pid;
        ret.state = status.state;

        Ok(ret)
    }
    async fn ping_sandbox(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        _: sandbox_api::PingRequest,
    ) -> ::ttrpc::Result<sandbox_api::PingResponse> {
        Ok(sandbox_api::PingResponse::new())
    }
    async fn shutdown_sandbox(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        _: sandbox_api::ShutdownSandboxRequest,
    ) -> ::ttrpc::Result<sandbox_api::ShutdownSandboxResponse> {

        self.handler.sandbox_api_shutdown().await
            .map_err(|err| ttrpc::Error::Others(format!("failed to shutdown: {:?}", err)))?;


        Ok(sandbox_api::ShutdownSandboxResponse::new())
    }
}
