// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;

use anyhow::{anyhow, ensure, Result};
use async_trait::async_trait;
use protocols::image;
use std::convert::TryFrom;
use std::fs::File;
use tokio::sync::Mutex;
use ttrpc::{self, error::get_rpc_status as ttrpc_error};

use crate::rpc::{verify_cid, CONTAINER_BASE};
use crate::sandbox::Sandbox;
use crate::AGENT_CONFIG;

use oci_distribution::client::ImageData;
use oci_distribution::manifest::{OciDescriptor, OciManifest};
use oci_distribution::{manifest, secrets::RegistryAuth, Client, Reference};
use ocicrypt_rs::config::CryptoConfig;
use ocicrypt_rs::encryption::decrypt_layer;
use ocicrypt_rs::helpers::create_decrypt_config;
use ocicrypt_rs::spec::{
    MEDIA_TYPE_LAYEE_GZIP_ENC, MEDIA_TYPE_LAYER_ENC, MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_ENC,
    MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_GZIP_ENC,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};

const SKOPEO_PATH: &str = "/usr/bin/skopeo";
const UMOCI_PATH: &str = "/usr/local/bin/umoci";
const IMAGE_OCI: &str = "image_oci";
const KEYPROVIDER_PATH: &str = "/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf";
const IMAGE_OCI: &str = "image_oci:latest";
const AA_PATH: &str = "/usr/local/bin/attestation-agent";
const AA_PORT: &str = "127.0.0.1:50000";
const OCICRYPT_CONFIG_PATH: &str = "/tmp/ocicrypt_config.json";

// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

pub struct ImageService {
    sandbox: Arc<Mutex<Sandbox>>,
}

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IndexDescriptor {
    pub schema_version: u8,
    pub manifests: Vec<OciDescriptor>,
}

impl ImageService {
    pub fn new(sandbox: Arc<Mutex<Sandbox>>) -> Self {
        Self { sandbox }
    }

    fn build_oci_path(cid: &str) -> PathBuf {
        let mut oci_path = PathBuf::from("/tmp");
        oci_path.push(cid);
        oci_path.push(IMAGE_OCI);
        oci_path
    }

    #[tokio::main(flavor = "current_thread")]
    async fn download_image(
        image: &str,
        auth: &RegistryAuth,
    ) -> anyhow::Result<(OciManifest, String, ImageData)> {
        let reference = Reference::try_from(image)?;
        let mut client = Client::default();
        let (image_manifest, _image_digest, image_config) =
            client.pull_manifest_and_config(&reference, auth).await?;

        let mut last_error = None;
        let mut image_data = ImageData {
            layers: Vec::with_capacity(0),
            digest: None,
        };

        for i in 1..2 {
            match client
                .pull(
                    &reference,
                    auth,
                    vec![
                        manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
                        manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
                        MEDIA_TYPE_LAYEE_GZIP_ENC,
                        MEDIA_TYPE_LAYER_ENC,
                        MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_ENC,
                        MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_GZIP_ENC,
                    ],
                )
                .await
            {
                Ok(data) => {
                    image_data = data;
                    break;
                }
                Err(e) => {
                    println!(
                        "Got error on pull call attempt {}. Will retry in 1s: {:?}",
                        i, e
                    );
                    last_error.replace(e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }

        Ok((image_manifest, image_config, image_data))
    }

    fn pull_image_with_oci_distribution(
        image: &str,
        cid: &str,
        source_creds: &Option<String>,
    ) -> Result<()> {
        let oci_path = Self::build_oci_path(cid);
        fs::create_dir_all(&oci_path)?;

        info!(
            sl!(),
            "Attempting to pull image with rust crate {}...", image
        );

        let mut auth = RegistryAuth::Anonymous;
        if let Some(source_creds) = source_creds {
            let auth_info: Vec<&str> = source_creds.split(':').collect();
            if auth_info.len() == 2 {
                auth = RegistryAuth::Basic(auth_info[0].to_string(), auth_info[1].to_string());
            } else {
                warn!(sl!(), "invalid source_creds format \n");
            }
        }

        let (mut image_manifest, image_config, image_data) = Self::download_image(image, &auth)?;

        // Prepare OCI layout storage for umoci
        image_manifest.config.media_type = manifest::IMAGE_CONFIG_MEDIA_TYPE.to_string();
        let oci_blob_path = format!("{}/blobs/sha256/", oci_path.to_string_lossy());
        fs::create_dir_all(Path::new(&oci_blob_path))?;

        if let Some(config_name) = &image_manifest.config.digest.strip_prefix("sha256:") {
            let mut out_file = File::create(format!("{}/{}", oci_blob_path, config_name))?;
            out_file.write_all(image_config.as_bytes())?;
        }

        let mut cc = CryptoConfig::default();
        // aa_kbc_params will get from PR: https://github.com/kata-containers/kata-containers/pull/2911
        let aa_kbc_params = "kbc:ip:port".to_string();
        if aa_kbc_params != "" {
            let decrypt_config = format!("provider:attestation-agent:{}", aa_kbc_params);
            cc = create_decrypt_config(vec![decrypt_config], vec![])?;
        }

        // Covert docker layer media type to OCI type
        for layer_desc in image_manifest.layers.iter_mut() {
            if layer_desc.media_type == manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE {
                layer_desc.media_type = manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string();
            }
        }

        for layer in image_data.layers.iter() {
            let layer_digest = layer.clone().sha256_digest();

            if layer.media_type == MEDIA_TYPE_LAYEE_GZIP_ENC
                || layer.media_type == MEDIA_TYPE_LAYER_ENC
            {
                if cc.decrypt_config.is_none() {
                    break;
                }

                for layer_desc in image_manifest.layers.iter_mut() {
                    if layer_desc.digest == layer_digest {
                        let (layer_decryptor, _dec_digest) = decrypt_layer(
                            &cc.decrypt_config.as_ref().unwrap(),
                            layer.data.as_slice(),
                            layer_desc,
                            false,
                        )?;
                        let mut plaintxt_data: Vec<u8> = Vec::new();
                        let mut decryptor = layer_decryptor.unwrap();

                        decryptor.read_to_end(&mut plaintxt_data)?;
                        let layer_name = format!("{:x}", Sha256::digest(&plaintxt_data));
                        let mut out_file =
                            File::create(format!("{}/{}", oci_blob_path, layer_name))?;
                        info!(sl!(), "Saving image file {}...", layer_name);
                        out_file.write_all(&plaintxt_data)?;
                        layer_desc.media_type = manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string();

                        layer_desc.digest = format!("sha256:{}", layer_name);
                    }
                }
            } else if let Some(layer_name) = layer_digest.strip_prefix("sha256:") {
                let mut out_file = File::create(format!("{}/{}", oci_blob_path, layer_name))?;
                info!(sl!(), "Saving image file {}...", layer_name);
                out_file.write_all(&layer.data)?;
            }
        }
        let manifest_json = serde_json::to_string(&image_manifest)?;

        let image_manifest_file = format!(
            "{}{:x}",
            oci_blob_path,
            Sha256::digest(manifest_json.as_bytes())
        );

        let mut out_file = File::create(&image_manifest_file)?;
        out_file.write_all(manifest_json.as_bytes())?;

        let mut annotations = HashMap::new();
        annotations.insert(
            "org.opencontainers.image.ref.name".to_string(),
            "latest".to_string(),
        );

        let manifest_descriptor = OciDescriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: format!("sha256:{:x}", Sha256::digest(manifest_json.as_bytes())),
            size: manifest_json.len() as i64,
            annotations: Some(annotations),
            ..Default::default()
        };

        let index_descriptor = IndexDescriptor {
            schema_version: image_manifest.schema_version,
            manifests: vec![manifest_descriptor],
        };

        let mut out_file = File::create(format!("{}/index.json", oci_path.to_string_lossy()))?;
        out_file.write_all(serde_json::to_string(&index_descriptor).unwrap().as_bytes())?;

        let mut out_file = File::create(format!("{}/oci-layout", oci_path.to_string_lossy()))?;
        let oci_layout = r#"{"imageLayoutVersion": "1.0.0"}"#;
        out_file.write_all(oci_layout.as_bytes())?;

        Ok(())
    }

    fn pull_image_from_registry(
        image: &str,
        cid: &str,
        source_creds: &Option<&str>,
        aa_kbc_params: &String,
    ) -> Result<()> {
        let source_image = format!("{}{}", "docker://", image);

        let mut manifest_path = PathBuf::from("/tmp");
        manifest_path.push(cid);
        manifest_path.push("image_manifest");
        let target_path_manifest = format!("dir://{}", manifest_path.to_string_lossy());

        // Define the target transport and path for the OCI image, without signature
        let oci_path = Self::build_oci_path(cid);
        let target_path_oci = format!("oci://{}:latest", oci_path.to_string_lossy());

        fs::create_dir_all(&manifest_path)?;
        fs::create_dir_all(&oci_path)?;

        info!(sl!(), "Attempting to pull image {}...", &source_image);

        let mut pull_command = Command::new(SKOPEO_PATH);
        pull_command
            // TODO: need to create a proper policy
            .arg("--insecure-policy")
            .arg("copy")
            .arg(source_image)
            .arg(&target_path_manifest);

        if let Some(source_creds) = source_creds {
            pull_command.arg("--src-creds").arg(source_creds);
        }

        if aa_kbc_params != "" {
            // Skopeo will copy an unencrypted image even if the decryption key argument is provided.
            // Thus, this does not guarantee that the image was encrypted.
            pull_command
                .arg("--decryption-key")
                .arg(format!("provider:attestation-agent:{}", aa_kbc_params))
                .env("OCICRYPT_KEYPROVIDER_CONFIG", KEYPROVIDER_PATH);
        }

        let status: ExitStatus = pull_command.status()?;
        ensure!(
            status.success(),
            "failed to copy image manifest: {:?}",
            status,
        );

        // Copy image from one local file-system to another
        // Resulting image is still stored in manifest format, but no longer includes the signature
        // The image with a signature can then be unpacked into a bundle
        let status: ExitStatus = Command::new(SKOPEO_PATH)
            .arg("--insecure-policy")
            .arg("copy")
            .arg(&target_path_manifest)
            .arg(&target_path_oci)
            .arg("--remove-signatures")
            .status()?;

        ensure!(status.success(), "failed to copy image oci: {:?}", status);

        // To save space delete the manifest.
        // TODO LATER - when verify image is added, this will need moving the end of that, if required
        fs::remove_dir_all(&manifest_path)?;
        Ok(())
    }

    fn unpack_image(cid: &str) -> Result<()> {
        let source_path_oci = Self::build_oci_path(cid);
        let target_path_bundle = format!("{}{}{}", CONTAINER_BASE, "/", cid);

        info!(sl!(), "unpack image"; "cid" => cid, "target_bundle_path" => &target_path_bundle);

        // Unpack image
        let status: ExitStatus = Command::new(UMOCI_PATH)
            .arg("unpack")
            .arg("--image")
            .arg(&source_path_oci)
            .arg(&target_path_bundle)
            .status()?;

        ensure!(status.success(), "failed to unpack image: {:?}", status);

        // To save space delete the oci image after unpack
        fs::remove_dir_all(&source_path_oci)?;

        Ok(())
    }

    // If we fail to start the AA, Skopeo/ocicrypt won't be able to unwrap keys
    // and container decryption will fail.
    //fn init_attestation_agent() {
    //    let config_path = OCICRYPT_CONFIG_PATH;

    //    // The image will need to be encrypted using a keyprovider
    //    // that has the same name (at least according to the config).
    //    let ocicrypt_config = serde_json::json!({
    //        "key-providers": {
    //            "attestation-agent":{
    //                "grpc":AA_PORT
    //            }
    //        }
    //    });

    //    let mut config_file = fs::File::create(config_path).unwrap();
    //    config_file
    //        .write_all(ocicrypt_config.to_string().as_bytes())
    //        .unwrap();

    //    // The Attestation Agent will run for the duration of the guest.
    //    Command::new(AA_PATH)
    //        .arg("--grpc_sock")
    //        .arg(AA_PORT)
    //        .spawn()
    //        .unwrap();

    //}

    async fn pull_image(&self, req: &image::PullImageRequest) -> Result<String> {
        env::set_var("OCICRYPT_KEYPROVIDER_CONFIG", KEYPROVIDER_PATH);

        let image = req.get_image();
        let mut cid = req.get_container_id();
        let use_skopeo = req.get_use_skopeo();

        let agent_config = AGENT_CONFIG.read().await;
        let aa_kbc_params = &agent_config.aa_kbc_params;
        let aa_started = agent_config.confidential_setup_complete;

        if cid.is_empty() {
            let v: Vec<&str> = image.rsplit('/').collect();
            if !v[0].is_empty() {
                cid = v[0]
            } else {
                return Err(anyhow!("Invalid image name. {}", image));
            }
        } else {
            verify_cid(cid)?;
        }

        //if aa_kbc_params != "" && !aa_started {
        //Self::init_attestation_agent();
        //let mut agent_config = AGENT_CONFIG.write().await;
        //agent_config.confidential_setup_complete = true;
        //}

        let source_creds = (!req.get_source_creds().is_empty()).then(|| req.get_source_creds());

        if use_skopeo {
            Self::pull_image_from_registry(image, cid, &source_creds, aa_kbc_params)?;
        } else {
            let image = image.to_string();
            let cid = cid.to_string();
            let source_creds =
                (!req.get_source_creds().is_empty()).then(|| req.get_source_creds().to_string());
            tokio::task::spawn_blocking(move || {
                Self::pull_image_with_oci_distribution(&image, &cid, &source_creds)
                    .map_err(|err| println!("{:?}", err))
                    .ok();
            })
            .await?;
        }

        Self::unpack_image(cid)?;

        let mut sandbox = self.sandbox.lock().await;
        sandbox.images.insert(String::from(image), cid.to_string());
        Ok(image.to_owned())
    }
}

#[async_trait]
impl protocols::image_ttrpc::Image for ImageService {
    async fn pull_image(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        req: image::PullImageRequest,
    ) -> ttrpc::Result<image::PullImageResponse> {
        match self.pull_image(&req).await {
            Ok(r) => {
                let mut resp = image::PullImageResponse::new();
                resp.image_ref = r;
                return Ok(resp);
            }
            Err(e) => {
                return Err(ttrpc_error(ttrpc::Code::INTERNAL, e.to_string()));
            }
        }
    }
}
