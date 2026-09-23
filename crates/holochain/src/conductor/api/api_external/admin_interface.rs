use crate::conductor::api::error::ConductorApiError;
use crate::conductor::api::error::ConductorApiResult;
use crate::conductor::api::error::SerializationError;
use crate::conductor::error::ConductorError;
use crate::conductor::interface::error::InterfaceError;
use crate::conductor::interface::error::InterfaceResult;
use crate::conductor::ConductorHandle;
pub use holochain_conductor_api::*;
use holochain_serialized_bytes::prelude::*;
use holochain_types::prelude::*;
use mr_bundle::FileSystemBundler;
use std::collections::HashSet;
use tracing::*;

/// The admin interface that external connections
/// can use to make requests to the conductor
/// The concrete (non-mock) implementation of the AdminInterfaceApi
#[derive(Clone)]
pub struct AdminInterfaceApi {
    /// Mutable access to the Conductor
    conductor_handle: ConductorHandle,
}

impl AdminInterfaceApi {
    /// Create an admin interface api.
    pub fn new(conductor_handle: ConductorHandle) -> Self {
        AdminInterfaceApi { conductor_handle }
    }

    /// Handle an [AdminRequest] and return an [AdminResponse].
    pub async fn handle_request(
        &self,
        request: Result<AdminRequest, SerializedBytesError>,
    ) -> InterfaceResult<AdminResponse> {
        // Don't hold the read across both awaits
        {
            self.conductor_handle
                .check_running()
                .map_err(Box::new)
                .map_err(InterfaceError::RequestHandler)?;
        }
        match request {
            Ok(request) => Ok(self.handle_admin_request(request).await),
            Err(e) => Ok(AdminResponse::Error(SerializationError::from(e).into())),
        }
    }

    /// Deal with error cases produced by `handle_admin_request_inner`
    pub(crate) async fn handle_admin_request(&self, request: AdminRequest) -> AdminResponse {
        debug!("admin request: {:?}", request);

        let res = self
            .handle_admin_request_inner(request)
            .await
            .unwrap_or_else(|e| AdminResponse::Error(e.into()));
        debug!("admin response: {:?}", res);
        res
    }

    async fn handle_admin_request_inner(
        &self,
        request: AdminRequest,
    ) -> ConductorApiResult<AdminResponse> {
        use AdminRequest::*;
        match request {
            CaptureSqlTiming { request } => Ok(AdminResponse::DiagnosticCapture(
                sql_capture_response(request),
            )),
            CaptureWorkflowDiagnostics { request } => Ok(AdminResponse::DiagnosticCapture(
                crate::core::queue_consumer::capture_workflow_diagnostics(request),
            )),
            CaptureHeap { request } => Ok(AdminResponse::HeapCapture(
                match crate::heap_capture::capture(request).await {
                    Ok(receipt) => HeapCaptureResponse::Completed(receipt),
                    Err(failure) => HeapCaptureResponse::Refused(failure),
                },
            )),
            AddAdminInterfaces(configs) => {
                self.conductor_handle
                    .clone()
                    .add_admin_interfaces(configs)
                    .await?;
                Ok(AdminResponse::AdminInterfacesAdded)
            }
            GetDnaDefinition(cell_id) => {
                let dna_def = self
                    .conductor_handle
                    .get_dna_definition(&cell_id)
                    .await?
                    .ok_or(ConductorApiError::CellMissing(*cell_id))?;
                Ok(AdminResponse::DnaDefinitionReturned(dna_def.content))
            }
            UpdateCoordinators(payload) => {
                let UpdateCoordinatorsPayload { cell_id, source } = *payload;
                let (coordinator_zomes, wasms) = match source {
                    CoordinatorSource::Path(ref path) => {
                        let bundle = FileSystemBundler::load_from::<CoordinatorManifest>(path)
                            .await
                            .map(CoordinatorBundle::from)?;
                        bundle.into_zomes().await?
                    }
                    CoordinatorSource::Bundle(bundle) => bundle.into_zomes().await?,
                };

                self.conductor_handle
                    .update_coordinators(cell_id, coordinator_zomes, wasms)
                    .await?;

                Ok(AdminResponse::CoordinatorsUpdated)
            }
            InstallApp(payload) => {
                let app: InstalledApp = self
                    .conductor_handle
                    .clone()
                    .install_app_bundle(*payload)
                    .await?;
                let dna_definitions = self.conductor_handle.get_dna_definitions(&app).await?;
                Ok(AdminResponse::AppInstalled(AppInfo::from_installed_app(
                    &app,
                    &dna_definitions,
                )))
            }
            UninstallApp {
                installed_app_id,
                force,
            } => {
                self.conductor_handle
                    .clone()
                    .uninstall_app(&installed_app_id, force)
                    .await?;
                Ok(AdminResponse::AppUninstalled)
            }
            ListDnas => {
                let dna_list = self.conductor_handle.list_dna_hashes().await?;
                Ok(AdminResponse::DnasListed(dna_list.into_iter().collect()))
            }
            GenerateAgentPubKey => {
                let agent_pub_key = self
                    .conductor_handle
                    .keystore()
                    .clone()
                    .new_sign_keypair_random()
                    .await?;
                Ok(AdminResponse::AgentPubKeyGenerated(agent_pub_key))
            }
            ListCellIds => {
                let cell_ids = self
                    .conductor_handle
                    .running_cell_ids()
                    .into_iter()
                    .collect();
                Ok(AdminResponse::CellIdsListed(cell_ids))
            }
            ListApps { status_filter } => {
                let apps = self.conductor_handle.list_apps(status_filter).await?;
                Ok(AdminResponse::AppsListed(apps))
            }
            EnableApp { installed_app_id } => {
                // Enable app
                let _ = self
                    .conductor_handle
                    .clone()
                    .enable_app(installed_app_id.clone())
                    .await?;
                let app_info = self
                    .conductor_handle
                    .get_app_info(&installed_app_id)
                    .await?
                    .ok_or(ConductorError::AppNotInstalled(installed_app_id))?;
                Ok(AdminResponse::AppEnabled(app_info))
            }
            DisableApp { installed_app_id } => {
                // Disable app
                self.conductor_handle
                    .clone()
                    .disable_app(installed_app_id, DisabledAppReason::User)
                    .await?;
                Ok(AdminResponse::AppDisabled)
            }
            AttachAppInterface {
                port,
                danger_bind_addr,
                allowed_origins,
                installed_app_id,
            } => {
                let port = port.unwrap_or(0);
                let port = self
                    .conductor_handle
                    .clone()
                    .add_app_interface(
                        either::Either::Left(port),
                        danger_bind_addr,
                        allowed_origins,
                        installed_app_id,
                    )
                    .await?;
                Ok(AdminResponse::AppInterfaceAttached { port })
            }
            ListAppInterfaces => {
                let interfaces = self.conductor_handle.list_app_interfaces().await?;
                Ok(AdminResponse::AppInterfacesListed(interfaces))
            }
            DumpState {
                cell_id,
                source_chain_cursor,
                limit,
            } => {
                let state = self
                    .conductor_handle
                    .dump_cell_state(&cell_id, source_chain_cursor.as_ref(), limit)
                    .await?;
                Ok(AdminResponse::StateDumped(state))
            }
            DumpConductorState => {
                let state = self.conductor_handle.dump_conductor_state().await?;
                Ok(AdminResponse::ConductorStateDumped(state))
            }
            DumpFullState {
                cell_id,
                dht_ops_cursor,
                limit,
            } => {
                let state = self
                    .conductor_handle
                    .dump_full_cell_state(&cell_id, dht_ops_cursor, limit)
                    .await?;
                Ok(AdminResponse::FullStateDumped(state))
            }
            DumpOpTimings {
                dna_hash,
                cursor,
                limit,
            } => {
                let timings = self
                    .conductor_handle
                    .dump_op_timings(&dna_hash, cursor, limit)
                    .await?;
                Ok(AdminResponse::OpTimingsDumped(timings))
            }
            DumpNetworkMetrics {
                dna_hash,
                include_dht_summary,
            } => {
                let dump = self
                    .conductor_handle
                    .dump_network_metrics(Kitsune2NetworkMetricsRequest {
                        dna_hash,
                        include_dht_summary,
                    })
                    .await?;
                Ok(AdminResponse::NetworkMetricsDumped(dump))
            }
            DumpNetworkStats => {
                let stats = self.conductor_handle.dump_network_stats().await?;
                Ok(AdminResponse::NetworkStatsDumped(stats))
            }
            AddAgentInfo { agent_infos } => {
                self.conductor_handle.add_agent_infos(agent_infos).await?;
                Ok(AdminResponse::AgentInfoAdded)
            }
            AgentInfo { dna_hashes } => {
                let r = self.conductor_handle.get_agent_infos(dna_hashes).await?;
                let mut encoded = Vec::with_capacity(r.len());
                for info in r {
                    encoded.push(info.encode()?);
                }
                Ok(AdminResponse::AgentInfo(encoded))
            }
            PeerMetaInfo { url, dna_hashes } => {
                let r = self
                    .conductor_handle
                    .peer_meta_info(url, dna_hashes)
                    .await?;
                Ok(AdminResponse::PeerMetaInfo(r))
            }
            GrantZomeCallCapability(payload) => self
                .conductor_handle
                .grant_zome_call_capability(*payload)
                .await
                .map(AdminResponse::ZomeCallCapabilityGranted),

            RevokeZomeCallCapability {
                action_hash,
                cell_id,
            } => {
                self.conductor_handle
                    .revoke_zome_call_capability(cell_id, action_hash)
                    .await?;
                Ok(AdminResponse::ZomeCallCapabilityRevoked)
            }

            ListCapabilityGrants {
                installed_app_id,
                include_revoked,
            } => {
                let state = self.conductor_handle.clone().get_state().await?;
                let app = state.get_app(&installed_app_id)?;
                let app_cells: HashSet<CellId> = app.required_cells().collect();
                let cap_info = self
                    .conductor_handle
                    .clone()
                    .capability_grant_info(&app_cells, include_revoked)
                    .await?;
                Ok(AdminResponse::CapabilityGrantsInfo(cap_info))
            }

            DeleteCloneCell(payload) => {
                self.conductor_handle.delete_clone_cell(&payload).await?;
                Ok(AdminResponse::CloneCellDeleted)
            }
            StorageInfo => Ok(AdminResponse::StorageInfo(
                self.conductor_handle.storage_info().await?,
            )),
            IssueAppAuthenticationToken(payload) => {
                Ok(AdminResponse::AppAuthenticationTokenIssued(
                    self.conductor_handle
                        .issue_app_authentication_token(payload)?,
                ))
            }
            RevokeAppAuthenticationToken(token) => {
                self.conductor_handle
                    .revoke_app_authentication_token(token)?;
                Ok(AdminResponse::AppAuthenticationTokenRevoked)
            }
            #[cfg(feature = "unstable-migration")]
            GetCompatibleCells(dna_hash) => Ok(AdminResponse::CompatibleCells(
                self.conductor_handle
                    .cells_by_dna_lineage(&dna_hash)
                    .await?,
            )),
        }
    }
}

fn sql_capture_response(request: CaptureDiagnosticRequest) -> CaptureDiagnosticResponse {
    let admission = holochain_trace::capture_sql_timing(
        request.schema_version,
        &request.nonce,
        request.requested_seconds,
    );
    let outcome = match admission.outcome {
        holochain_trace::SqlCaptureOutcome::Admitted => CaptureAdmissionOutcome::Admitted,
        holochain_trace::SqlCaptureOutcome::RefusedDisabled => {
            CaptureAdmissionOutcome::RefusedDisabled
        }
        holochain_trace::SqlCaptureOutcome::RefusedBusy => CaptureAdmissionOutcome::RefusedBusy,
        holochain_trace::SqlCaptureOutcome::RefusedDuplicateNonce => {
            CaptureAdmissionOutcome::RefusedDuplicateNonce
        }
        holochain_trace::SqlCaptureOutcome::RefusedGenerationBudget => {
            CaptureAdmissionOutcome::RefusedGenerationBudget
        }
        holochain_trace::SqlCaptureOutcome::RefusedInvalidRequest => {
            CaptureAdmissionOutcome::RefusedInvalidRequest
        }
        holochain_trace::SqlCaptureOutcome::RefusedIo => CaptureAdmissionOutcome::RefusedIo,
    };
    let counters = CaptureAdmissionCounters {
        admitted: admission.counters.admitted,
        refused_disabled: admission.counters.refused_disabled,
        refused_busy: admission.counters.refused_busy,
        refused_duplicate_nonce: admission.counters.refused_duplicate_nonce,
        refused_generation_budget: admission.counters.refused_generation_budget,
        refused_invalid_request: admission.counters.refused_invalid_request,
        refused_trace_unavailable: 0,
        refused_io: admission.counters.refused_io,
    };
    let window = (outcome == CaptureAdmissionOutcome::Admitted).then_some(DiagnosticWindowStatus {
        requested_seconds: request.requested_seconds,
        event_limit: 10_000,
        state: CaptureWindowState::Active,
    });
    CaptureDiagnosticResponse {
        schema_version: DIAGNOSTIC_CAPTURE_SCHEMA_VERSION,
        family: DiagnosticCaptureFamily::SqlTiming,
        nonce: if holochain_trace::private_capture::valid_capture_nonce(&request.nonce) {
            request.nonce
        } else {
            "invalid".to_owned()
        },
        outcome,
        producer_id: admission.producer_id,
        generation: admission.generation,
        output_basename: admission.output_basename,
        window,
        counters,
    }
}
