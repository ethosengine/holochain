use crate::conductor::api::error::ConductorApiError;
use crate::conductor::api::error::ConductorApiResult;
use crate::conductor::api::error::SerializationError;
use crate::conductor::interface::error::InterfaceError;
use crate::conductor::interface::error::InterfaceResult;
use crate::conductor::ConductorHandle;
use holochain_conductor_api::conductor::ConductorConfig;
pub use holochain_conductor_api::*;
use holochain_serialized_bytes::prelude::*;
use holochain_types::prelude::*;
use std::time::Duration;

/// What the conductor decided to do with an incoming zome call, before any of
/// the call's work has begun.
///
/// This is the return type of [`ZomeCallAdmission::decide`], which is a pure
/// function of the policy, the caller's declared deadline, and the number of
/// calls already running. Keeping the decision separate from the machinery that
/// enacts it is what makes the policy testable without a conductor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZomeCallAdmissionDecision {
    /// Run the call, bounded by this deadline.
    ///
    /// `None` means run it unbounded, which is the behaviour of conductors that
    /// predate deadlines.
    Admit(Option<Duration>),
    /// Decline to start the call, because the interface is already running
    /// `in_flight` calls against a limit of `max_in_flight` and the caller told
    /// us it will not wait long enough for a slot to free up.
    Refuse {
        /// How many zome calls this interface was already running.
        in_flight: usize,
        /// The configured concurrent zome call limit.
        max_in_flight: usize,
    },
}

/// Admission and deadline policy for zome calls arriving on one app interface.
#[derive(Debug)]
pub struct ZomeCallAdmission {
    max_in_flight: Option<usize>,
    default_deadline: Option<Duration>,
    max_deadline: Duration,
}

impl ZomeCallAdmission {
    /// Build the policy from a conductor's tuning parameters.
    pub fn from_config(config: &ConductorConfig) -> Self {
        let tuning = config.conductor_tuning_params();
        Self {
            max_in_flight: tuning.max_concurrent_zome_calls(),
            default_deadline: tuning.zome_call_deadline(),
            max_deadline: tuning.zome_call_deadline_max(),
        }
    }

    /// Decide what to do with a call, given the caller's declared deadline and
    /// the number of calls already running on this interface.
    ///
    /// Pure: no clock, no counter, no side effects.
    ///
    /// The rules, in order:
    ///
    /// - A declared deadline is clamped to the configured maximum. Absent a
    ///   declared deadline, the configured default applies, which may be none.
    /// - At the concurrency limit, a call with an effective deadline is
    ///   refused. Refusing now is strictly better for that caller than
    ///   spending its deadline in a queue.
    /// - At the concurrency limit, a call with no effective deadline is still
    ///   admitted and queued. An existing client that never declared a deadline
    ///   must not start seeing refusals it has no code to handle.
    pub fn decide(
        &self,
        declared: Option<Duration>,
        in_flight: usize,
    ) -> ZomeCallAdmissionDecision {
        let effective = match declared {
            Some(d) => Some(d.min(self.max_deadline)),
            None => self.default_deadline,
        };

        match (self.max_in_flight, effective) {
            (Some(max), Some(_)) if in_flight >= max => ZomeCallAdmissionDecision::Refuse {
                in_flight,
                max_in_flight: max,
            },
            _ => ZomeCallAdmissionDecision::Admit(effective),
        }
    }
}

/// The Conductor lives inside an Arc<RwLock<_>> which is shared with all
/// other Api references
#[derive(Clone)]
pub struct AppInterfaceApi {
    conductor_handle: ConductorHandle,
}

impl AppInterfaceApi {
    /// Create a new instance from a shared Conductor reference
    pub fn new(conductor_handle: ConductorHandle) -> Self {
        Self { conductor_handle }
    }

    /// Check an authentication request and return the app that access has been granted
    /// for on success.
    pub async fn auth(&self, auth: AppAuthentication) -> InterfaceResult<InstalledAppId> {
        self.conductor_handle
            .authenticate_app_token(auth.token, auth.installed_app_id)
            .map_err(Box::new)
            .map_err(InterfaceError::RequestHandler)
    }

    /// Handle an [AppRequest] in the context of an [InstalledAppId], and return an [AppResponse].
    pub async fn handle_request(
        &self,
        installed_app_id: InstalledAppId,
        request: Result<AppRequest, SerializedBytesError>,
    ) -> InterfaceResult<AppResponse> {
        {
            self.conductor_handle
                .check_running()
                .map_err(Box::new)
                .map_err(InterfaceError::RequestHandler)?;
        }
        match request {
            Ok(request) => Ok(self.handle_app_request(installed_app_id, request).await),
            Err(e) => Ok(AppResponse::Error(SerializationError::from(e).into())),
        }
    }

    /// Deal with error cases produced by `handle_app_request_inner`
    async fn handle_app_request(
        &self,
        installed_app_id: InstalledAppId,
        request: AppRequest,
    ) -> AppResponse {
        tracing::debug!("app request: {:?}", request);

        let res = self
            .handle_app_request_inner(installed_app_id, request)
            .await
            .unwrap_or_else(|e| AppResponse::Error(e.into()));
        tracing::debug!("app response: {:?}", res);
        res
    }

    /// Routes the [AppRequest] to the [AppResponse]
    async fn handle_app_request_inner(
        &self,
        installed_app_id: InstalledAppId,
        request: AppRequest,
    ) -> ConductorApiResult<AppResponse> {
        match request {
            AppRequest::AppInfo => Ok(AppResponse::AppInfo(
                self.conductor_handle
                    .get_app_info(&installed_app_id)
                    .await?,
            )),
            AppRequest::AgentInfo { dna_hashes } => {
                let agent_infos = self
                    .conductor_handle
                    .get_app_agent_infos(&installed_app_id, dna_hashes)
                    .await?;
                let items: Result<Vec<_>, _> =
                    agent_infos.into_iter().map(|info| info.encode()).collect();
                Ok(AppResponse::AgentInfo(items?))
            }
            AppRequest::PeerMetaInfo { url, dna_hashes } => {
                let r = self
                    .conductor_handle
                    .app_peer_meta_info(&installed_app_id, url, dna_hashes)
                    .await?;
                Ok(AppResponse::PeerMetaInfo(r))
            }
            AppRequest::CallZome(zome_call_params_signed) => {
                self.handle_call_zome(*zome_call_params_signed).await
            }
            AppRequest::CallZomeWithDeadline { call, .. } => {
                self.handle_call_zome(*call).await
            }
            #[cfg(feature = "unstable-countersigning")]
            AppRequest::GetCountersigningSessionState(payload) => {
                let countersigning_session_state = self
                    .conductor_handle
                    .clone()
                    .get_countersigning_session_state(&payload)
                    .await?;
                Ok(AppResponse::CountersigningSessionState(Box::new(
                    countersigning_session_state,
                )))
            }
            #[cfg(feature = "unstable-countersigning")]
            AppRequest::AbandonCountersigningSession(payload) => {
                self.conductor_handle
                    .clone()
                    .abandon_countersigning_session(&payload)
                    .await?;
                Ok(AppResponse::CountersigningSessionAbandoned)
            }
            #[cfg(feature = "unstable-countersigning")]
            AppRequest::PublishCountersigningSession(payload) => {
                self.conductor_handle
                    .clone()
                    .publish_countersigning_session(&payload)
                    .await?;
                Ok(AppResponse::PublishCountersigningSessionTriggered)
            }
            AppRequest::CreateCloneCell(payload) => {
                let clone_cell = self
                    .conductor_handle
                    .clone()
                    .create_clone_cell(&installed_app_id, *payload)
                    .await?;
                Ok(AppResponse::CloneCellCreated(clone_cell))
            }
            AppRequest::DisableCloneCell(payload) => {
                self.conductor_handle
                    .clone()
                    .disable_clone_cell(&installed_app_id, &payload)
                    .await?;
                Ok(AppResponse::CloneCellDisabled)
            }
            AppRequest::EnableCloneCell(payload) => {
                let enabled_cell = self
                    .conductor_handle
                    .clone()
                    .enable_clone_cell(&installed_app_id, &payload)
                    .await?;
                Ok(AppResponse::CloneCellEnabled(enabled_cell))
            }
            AppRequest::DumpOpTimings {
                dna_hash,
                cursor,
                limit,
            } => {
                let timings = self
                    .conductor_handle
                    .dump_op_timings_for_app(&installed_app_id, &dna_hash, cursor, limit)
                    .await?;
                Ok(AppResponse::OpTimingsDumped(timings))
            }
            AppRequest::DumpNetworkMetrics {
                dna_hash,
                include_dht_summary,
            } => {
                let info = self
                    .conductor_handle
                    .dump_network_metrics_for_app(
                        &installed_app_id,
                        Kitsune2NetworkMetricsRequest {
                            dna_hash,
                            include_dht_summary,
                        },
                    )
                    .await?;
                Ok(AppResponse::NetworkMetricsDumped(info))
            }
            AppRequest::DumpNetworkStats => {
                let stats = self
                    .conductor_handle
                    .dump_network_stats_for_app(&installed_app_id)
                    .await?;
                Ok(AppResponse::NetworkStatsDumped(stats))
            }
            AppRequest::ListWasmHostFunctions => Ok(AppResponse::ListWasmHostFunctions(
                self.conductor_handle.list_wasm_host_functions().await?,
            )),
            AppRequest::ProvideMemproofs(memproofs) => {
                self.conductor_handle
                    .clone()
                    .provide_memproofs(&installed_app_id, memproofs)
                    .await?;
                Ok(AppResponse::Ok)
            }
            AppRequest::EnableApp => {
                let status = self
                    .conductor_handle
                    .get_app_info(&installed_app_id)
                    .await?
                    .ok_or(ConductorApiError::other("app not found".to_string()))?
                    .status;
                match status {
                    AppStatus::Enabled
                    | AppStatus::Disabled(DisabledAppReason::NotStartedAfterProvidingMemproofs) => {
                        self.conductor_handle
                            .clone()
                            .enable_app(installed_app_id.clone())
                            .await?;
                        Ok(AppResponse::Ok)
                    }
                    _ => Err(ConductorApiError::other(
                        "app not in correct state to enable".to_string(),
                    )),
                }
            }
            AppRequest::SendDirectSignal {
                dna_hash,
                agents,
                signal,
            } => {
                self.conductor_handle
                    .clone()
                    .send_direct_signal(installed_app_id, dna_hash, agents, signal)
                    .await?;

                Ok(AppResponse::Ok)
            }
        }
    }

    /// Run a zome call and translate its outcome into an [`AppResponse`].
    ///
    /// Shared by [`AppRequest::CallZome`] and
    /// [`AppRequest::CallZomeWithDeadline`]; the latter's deadline is not yet
    /// acted on.
    async fn handle_call_zome(
        &self,
        zome_call_params_signed: ZomeCallParamsSigned,
    ) -> ConductorApiResult<AppResponse> {
        match self
            .conductor_handle
            .handle_external_zome_call(zome_call_params_signed)
            .await?
        {
            Ok(ZomeCallResponse::Ok(output)) => Ok(AppResponse::ZomeCalled(Box::new(output))),
            Ok(ZomeCallResponse::AuthenticationFailed(signature, provenance)) => Ok(AppResponse::Error(
                ExternalApiWireError::ZomeCallAuthenticationFailed(format!(
                    "Authentication failure. Bad signature {signature:?} by provenance {provenance:?}.",
                )),
            )),
            Ok(ZomeCallResponse::Unauthorized(zome_call_authorization, cap_secret, zome_name, fn_name)) => Ok(AppResponse::Error(
                ExternalApiWireError::ZomeCallUnauthorized(format!(
                    "Call was not authorized with reason {zome_call_authorization:?}, cap secret {cap_secret:?} to call the function {fn_name} in zome {zome_name}"
                )),
            )),
            Ok(ZomeCallResponse::NetworkError(e)) => unreachable!(
                "Interface zome calls should never be routed to the network. This is a bug. Got {}",
                e
            ),
            Ok(ZomeCallResponse::CountersigningSession(e)) => Ok(AppResponse::Error(
                ExternalApiWireError::CountersigningSessionError(format!(
                    "A countersigning session has failed to start on this zome call because: {e}"
                )),
            )),
            Err(e) => Ok(AppResponse::Error(e.into())),
        }
    }
}

/// The payload for authenticating an app interface connection
#[derive(Debug, serde::Serialize, serde::Deserialize, SerializedBytes)]
pub struct AppAuthentication {
    /// The token received from the admin interface, demonstrating that the app is allowed
    /// to connect.
    pub token: Vec<u8>,

    /// If the app interface is bound to an installed app, this is the ID of that app. This field
    /// must be provided by Holochain and not the client.
    pub installed_app_id: Option<InstalledAppId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use holochain_conductor_api::conductor::ConductorTuningParams;

    fn admission(
        default_deadline: Option<Duration>,
        max_deadline: Option<Duration>,
        max_concurrent: Option<usize>,
    ) -> ZomeCallAdmission {
        let config = ConductorConfig {
            tuning_params: Some(ConductorTuningParams {
                zome_call_deadline: default_deadline,
                zome_call_deadline_max: max_deadline,
                max_concurrent_zome_calls: max_concurrent,
                ..Default::default()
            }),
            ..Default::default()
        };
        ZomeCallAdmission::from_config(&config)
    }

    #[test]
    fn unconfigured_conductor_admits_every_call_unbounded() {
        let admission = admission(None, None, None);

        // This is the pre-deadline behaviour, and it must be exactly preserved
        // for a conductor whose operator has not opted in.
        assert_eq!(
            admission.decide(None, 0),
            ZomeCallAdmissionDecision::Admit(None)
        );
        assert_eq!(
            admission.decide(None, 10_000),
            ZomeCallAdmissionDecision::Admit(None)
        );
    }

    #[test]
    fn declared_deadline_is_honoured_and_clamped_to_the_configured_maximum() {
        let admission = admission(None, Some(Duration::from_secs(30)), None);

        assert_eq!(
            admission.decide(Some(Duration::from_secs(5)), 0),
            ZomeCallAdmissionDecision::Admit(Some(Duration::from_secs(5)))
        );
        assert_eq!(
            admission.decide(Some(Duration::from_secs(600)), 0),
            ZomeCallAdmissionDecision::Admit(Some(Duration::from_secs(30)))
        );
    }

    #[test]
    fn default_maximum_deadline_is_five_minutes() {
        let admission = admission(None, None, None);

        assert_eq!(
            admission.decide(Some(Duration::from_secs(3600)), 0),
            ZomeCallAdmissionDecision::Admit(Some(Duration::from_secs(300)))
        );
    }

    #[test]
    fn configured_default_deadline_applies_when_the_caller_declares_none() {
        let admission = admission(Some(Duration::from_secs(15)), None, None);

        assert_eq!(
            admission.decide(None, 0),
            ZomeCallAdmissionDecision::Admit(Some(Duration::from_secs(15)))
        );
        // An explicit declaration always wins over the conductor default.
        assert_eq!(
            admission.decide(Some(Duration::from_secs(2)), 0),
            ZomeCallAdmissionDecision::Admit(Some(Duration::from_secs(2)))
        );
    }

    #[test]
    fn at_the_concurrency_limit_a_deadlined_call_is_refused_not_queued() {
        let admission = admission(None, None, Some(4));

        assert_eq!(
            admission.decide(Some(Duration::from_secs(5)), 3),
            ZomeCallAdmissionDecision::Admit(Some(Duration::from_secs(5)))
        );
        assert_eq!(
            admission.decide(Some(Duration::from_secs(5)), 4),
            ZomeCallAdmissionDecision::Refuse {
                in_flight: 4,
                max_in_flight: 4
            }
        );
        assert_eq!(
            admission.decide(Some(Duration::from_secs(5)), 9),
            ZomeCallAdmissionDecision::Refuse {
                in_flight: 9,
                max_in_flight: 4
            }
        );
    }

    #[test]
    fn at_the_concurrency_limit_a_call_without_a_deadline_is_still_queued() {
        // A client that never declared a deadline has no code to handle a
        // refusal, so the limit must not change what it sees.
        let admission = admission(None, None, Some(4));

        assert_eq!(
            admission.decide(None, 99),
            ZomeCallAdmissionDecision::Admit(None)
        );
    }

    #[test]
    fn a_conductor_default_deadline_makes_the_concurrency_limit_bite() {
        // Once an operator sets a default deadline, calls that declare nothing
        // acquire one, and therefore become refusable at the limit. This is the
        // documented consequence of opting in.
        let admission = admission(Some(Duration::from_secs(15)), None, Some(2));

        assert_eq!(
            admission.decide(None, 2),
            ZomeCallAdmissionDecision::Refuse {
                in_flight: 2,
                max_in_flight: 2
            }
        );
    }
}
