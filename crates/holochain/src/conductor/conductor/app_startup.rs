//! Conductor startup of the enabled apps.
//!
//! Each enabled app starts as one unit — its ribosomes are loaded, its cells
//! are created and joined to the network, and those cells are published as
//! running — independently of every other app. A slow app holds only its own
//! slot, and an app whose startup fails is disabled while the rest start.

use super::*;
use holochain_types::cell_config_overrides::CellConfigOverrides;
use std::future::Future;

/// Maximum number of enabled-app startup attempts in flight during conductor
/// startup.
///
/// An attempt is one app's whole startup: loading its ribosomes, creating its
/// cells and awaiting their network joins — the last two bounded per app by
/// `CELL_CREATION_CONCURRENCY` and `NETWORK_JOIN_CONCURRENCY`. So at most this
/// many apps' worth of that work runs at once, and the next app in the
/// conductor's order starts as soon as any attempt finishes.
///
/// It bounds attempts, not time: an attempt that never finishes holds its
/// slot for as long as it is pending. Nor does it bound the work nested inside
/// an attempt beyond those per-app limits, or operations that arrive on the
/// admin interface while startup is under way.
pub(crate) const APP_STARTUP_CONCURRENCY: usize = 4;

impl Conductor {
    /// Start every enabled app, at most [`APP_STARTUP_CONCURRENCY`] at a time,
    /// and return once every attempt has finished.
    ///
    /// An app's cells are running as soon as its own attempt succeeds. An app
    /// whose attempt fails — including one refused because its P2P overrides
    /// conflict with an app earlier in the conductor's order — is disabled with
    /// [`DisabledAppReason::Error`], so the next restart does not retry it.
    /// The only error returned is a failure to record such a disable, and it is
    /// returned only after every attempt has finished.
    pub(crate) async fn startup_enabled_apps(self: Arc<Self>) -> ConductorResult<()> {
        let state = self.get_state().await?;
        let mut reservations = P2pOverrideReservations::default();
        let attempts: Vec<_> = state
            .enabled_apps()
            .map(|(app_id, app)| {
                let admission = reservations.reserve(app);
                let conductor = self.clone();
                let app = app.clone();
                let publication = CellPublication::WhileAppEnabled(app_id.clone());
                let attempt = async move {
                    match admission {
                        Ok(()) => conductor.startup_app(app, publication).await,
                        Err(conflict) => Err(conflict.into()),
                    }
                };
                (app_id.clone(), attempt)
            })
            .collect();

        run_app_startup_attempts(attempts, |app_id, error| {
            self.clone().disable_app_after_failed_startup(app_id, error)
        })
        .await
    }

    /// Start one app: load its ribosomes, then create its enabled cells, join
    /// them to the network and publish them as running, as `publication`
    /// allows.
    ///
    /// When this returns `Ok` every enabled cell of the app is running, unless
    /// `publication` withheld them all; when it returns `Err` none of them is.
    /// Setting the app's persisted status is the caller's part.
    pub(crate) async fn startup_app(
        self: Arc<Self>,
        app: InstalledApp,
        publication: CellPublication,
    ) -> ConductorResult<()> {
        self.load_wasms_into_ribosome_for_app(&app).await?;
        let config_override = Self::p2p_config_overrides(&app.manifest);
        self.create_and_publish_cells(app.all_enabled_cells(), config_override, publication)
            .await
    }

    /// Disable an app whose startup failed, with the failure as its reason.
    async fn disable_app_after_failed_startup(
        self: Arc<Self>,
        app_id: InstalledAppId,
        error: ConductorError,
    ) -> ConductorResult<()> {
        error!(%app_id, ?error, "App startup failed; disabling the app.");
        let reason = DisabledAppReason::Error(error.to_string());
        if let Err(disable_error) = self.disable_app(app_id.clone(), reason).await {
            error!(
                %app_id,
                ?disable_error,
                "Could not disable the app after its startup failed."
            );
            return Err(disable_error);
        }
        Ok(())
    }
}

/// When the cells a call creates and joins may be published as running.
#[derive(Clone, Debug)]
pub(crate) enum CellPublication {
    /// Always: the caller owns the app's lifecycle for the whole call, as
    /// enabling an app or a clone cell does.
    Always,
    /// Only if the app is still `Enabled` in the persisted state just before
    /// publishing: conductor startup, where the admin interface may disable
    /// or uninstall the app while its attempt is under way.
    WhileAppEnabled(InstalledAppId),
}

/// Run app startup attempts, at most [`APP_STARTUP_CONCURRENCY`] at a time,
/// until every one of them has finished.
///
/// A failed attempt is handed to `record_failure` inside its own slot, so the
/// next app does not start until that failure is recorded. No attempt is
/// cancelled because another one failed. If recording a failure fails, the
/// first such error is returned once every attempt has finished.
pub(super) async fn run_app_startup_attempts<Attempt, Record, Recorded>(
    attempts: impl IntoIterator<Item = (InstalledAppId, Attempt)>,
    record_failure: Record,
) -> ConductorResult<()>
where
    Attempt: Future<Output = ConductorResult<()>>,
    Record: Fn(InstalledAppId, ConductorError) -> Recorded,
    Recorded: Future<Output = ConductorResult<()>>,
{
    let record_failure = &record_failure;
    let mut outcomes = futures::stream::iter(attempts)
        .map(|(app_id, attempt)| async move {
            match attempt.await {
                Ok(()) => Ok(()),
                Err(error) => record_failure(app_id, error).await,
            }
        })
        .buffer_unordered(APP_STARTUP_CONCURRENCY);

    let mut first_unrecorded_failure = None;
    while let Some(outcome) = outcomes.next().await {
        if let Err(error) = outcome {
            first_unrecorded_failure.get_or_insert(error);
        }
    }
    first_unrecorded_failure.map_or(Ok(()), Err)
}

/// The P2P overrides each DNA joins the network with, settled for a whole set
/// of apps before any of them starts.
///
/// A DNA's network space takes its configuration from the first join that
/// creates it, so two apps that run the same DNA with different overrides
/// cannot both be honoured. The check made as each cell is created only sees
/// cells that are already running, and apps that start side by side are not
/// running yet. So the set is checked up front, in the conductor's app order,
/// and an app that disagrees with an earlier one is refused.
#[derive(Default)]
pub(super) struct P2pOverrideReservations {
    by_dna: HashMap<DnaHash, P2pOverrideReservation>,
}

/// The overrides a DNA is reserved for, and the cell that reserved it.
struct P2pOverrideReservation {
    overrides: CellConfigOverrides,
    app_id: InstalledAppId,
    cell_id: CellId,
}

impl P2pOverrideReservations {
    /// Reserve every DNA of `app`'s enabled cells for the app's P2P overrides:
    /// all of them, or — if any is already reserved for different overrides —
    /// none.
    pub(super) fn reserve(&mut self, app: &InstalledApp) -> Result<(), CellError> {
        let overrides = Conductor::p2p_config_overrides(&app.manifest).unwrap_or_default();
        let cell_ids: Vec<CellId> = app.all_enabled_cells().collect();

        let conflict = cell_ids.iter().find_map(|cell_id| {
            self.by_dna
                .get(cell_id.dna_hash())
                .filter(|reserved| reserved.overrides != overrides)
                .map(|reserved| (cell_id, reserved))
        });
        if let Some((cell_id, reserved)) = conflict {
            return Err(CellError::P2pConfigOverridesConflict {
                app_id: Some(Box::new(app.id().clone())),
                cell_id: cell_id.clone(),
                conflicting_app_id: Some(Box::new(reserved.app_id.clone())),
                conflicting_cell_id: reserved.cell_id.clone(),
            });
        }

        for cell_id in cell_ids {
            self.by_dna
                .entry(cell_id.dna_hash().clone())
                .or_insert_with(|| P2pOverrideReservation {
                    overrides: overrides.clone(),
                    app_id: app.id().clone(),
                    cell_id,
                });
        }
        Ok(())
    }
}
