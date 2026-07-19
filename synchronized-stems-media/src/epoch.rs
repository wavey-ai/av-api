use crate::config::{AuthoritativeStemConfig, CompositeIdentity, SourceDefinition, StemEncoding};
use crate::wire::RecoveredStemGroup;
use crate::{safe, Result, StemError, StemErrorCode};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const DEFAULT_MAX_PENDING_EPOCHS: usize = 64;
const RELEASED_WINDOW_EPOCHS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingReason {
    NotPublished,
    AggregationDeadline,
    DecodeError,
    Corrupt,
    Unauthorized,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceStatus {
    Present,
    MissingRequired,
    MissingOptional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseReason {
    Complete,
    AggregationDeadline,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedGroup {
    source_id: String,
    required: bool,
    channel_count: u16,
    status: SourceStatus,
    encoding: Option<StemEncoding>,
    group_sequence: Option<u64>,
    payload: Option<Vec<u8>>,
    missing_reason: Option<MissingReason>,
}

impl ReleasedGroup {
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    #[must_use]
    pub const fn channel_count(&self) -> u16 {
        self.channel_count
    }

    #[must_use]
    pub const fn status(&self) -> SourceStatus {
        self.status
    }

    #[must_use]
    pub const fn encoding(&self) -> Option<StemEncoding> {
        self.encoding
    }

    #[must_use]
    pub const fn group_sequence(&self) -> Option<u64> {
        self.group_sequence
    }

    #[must_use]
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    #[must_use]
    pub const fn missing_reason(&self) -> Option<MissingReason> {
        self.missing_reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedEpoch {
    identity: CompositeIdentity,
    config_generation: u64,
    source_map_version: u64,
    key_epoch: u32,
    source_clock_id: String,
    epoch_number: u64,
    remote_pts: u64,
    frame_samples: u32,
    groups: Vec<ReleasedGroup>,
    release_reason: ReleaseReason,
    released_at_host_time_nanoseconds: u64,
}

impl ReleasedEpoch {
    #[must_use]
    pub const fn identity(&self) -> &CompositeIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn config_generation(&self) -> u64 {
        self.config_generation
    }

    #[must_use]
    pub const fn source_map_version(&self) -> u64 {
        self.source_map_version
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    #[must_use]
    pub fn source_clock_id(&self) -> &str {
        &self.source_clock_id
    }

    #[must_use]
    pub const fn epoch_number(&self) -> u64 {
        self.epoch_number
    }

    #[must_use]
    pub const fn remote_pts(&self) -> u64 {
        self.remote_pts
    }

    #[must_use]
    pub const fn frame_samples(&self) -> u32 {
        self.frame_samples
    }

    #[must_use]
    pub fn groups(&self) -> &[ReleasedGroup] {
        &self.groups
    }

    #[must_use]
    pub const fn release_reason(&self) -> ReleaseReason {
        self.release_reason
    }

    #[must_use]
    pub const fn released_at_host_time_nanoseconds(&self) -> u64 {
        self.released_at_host_time_nanoseconds
    }

    #[must_use]
    pub fn is_safe_complete(&self) -> bool {
        self.release_reason == ReleaseReason::Complete
            && self
                .groups
                .iter()
                .all(|group| group.status == SourceStatus::Present)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EpochInsert {
    Accepted,
    DuplicateDiscarded,
    LateDiscarded,
    Released(ReleasedEpoch),
}

#[derive(Debug)]
struct PendingEpoch {
    remote_pts: u64,
    first_observed_host_time_nanoseconds: u64,
    groups: BTreeMap<u16, RecoveredStemGroup>,
    missing_reasons: HashMap<String, MissingReason>,
}

impl PendingEpoch {
    fn new(remote_pts: u64, observed_at: u64) -> Self {
        Self {
            remote_pts,
            first_observed_host_time_nanoseconds: observed_at,
            groups: BTreeMap::new(),
            missing_reasons: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct EpochAssembler {
    config: AuthoritativeStemConfig,
    pending: BTreeMap<u64, PendingEpoch>,
    released_recent: BTreeSet<u64>,
    next_contiguous_release: u64,
    timeline_origin: Option<(u64, u64)>,
    source_sequence_origins: HashMap<String, (u64, u64)>,
    last_host_time_nanoseconds: Option<u64>,
    max_pending_epochs: usize,
}

impl EpochAssembler {
    /// Create an assembler with the bounded default pending-epoch capacity.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied authoritative config is invalid.
    pub fn new(config: AuthoritativeStemConfig) -> Result<Self> {
        Self::with_pending_capacity(config, DEFAULT_MAX_PENDING_EPOCHS)
    }

    /// Create an assembler with an explicit bounded pending-epoch capacity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid config or a zero/oversized capacity.
    pub fn with_pending_capacity(
        config: AuthoritativeStemConfig,
        max_pending_epochs: usize,
    ) -> Result<Self> {
        config.validate()?;
        if max_pending_epochs == 0 || max_pending_epochs > 1_024 {
            return Err(StemError::new(
                StemErrorCode::PendingEpochCapacity,
                "maxPendingEpochs",
            ));
        }
        let next_contiguous_release = config.effective_epoch();
        Ok(Self {
            config,
            pending: BTreeMap::new(),
            released_recent: BTreeSet::new(),
            next_contiguous_release,
            timeline_origin: None,
            source_sequence_origins: HashMap::new(),
            last_host_time_nanoseconds: None,
            max_pending_epochs,
        })
    }

    #[must_use]
    pub fn config(&self) -> &AuthoritativeStemConfig {
        &self.config
    }

    #[must_use]
    pub fn pending_epoch_count(&self) -> usize {
        self.pending.len()
    }

    /// Insert one independently recovered and authenticated source group.
    ///
    /// # Errors
    ///
    /// Returns an error for binding/timeline conflicts, a conflicting duplicate,
    /// host-clock regression, arithmetic overflow, or pending-capacity exhaustion.
    pub fn insert(
        &mut self,
        group: RecoveredStemGroup,
        observed_at_host_time_nanoseconds: u64,
    ) -> Result<EpochInsert> {
        self.observe_host_time(observed_at_host_time_nanoseconds)?;
        let header = *group.header();
        if self.was_released(header.epoch_number) {
            return Ok(EpochInsert::LateDiscarded);
        }
        self.validate_group_binding(&group)?;
        self.validate_timeline(header.epoch_number, header.remote_pts)?;
        self.validate_source_sequence(
            group.source_id(),
            header.epoch_number,
            header.group_sequence,
        )?;
        self.ensure_pending_capacity(header.epoch_number)?;
        let pending = self.pending.entry(header.epoch_number).or_insert_with(|| {
            PendingEpoch::new(header.remote_pts, observed_at_host_time_nanoseconds)
        });
        if pending.remote_pts != header.remote_pts {
            return Err(StemError::new(
                StemErrorCode::EpochGeometryMismatch,
                "remotePts",
            ));
        }
        if let Some(existing) = pending.groups.get(&header.source_ref) {
            return if existing == &group {
                Ok(EpochInsert::DuplicateDiscarded)
            } else {
                Err(StemError::new(
                    StemErrorCode::DuplicateConflict,
                    "sourceRef",
                ))
            };
        }
        pending.missing_reasons.remove(group.source_id());
        pending.groups.insert(header.source_ref, group);
        if self.epoch_is_complete(header.epoch_number) {
            let released = self.release_epoch(
                header.epoch_number,
                ReleaseReason::Complete,
                observed_at_host_time_nanoseconds,
            )?;
            Ok(EpochInsert::Released(released))
        } else {
            Ok(EpochInsert::Accepted)
        }
    }

    /// Record a trusted post-header failure (for example AEAD corruption or a
    /// per-source decoder failure) so deadline release reports the closed cause.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown source, timeline conflict, host-clock
    /// regression, arithmetic overflow, or pending-capacity exhaustion.
    pub fn record_missing_source(
        &mut self,
        epoch_number: u64,
        remote_pts: u64,
        source_id: &str,
        reason: MissingReason,
        observed_at_host_time_nanoseconds: u64,
    ) -> Result<EpochInsert> {
        self.observe_host_time(observed_at_host_time_nanoseconds)?;
        if self.was_released(epoch_number) {
            return Ok(EpochInsert::LateDiscarded);
        }
        if !self.config.source_is_admitted(source_id) {
            return Err(StemError::new(
                StemErrorCode::SourceNotAuthorized,
                "sourceId",
            ));
        }
        self.validate_timeline(epoch_number, remote_pts)?;
        self.ensure_pending_capacity(epoch_number)?;
        let pending = self
            .pending
            .entry(epoch_number)
            .or_insert_with(|| PendingEpoch::new(remote_pts, observed_at_host_time_nanoseconds));
        if pending.remote_pts != remote_pts {
            return Err(StemError::new(
                StemErrorCode::EpochGeometryMismatch,
                "remotePts",
            ));
        }
        if !pending
            .groups
            .values()
            .any(|group| group.source_id() == source_id)
        {
            pending
                .missing_reasons
                .insert(source_id.to_string(), reason);
        }
        Ok(EpochInsert::Accepted)
    }

    /// Release every pending epoch whose immutable aggregation deadline elapsed.
    ///
    /// # Errors
    ///
    /// Returns an error for host-clock regression or arithmetic/state corruption.
    pub fn release_due(&mut self, now_host_time_nanoseconds: u64) -> Result<Vec<ReleasedEpoch>> {
        self.observe_host_time(now_host_time_nanoseconds)?;
        let deadline_ns = u64::from(self.config.aggregation_deadline_microseconds())
            .checked_mul(1_000)
            .ok_or_else(|| {
                StemError::new(StemErrorCode::ArithmeticOverflow, "aggregationDeadline")
            })?;
        let due = self
            .pending
            .iter()
            .filter_map(|(epoch, pending)| {
                pending
                    .first_observed_host_time_nanoseconds
                    .checked_add(deadline_ns)
                    .filter(|deadline| *deadline <= now_host_time_nanoseconds)
                    .map(|_| *epoch)
            })
            .collect::<Vec<_>>();
        due.into_iter()
            .map(|epoch| {
                self.release_epoch(
                    epoch,
                    ReleaseReason::AggregationDeadline,
                    now_host_time_nanoseconds,
                )
            })
            .collect()
    }

    fn validate_group_binding(&self, group: &RecoveredStemGroup) -> Result<()> {
        let header = group.header();
        let source = self
            .config
            .source_for_ref(header.source_ref)
            .ok_or_else(|| StemError::new(StemErrorCode::UnknownSourceRef, "sourceRef"))?;
        if header.topology_generation != self.config.topology_generation()
            || header.binding_generation != self.config.binding_generation()
            || header.config_ref != self.config.config_ref()
            || header.config_generation != self.config.config_generation()
            || u64::from(header.source_map_version) != self.config.source_map_version()
            || header.key_epoch != self.config.key_epoch()
            || header.frame_samples != self.config.frame_samples()
            || source.source_id() != group.source_id()
            || source.required() != group.required()
            || source.channel_layout().channel_count() != group.channel_count()
            || self.config.encoding_for_source(source.source_id()) != Some(header.encoding)
        {
            return Err(StemError::new(
                StemErrorCode::EpochGeometryMismatch,
                "groupBinding",
            ));
        }
        Ok(())
    }

    fn validate_timeline(&mut self, epoch_number: u64, remote_pts: u64) -> Result<()> {
        if epoch_number < self.config.effective_epoch() {
            return Err(StemError::new(
                StemErrorCode::ConfigNotEffective,
                "epochNumber",
            ));
        }
        let origin = *self
            .timeline_origin
            .get_or_insert((epoch_number, remote_pts));
        let epoch_delta = i128::from(epoch_number) - i128::from(origin.0);
        let expected = i128::from(origin.1)
            .checked_add(
                epoch_delta
                    .checked_mul(i128::from(self.config.frame_samples()))
                    .ok_or_else(|| {
                        StemError::new(StemErrorCode::ArithmeticOverflow, "remotePts")
                    })?,
            )
            .ok_or_else(|| StemError::new(StemErrorCode::ArithmeticOverflow, "remotePts"))?;
        if expected != i128::from(remote_pts) {
            return Err(StemError::new(
                StemErrorCode::EpochGeometryMismatch,
                "remotePts",
            ));
        }
        Ok(())
    }

    fn validate_source_sequence(
        &mut self,
        source_id: &str,
        epoch_number: u64,
        group_sequence: u64,
    ) -> Result<()> {
        let origin = *self
            .source_sequence_origins
            .entry(source_id.to_string())
            .or_insert((epoch_number, group_sequence));
        let epoch_delta = i128::from(epoch_number) - i128::from(origin.0);
        let expected = i128::from(origin.1)
            .checked_add(epoch_delta)
            .ok_or_else(|| StemError::new(StemErrorCode::ArithmeticOverflow, "groupSequence"))?;
        if expected != i128::from(group_sequence) {
            return Err(StemError::new(
                StemErrorCode::EpochGeometryMismatch,
                "groupSequence",
            ));
        }
        Ok(())
    }

    fn ensure_pending_capacity(&self, epoch_number: u64) -> Result<()> {
        if !self.pending.contains_key(&epoch_number)
            && self.pending.len() >= self.max_pending_epochs
        {
            return Err(StemError::new(
                StemErrorCode::PendingEpochCapacity,
                "pendingEpochs",
            ));
        }
        Ok(())
    }

    fn epoch_is_complete(&self, epoch_number: u64) -> bool {
        self.pending.get(&epoch_number).is_some_and(|pending| {
            self.config.expected_sources().iter().all(|source| {
                pending
                    .groups
                    .values()
                    .any(|group| group.source_id() == source.source_id())
            })
        })
    }

    fn release_epoch(
        &mut self,
        epoch_number: u64,
        release_reason: ReleaseReason,
        released_at: u64,
    ) -> Result<ReleasedEpoch> {
        if epoch_number != self.next_contiguous_release
            && !self.released_recent.contains(&epoch_number)
            && self.released_recent.len() >= RELEASED_WINDOW_EPOCHS
        {
            return Err(StemError::new(
                StemErrorCode::PendingEpochCapacity,
                "releasedEpochWindow",
            ));
        }
        let pending = self
            .pending
            .remove(&epoch_number)
            .ok_or_else(|| StemError::new(StemErrorCode::EpochGeometryMismatch, "pendingEpoch"))?;
        let groups = self
            .config
            .expected_sources()
            .into_iter()
            .map(|source| released_group(source, &pending))
            .collect::<Vec<_>>();
        if release_reason == ReleaseReason::Complete
            && groups
                .iter()
                .any(|group| group.status != SourceStatus::Present)
        {
            return Err(StemError::new(
                StemErrorCode::EpochGeometryMismatch,
                "completeRelease",
            ));
        }
        let released = ReleasedEpoch {
            identity: self.config.identity().clone(),
            config_generation: self.config.config_generation(),
            source_map_version: self.config.source_map_version(),
            key_epoch: self.config.key_epoch(),
            source_clock_id: self.config.source_clock_id().to_string(),
            epoch_number,
            remote_pts: pending.remote_pts,
            frame_samples: self.config.frame_samples(),
            groups,
            release_reason,
            released_at_host_time_nanoseconds: released_at,
        };
        self.remember_released(epoch_number);
        Ok(released)
    }

    fn remember_released(&mut self, epoch_number: u64) {
        self.released_recent.insert(epoch_number);
        while self.released_recent.remove(&self.next_contiguous_release) {
            self.next_contiguous_release = self.next_contiguous_release.saturating_add(1);
        }
    }

    fn was_released(&self, epoch_number: u64) -> bool {
        epoch_number < self.next_contiguous_release || self.released_recent.contains(&epoch_number)
    }

    fn observe_host_time(&mut self, value: u64) -> Result<()> {
        if !safe(value) {
            return Err(StemError::new(
                StemErrorCode::ClockRegression,
                "hostTimeNanoseconds",
            ));
        }
        if self
            .last_host_time_nanoseconds
            .is_some_and(|last| value < last)
        {
            return Err(StemError::new(
                StemErrorCode::ClockRegression,
                "hostTimeNanoseconds",
            ));
        }
        self.last_host_time_nanoseconds = Some(value);
        Ok(())
    }
}

fn released_group(source: &SourceDefinition, pending: &PendingEpoch) -> ReleasedGroup {
    if let Some(group) = pending
        .groups
        .values()
        .find(|group| group.source_id() == source.source_id())
    {
        ReleasedGroup {
            source_id: source.source_id().to_string(),
            required: source.required(),
            channel_count: source.channel_layout().channel_count(),
            status: SourceStatus::Present,
            encoding: Some(group.header().encoding),
            group_sequence: Some(group.header().group_sequence),
            payload: Some(group.payload().to_vec()),
            missing_reason: None,
        }
    } else {
        ReleasedGroup {
            source_id: source.source_id().to_string(),
            required: source.required(),
            channel_count: source.channel_layout().channel_count(),
            status: if source.required() {
                SourceStatus::MissingRequired
            } else {
                SourceStatus::MissingOptional
            },
            encoding: None,
            group_sequence: None,
            payload: None,
            missing_reason: Some(
                pending
                    .missing_reasons
                    .get(source.source_id())
                    .copied()
                    .unwrap_or(MissingReason::AggregationDeadline),
            ),
        }
    }
}
