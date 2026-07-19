use crate::{invalid, positive_safe, safe, valid_id, Result, StemError};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MediaClass {
    Program,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConfigKind {
    StemStreamConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConfigDelivery {
    ReliableAuthenticatedControlStream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceMapKind {
    SynchronizedStemSourceMap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChannelLayoutKind {
    StemChannelLayout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CodecStateScope {
    PerSourcePerConfigGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PcmFormat {
    S24leInterleavedV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MissingSourcePolicy {
    ExplicitErasureAtSamePts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LateArrivalPolicy {
    DiscardAfterRelease,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositeIdentity {
    tenant_id: String,
    session_id: String,
    session_epoch: u64,
    contributor_id: String,
}

impl CompositeIdentity {
    /// Construct and validate one full contributor identity.
    ///
    /// # Errors
    ///
    /// Returns `invalid_config` for a malformed identifier or unsafe epoch.
    pub fn new(
        tenant_id: String,
        session_id: String,
        session_epoch: u64,
        contributor_id: String,
    ) -> Result<Self> {
        let value = Self {
            tenant_id,
            session_id,
            session_epoch,
            contributor_id,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn session_epoch(&self) -> u64 {
        self.session_epoch
    }

    #[must_use]
    pub fn contributor_id(&self) -> &str {
        &self.contributor_id
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !valid_id(&self.tenant_id) {
            return Err(invalid("identity.tenantId"));
        }
        if !valid_id(&self.session_id) {
            return Err(invalid("identity.sessionId"));
        }
        if !positive_safe(self.session_epoch) {
            return Err(invalid("identity.sessionEpoch"));
        }
        if !valid_id(&self.contributor_id) {
            return Err(invalid("identity.contributorId"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChannelLayoutName {
    #[serde(rename = "mono")]
    Mono,
    #[serde(rename = "stereo")]
    Stereo,
    #[serde(rename = "lcr")]
    Lcr,
    #[serde(rename = "quad")]
    Quad,
    #[serde(rename = "5.1")]
    FivePointOne,
    #[serde(rename = "7.1")]
    SevenPointOne,
    #[serde(rename = "ambisonic_acn_sn3d")]
    AmbisonicAcnSn3d,
    #[serde(rename = "discrete")]
    Discrete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelRole {
    Mono,
    FrontLeft,
    FrontRight,
    FrontCenter,
    Lfe,
    SideLeft,
    SideRight,
    RearLeft,
    RearRight,
    AmbisonicW,
    AmbisonicX,
    AmbisonicY,
    AmbisonicZ,
    Discrete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChannelDefinition {
    channel_id: String,
    order: u16,
    role: ChannelRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelLayout {
    schema_version: u8,
    kind: ChannelLayoutKind,
    layout: ChannelLayoutName,
    channel_count: u16,
    channels: Vec<ChannelDefinition>,
}

impl ChannelLayout {
    #[must_use]
    pub const fn layout(&self) -> ChannelLayoutName {
        self.layout
    }

    #[must_use]
    pub const fn channel_count(&self) -> u16 {
        self.channel_count
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.kind != ChannelLayoutKind::StemChannelLayout {
            return Err(invalid("sourceMap.sources.channelLayout.constants"));
        }
        if !(1..=128).contains(&self.channel_count)
            || usize::from(self.channel_count) != self.channels.len()
        {
            return Err(invalid("sourceMap.sources.channelLayout.channelCount"));
        }
        let expected_count = match self.layout {
            ChannelLayoutName::Mono => Some(1),
            ChannelLayoutName::Stereo => Some(2),
            ChannelLayoutName::Lcr => Some(3),
            ChannelLayoutName::Quad | ChannelLayoutName::AmbisonicAcnSn3d => Some(4),
            ChannelLayoutName::FivePointOne => Some(6),
            ChannelLayoutName::SevenPointOne => Some(8),
            ChannelLayoutName::Discrete => None,
        };
        if expected_count.is_some_and(|count| count != self.channel_count) {
            return Err(invalid("sourceMap.sources.channelLayout.layout"));
        }
        let mut ids = HashSet::with_capacity(self.channels.len());
        for (index, channel) in self.channels.iter().enumerate() {
            if !valid_id(&channel.channel_id) || !ids.insert(channel.channel_id.as_str()) {
                return Err(invalid(
                    "sourceMap.sources.channelLayout.channels.channelId",
                ));
            }
            if usize::from(channel.order) != index {
                return Err(invalid("sourceMap.sources.channelLayout.channels.order"));
            }
            if channel
                .label
                .as_ref()
                .is_some_and(|label| label.is_empty() || label.chars().count() > 80)
            {
                return Err(invalid("sourceMap.sources.channelLayout.channels.label"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceDefinition {
    source_id: String,
    source_ref: u16,
    label: String,
    order: u16,
    required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    media_class: MediaClass,
    channel_layout: ChannelLayout,
}

impl SourceDefinition {
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    #[must_use]
    pub const fn source_ref(&self) -> u16 {
        self.source_ref
    }

    #[must_use]
    pub const fn order(&self) -> u16 {
        self.order
    }

    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    #[must_use]
    pub const fn channel_layout(&self) -> &ChannelLayout {
        &self.channel_layout
    }

    fn validate(&self, expected_order: usize) -> Result<()> {
        if !valid_id(&self.source_id) || self.source_ref == 0 {
            return Err(invalid("sourceMap.sources.identity"));
        }
        if self.label.is_empty() || self.label.chars().count() > 160 {
            return Err(invalid("sourceMap.sources.label"));
        }
        if usize::from(self.order) != expected_order {
            return Err(invalid("sourceMap.sources.order"));
        }
        if self.priority.is_some_and(|priority| priority > 1_000) {
            return Err(invalid("sourceMap.sources.priority"));
        }
        if self.media_class != MediaClass::Program {
            return Err(invalid("sourceMap.sources.mediaClass"));
        }
        self.channel_layout.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceMap {
    schema_version: u8,
    kind: SourceMapKind,
    media_class: MediaClass,
    talkback_included: bool,
    identity: CompositeIdentity,
    #[serde(rename = "sourceMapVersion")]
    version: u64,
    config_generation: u64,
    effective_epoch: u64,
    source_clock_id: String,
    sample_rate: u32,
    frame_samples: u32,
    sources: Vec<SourceDefinition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepresentationMode {
    PcmS24le,
    FlacS24le,
    OpusStems,
    PriorityStems,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StemEncoding {
    PcmS24le,
    FlacS24le,
    Opus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PriorityEncoding {
    PcmS24le,
    FlacS24le,
    OpusStems,
}

impl From<PriorityEncoding> for StemEncoding {
    fn from(value: PriorityEncoding) -> Self {
        match value {
            PriorityEncoding::PcmS24le => Self::PcmS24le,
            PriorityEncoding::FlacS24le => Self::FlacS24le,
            PriorityEncoding::OpusStems => Self::Opus,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Representation {
    mode: RepresentationMode,
    sample_rate: u32,
    frame_samples: u32,
    independently_decodable_per_source: bool,
    codec_state_scope: CodecStateScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcm_format: Option<PcmFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    opus_frame_duration_microseconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority_encoding: Option<PriorityEncoding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority_source_ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LatencyPolicy {
    aggregation_deadline_microseconds: u32,
    receiver_allowance_milliseconds: u32,
    missing_source_policy: MissingSourcePolicy,
    late_arrival_policy: LateArrivalPolicy,
    released_epoch_mutable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FecStrategy {
    None,
    Duplicate,
    Xor,
    ReedSolomon,
    Raptorq,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FecPolicy {
    strategy: FecStrategy,
    same_deadline_epoch_only: bool,
    max_repair_overhead_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_symbols: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repair_symbols: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProfile {
    NativeDatagram,
    WebtransportDatagram,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CarrierProfile {
    transport_profile: TransportProfile,
    max_datagram_bytes: u16,
    fragmentation_required: bool,
}

impl CarrierProfile {
    #[must_use]
    pub const fn transport_profile(&self) -> TransportProfile {
        self.transport_profile
    }

    #[must_use]
    pub const fn max_datagram_bytes(&self) -> u16 {
        self.max_datagram_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritativeStemConfig {
    schema_version: u8,
    kind: ConfigKind,
    delivery: ConfigDelivery,
    media_class: MediaClass,
    talkback_included: bool,
    identity: CompositeIdentity,
    topology_generation: u64,
    binding_generation: u64,
    config_ref: u32,
    config_generation: u64,
    effective_epoch: u64,
    source_map: SourceMap,
    representation: Representation,
    latency_policy: LatencyPolicy,
    fec_policy: FecPolicy,
    carrier: CarrierProfile,
    key_epoch: u32,
    admission_decision_id: String,
}

impl AuthoritativeStemConfig {
    /// Parse and semantically validate one authenticated reliable-control value.
    ///
    /// # Errors
    ///
    /// Returns a closed `invalid_config` error for malformed JSON, unknown or
    /// duplicate fields, invalid bounds, or inconsistent cross-object state.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid("config.json"))?;
        value.validate()?;
        Ok(value)
    }

    /// Deterministic field-order JSON for exact reliable-control replay checks.
    ///
    /// # Errors
    ///
    /// Returns `invalid_config` if serialization unexpectedly fails.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| invalid("config.json"))
    }

    #[must_use]
    pub const fn identity(&self) -> &CompositeIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn topology_generation(&self) -> u64 {
        self.topology_generation
    }

    #[must_use]
    pub const fn binding_generation(&self) -> u64 {
        self.binding_generation
    }

    #[must_use]
    pub const fn config_ref(&self) -> u32 {
        self.config_ref
    }

    #[must_use]
    pub const fn config_generation(&self) -> u64 {
        self.config_generation
    }

    #[must_use]
    pub const fn effective_epoch(&self) -> u64 {
        self.effective_epoch
    }

    #[must_use]
    pub const fn source_map_version(&self) -> u64 {
        self.source_map.version
    }

    #[must_use]
    pub fn source_clock_id(&self) -> &str {
        &self.source_map.source_clock_id
    }

    #[must_use]
    pub const fn sample_rate(&self) -> u32 {
        self.source_map.sample_rate
    }

    #[must_use]
    pub const fn frame_samples(&self) -> u32 {
        self.source_map.frame_samples
    }

    #[must_use]
    pub const fn representation_mode(&self) -> RepresentationMode {
        self.representation.mode
    }

    #[must_use]
    pub const fn fec_strategy(&self) -> FecStrategy {
        self.fec_policy.strategy
    }

    #[must_use]
    pub const fn source_symbols(&self) -> u16 {
        match self.fec_policy.source_symbols {
            Some(value) => value,
            None => 1,
        }
    }

    #[must_use]
    pub const fn repair_symbols(&self) -> u16 {
        match self.fec_policy.repair_symbols {
            Some(value) => value,
            None => 0,
        }
    }

    #[must_use]
    pub const fn carrier(&self) -> &CarrierProfile {
        &self.carrier
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    #[must_use]
    pub const fn aggregation_deadline_microseconds(&self) -> u32 {
        self.latency_policy.aggregation_deadline_microseconds
    }

    #[must_use]
    pub fn sources(&self) -> &[SourceDefinition] {
        &self.source_map.sources
    }

    #[must_use]
    pub fn source_for_ref(&self, source_ref: u16) -> Option<&SourceDefinition> {
        self.source_map
            .sources
            .iter()
            .find(|source| source.source_ref == source_ref)
    }

    #[must_use]
    pub fn source_for_id(&self, source_id: &str) -> Option<&SourceDefinition> {
        self.source_map
            .sources
            .iter()
            .find(|source| source.source_id == source_id)
    }

    #[must_use]
    pub fn source_is_admitted(&self, source_id: &str) -> bool {
        match self.representation.mode {
            RepresentationMode::PriorityStems => self
                .representation
                .priority_source_ids
                .as_ref()
                .is_some_and(|ids| {
                    ids.binary_search_by(|id| id.as_str().cmp(source_id))
                        .is_ok()
                }),
            _ => self.source_for_id(source_id).is_some(),
        }
    }

    #[must_use]
    pub fn expected_sources(&self) -> Vec<&SourceDefinition> {
        self.source_map
            .sources
            .iter()
            .filter(|source| self.source_is_admitted(&source.source_id))
            .collect()
    }

    #[must_use]
    pub fn encoding_for_source(&self, source_id: &str) -> Option<StemEncoding> {
        if !self.source_is_admitted(source_id) {
            return None;
        }
        match self.representation.mode {
            RepresentationMode::PcmS24le => Some(StemEncoding::PcmS24le),
            RepresentationMode::FlacS24le => Some(StemEncoding::FlacS24le),
            RepresentationMode::OpusStems => Some(StemEncoding::Opus),
            RepresentationMode::PriorityStems => self
                .representation
                .priority_encoding
                .map(StemEncoding::from),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.kind != ConfigKind::StemStreamConfig
            || self.delivery != ConfigDelivery::ReliableAuthenticatedControlStream
            || self.media_class != MediaClass::Program
            || self.talkback_included
        {
            return Err(invalid("config.constants"));
        }
        self.identity.validate()?;
        if !positive_safe(self.topology_generation)
            || !positive_safe(self.binding_generation)
            || self.config_ref == 0
            || !positive_safe(self.config_generation)
            || !safe(self.effective_epoch)
            || self.key_epoch == 0
            || !valid_id(&self.admission_decision_id)
        {
            return Err(invalid("config.generations"));
        }
        self.validate_source_map()?;
        self.validate_representation()?;
        self.validate_latency()?;
        self.validate_fec()?;
        if !(576..=1_500).contains(&self.carrier.max_datagram_bytes)
            || self.carrier.fragmentation_required
        {
            return Err(invalid("carrier"));
        }
        Ok(())
    }

    fn validate_source_map(&self) -> Result<()> {
        let map = &self.source_map;
        if map.schema_version != 1
            || map.kind != SourceMapKind::SynchronizedStemSourceMap
            || map.media_class != MediaClass::Program
            || map.talkback_included
            || map.identity != self.identity
            || map.config_generation != self.config_generation
            || map.effective_epoch != self.effective_epoch
            || !positive_safe(map.version)
            || map.version > u64::from(u32::MAX)
            || !valid_id(&map.source_clock_id)
            || !(8_000..=384_000).contains(&map.sample_rate)
            || !(1..=4_096).contains(&map.frame_samples)
            || map.sources.is_empty()
            || map.sources.len() > 128
        {
            return Err(invalid("sourceMap"));
        }
        let mut ids = HashSet::with_capacity(map.sources.len());
        let mut refs = HashSet::with_capacity(map.sources.len());
        for (index, source) in map.sources.iter().enumerate() {
            source.validate(index)?;
            if !ids.insert(source.source_id.as_str()) || !refs.insert(source.source_ref) {
                return Err(invalid("sourceMap.sources.unique"));
            }
        }
        Ok(())
    }

    fn validate_representation(&self) -> Result<()> {
        let representation = &self.representation;
        if representation.sample_rate != self.source_map.sample_rate
            || representation.frame_samples != self.source_map.frame_samples
            || !representation.independently_decodable_per_source
            || representation.codec_state_scope != CodecStateScope::PerSourcePerConfigGeneration
        {
            return Err(invalid("representation.geometry"));
        }
        let valid_opus_duration = representation
            .opus_frame_duration_microseconds
            .is_some_and(|value| [2_500, 5_000, 10_000, 20_000].contains(&value));
        match representation.mode {
            RepresentationMode::PcmS24le | RepresentationMode::FlacS24le => {
                if representation.pcm_format != Some(PcmFormat::S24leInterleavedV1)
                    || representation.opus_frame_duration_microseconds.is_some()
                    || representation.priority_encoding.is_some()
                    || representation.priority_source_ids.is_some()
                {
                    return Err(invalid("representation"));
                }
            }
            RepresentationMode::OpusStems => {
                if !valid_opus_duration
                    || representation.pcm_format.is_some()
                    || representation.priority_encoding.is_some()
                    || representation.priority_source_ids.is_some()
                {
                    return Err(invalid("representation"));
                }
            }
            RepresentationMode::PriorityStems => {
                let priority_encoding = representation
                    .priority_encoding
                    .ok_or_else(|| invalid("representation.priorityEncoding"))?;
                let ids = representation
                    .priority_source_ids
                    .as_ref()
                    .ok_or_else(|| invalid("representation.prioritySourceIds"))?;
                if ids.is_empty()
                    || ids.len() > 128
                    || ids.windows(2).any(|pair| pair[0] >= pair[1])
                    || ids.iter().any(|id| self.source_for_id(id).is_none())
                {
                    return Err(invalid("representation.prioritySourceIds"));
                }
                match priority_encoding {
                    PriorityEncoding::PcmS24le | PriorityEncoding::FlacS24le => {
                        if representation.pcm_format != Some(PcmFormat::S24leInterleavedV1)
                            || representation.opus_frame_duration_microseconds.is_some()
                        {
                            return Err(invalid("representation"));
                        }
                    }
                    PriorityEncoding::OpusStems => {
                        if !valid_opus_duration || representation.pcm_format.is_some() {
                            return Err(invalid("representation"));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_latency(&self) -> Result<()> {
        let latency = &self.latency_policy;
        if !(100..=5_000).contains(&latency.aggregation_deadline_microseconds)
            || ![10, 20, 25, 75].contains(&latency.receiver_allowance_milliseconds)
            || latency.missing_source_policy != MissingSourcePolicy::ExplicitErasureAtSamePts
            || latency.late_arrival_policy != LateArrivalPolicy::DiscardAfterRelease
            || latency.released_epoch_mutable
        {
            return Err(invalid("latencyPolicy"));
        }
        Ok(())
    }

    fn validate_fec(&self) -> Result<()> {
        let fec = &self.fec_policy;
        if !fec.same_deadline_epoch_only
            || !fec.max_repair_overhead_percent.is_finite()
            || !(0.0..=100.0).contains(&fec.max_repair_overhead_percent)
        {
            return Err(invalid("fecPolicy"));
        }
        if fec.strategy == FecStrategy::None {
            if fec.source_symbols.is_some() || fec.repair_symbols.is_some() {
                return Err(invalid("fecPolicy.symbols"));
            }
        } else {
            let source = fec.source_symbols.filter(|value| *value > 0);
            let repair = fec.repair_symbols.filter(|value| *value > 0);
            let (Some(source), Some(repair)) = (source, repair) else {
                return Err(invalid("fecPolicy.symbols"));
            };
            let actual = f64::from(repair) * 100.0 / f64::from(source);
            if actual > fec.max_repair_overhead_percent + f64::EPSILON {
                return Err(invalid("fecPolicy.maxRepairOverheadPercent"));
            }
            match fec.strategy {
                FecStrategy::Duplicate if source != 1 || repair != 1 => {
                    return Err(invalid("fecPolicy.duplicateGeometry"));
                }
                FecStrategy::Xor if repair != 1 => {
                    return Err(invalid("fecPolicy.xorGeometry"));
                }
                FecStrategy::Duplicate
                | FecStrategy::Xor
                | FecStrategy::ReedSolomon
                | FecStrategy::Raptorq => {}
                FecStrategy::None => unreachable!("none handled above"),
            }
        }
        Ok(())
    }
}

impl From<serde_json::Error> for StemError {
    fn from(_: serde_json::Error) -> Self {
        invalid("config.json")
    }
}
