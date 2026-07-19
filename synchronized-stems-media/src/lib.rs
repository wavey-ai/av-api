//! Frozen synchronized-stems v1 media semantics.
//!
//! The crate is additive to the legacy numbered multichannel path. It accepts
//! only an authoritative, semantically valid control configuration; parses the
//! exact 84-byte `SST1` header; requires an external AEAD opener before payload
//! bytes become an [`AuthenticatedStemSymbol`]; and releases immutable epochs
//! with explicit missing-source state.

mod config;
mod epoch;
mod wire;

pub use config::{
    AuthoritativeStemConfig, CarrierProfile, ChannelLayout, ChannelLayoutName, ChannelRole,
    CompositeIdentity, FecStrategy, RepresentationMode, SourceDefinition, StemEncoding,
    TransportProfile,
};
pub use epoch::{
    EpochAssembler, EpochInsert, MissingReason, ReleaseReason, ReleasedEpoch, ReleasedGroup,
    SourceStatus,
};
pub use wire::{
    open_authenticated_datagram, open_authenticated_datagram_for, recover_authenticated_group,
    AeadOpenError, AuthenticatedStemSymbol, AuthorizationMediaClass, AuthorizationOperation,
    FecRecoveryError, RecoveredStemGroup, StemAeadOpener, StemAuthorization, StemDatagramHeader,
    StemFecRecoverer, SymbolKind, SST1_AEAD_TAG_BYTES, SST1_HEADER_BYTES, SST1_MAGIC,
};

use std::fmt;

pub type Result<T> = std::result::Result<T, StemError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StemErrorCode {
    InvalidConfig,
    NonCanonicalSourceScope,
    RouteIdentityMismatch,
    OperationNotAuthorized,
    MediaClassNotAuthorized,
    SourceNotAuthorized,
    TopologyAuthorizationMismatch,
    BindingAuthorizationMismatch,
    InvalidHeader,
    TopologyGenerationMismatch,
    BindingGenerationMismatch,
    ConfigRefMismatch,
    ConfigGenerationMismatch,
    SourceMapVersionMismatch,
    KeyEpochMismatch,
    UnknownSourceRef,
    ConfigNotEffective,
    FrameGeometryMismatch,
    EncodingMismatch,
    FecPolicyMismatch,
    SourceSymbolOutOfRange,
    RepairSymbolOutOfRange,
    DatagramSizeMismatch,
    CarrierMtuExceeded,
    AuthenticationFailed,
    EpochGeometryMismatch,
    DuplicateConflict,
    LateAfterRelease,
    PendingEpochCapacity,
    ClockRegression,
    ArithmeticOverflow,
}

impl StemErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::NonCanonicalSourceScope => "noncanonical_authorization_scope",
            Self::RouteIdentityMismatch => "route_identity_mismatch",
            Self::OperationNotAuthorized => "operation_not_authorized",
            Self::MediaClassNotAuthorized => "media_class_not_authorized",
            Self::SourceNotAuthorized => "source_not_authorized",
            Self::TopologyAuthorizationMismatch => "topology_authorization_mismatch",
            Self::BindingAuthorizationMismatch => "binding_authorization_mismatch",
            Self::InvalidHeader => "invalid_header",
            Self::TopologyGenerationMismatch => "topology_generation_mismatch",
            Self::BindingGenerationMismatch => "binding_generation_mismatch",
            Self::ConfigRefMismatch => "config_ref_mismatch",
            Self::ConfigGenerationMismatch => "config_generation_mismatch",
            Self::SourceMapVersionMismatch => "source_map_version_mismatch",
            Self::KeyEpochMismatch => "key_epoch_mismatch",
            Self::UnknownSourceRef => "unknown_source_ref",
            Self::ConfigNotEffective => "config_not_effective",
            Self::FrameGeometryMismatch => "frame_geometry_mismatch",
            Self::EncodingMismatch => "encoding_mismatch",
            Self::FecPolicyMismatch => "fec_policy_mismatch",
            Self::SourceSymbolOutOfRange => "source_symbol_out_of_range",
            Self::RepairSymbolOutOfRange => "repair_symbol_out_of_range",
            Self::DatagramSizeMismatch => "datagram_size_mismatch",
            Self::CarrierMtuExceeded => "carrier_mtu_exceeded",
            Self::AuthenticationFailed => "authentication_failed",
            Self::EpochGeometryMismatch => "epoch_geometry_mismatch",
            Self::DuplicateConflict => "duplicate_conflict",
            Self::LateAfterRelease => "late_after_release",
            Self::PendingEpochCapacity => "pending_epoch_capacity",
            Self::ClockRegression => "clock_regression",
            Self::ArithmeticOverflow => "arithmetic_overflow",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StemError {
    code: StemErrorCode,
    field: &'static str,
}

impl StemError {
    #[must_use]
    pub const fn new(code: StemErrorCode, field: &'static str) -> Self {
        Self { code, field }
    }

    #[must_use]
    pub const fn code(&self) -> StemErrorCode {
        self.code
    }

    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Display for StemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.field)
    }
}

impl std::error::Error for StemError {}

fn invalid(field: &'static str) -> StemError {
    StemError::new(StemErrorCode::InvalidConfig, field)
}

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn valid_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.len() <= 128
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(byte))
}

fn positive_safe(value: u64) -> bool {
    (1..=MAX_SAFE_INTEGER).contains(&value)
}

fn safe(value: u64) -> bool {
    value <= MAX_SAFE_INTEGER
}
