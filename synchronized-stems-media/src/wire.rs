use crate::config::{AuthoritativeStemConfig, FecStrategy, StemEncoding};
use crate::{positive_safe, valid_id, CompositeIdentity, Result, StemError, StemErrorCode};
use std::collections::HashSet;
use std::fmt;

pub const SST1_MAGIC: [u8; 4] = *b"SST1";
pub const SST1_HEADER_BYTES: usize = 84;
pub const SST1_AEAD_TAG_BYTES: usize = 16;
const SST1_MIN_DATAGRAM_BYTES: usize = SST1_HEADER_BYTES + SST1_AEAD_TAG_BYTES + 1;
const SST1_MAX_PAYLOAD_BYTES: usize = 1_400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolKind {
    Source,
    Repair,
}

impl SymbolKind {
    const fn code(self) -> u8 {
        match self {
            Self::Source => 0,
            Self::Repair => 1,
        }
    }

    fn from_code(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Source),
            1 => Ok(Self::Repair),
            _ => Err(StemError::new(StemErrorCode::InvalidHeader, "symbolKind")),
        }
    }
}

impl StemEncoding {
    const fn code(self) -> u8 {
        match self {
            Self::PcmS24le => 1,
            Self::FlacS24le => 2,
            Self::Opus => 3,
        }
    }

    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::PcmS24le),
            2 => Ok(Self::FlacS24le),
            3 => Ok(Self::Opus),
            _ => Err(StemError::new(StemErrorCode::InvalidHeader, "encoding")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StemDatagramHeader {
    pub topology_generation: u64,
    pub binding_generation: u64,
    pub config_ref: u32,
    pub config_generation: u64,
    pub source_map_version: u32,
    pub key_epoch: u32,
    pub source_ref: u16,
    pub symbol_kind: SymbolKind,
    pub symbol_index: u16,
    pub source_symbol_count: u16,
    pub repair_symbol_count: u16,
    pub epoch_number: u64,
    pub remote_pts: u64,
    pub group_sequence: u64,
    pub frame_samples: u32,
    pub encoding: StemEncoding,
    pub payload_byte_count: u16,
    pub datagram_byte_count: u16,
}

impl StemDatagramHeader {
    /// Decode and structurally validate the fixed `SST1` header.
    ///
    /// # Errors
    ///
    /// Returns a stable protocol error for malformed magic, fields, or lengths.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < SST1_HEADER_BYTES || input[..4] != SST1_MAGIC {
            return Err(StemError::new(StemErrorCode::InvalidHeader, "headerMagic"));
        }
        if input[4] != 1 || input[7] != 0 {
            return Err(StemError::new(
                StemErrorCode::InvalidHeader,
                "schemaVersion/reserved",
            ));
        }
        let value = Self {
            symbol_kind: SymbolKind::from_code(input[5])?,
            encoding: StemEncoding::from_code(input[6])?,
            topology_generation: read_u64(input, 8),
            binding_generation: read_u64(input, 16),
            config_ref: read_u32(input, 24),
            config_generation: read_u64(input, 28),
            source_map_version: read_u32(input, 36),
            key_epoch: read_u32(input, 40),
            source_ref: read_u16(input, 44),
            symbol_index: read_u16(input, 46),
            source_symbol_count: read_u16(input, 48),
            repair_symbol_count: read_u16(input, 50),
            epoch_number: read_u64(input, 52),
            remote_pts: read_u64(input, 60),
            group_sequence: read_u64(input, 68),
            frame_samples: read_u32(input, 76),
            payload_byte_count: read_u16(input, 80),
            datagram_byte_count: read_u16(input, 82),
        };
        value.validate_structural()?;
        Ok(value)
    }

    /// Encode this header using the frozen network-big-endian layout.
    ///
    /// # Errors
    ///
    /// Returns a stable protocol error when any field or declared length is invalid.
    pub fn encode(self) -> Result<[u8; SST1_HEADER_BYTES]> {
        self.validate_structural()?;
        let mut output = [0u8; SST1_HEADER_BYTES];
        output[..4].copy_from_slice(&SST1_MAGIC);
        output[4] = 1;
        output[5] = self.symbol_kind.code();
        output[6] = self.encoding.code();
        write_u64(&mut output, 8, self.topology_generation);
        write_u64(&mut output, 16, self.binding_generation);
        write_u32(&mut output, 24, self.config_ref);
        write_u64(&mut output, 28, self.config_generation);
        write_u32(&mut output, 36, self.source_map_version);
        write_u32(&mut output, 40, self.key_epoch);
        write_u16(&mut output, 44, self.source_ref);
        write_u16(&mut output, 46, self.symbol_index);
        write_u16(&mut output, 48, self.source_symbol_count);
        write_u16(&mut output, 50, self.repair_symbol_count);
        write_u64(&mut output, 52, self.epoch_number);
        write_u64(&mut output, 60, self.remote_pts);
        write_u64(&mut output, 68, self.group_sequence);
        write_u32(&mut output, 76, self.frame_samples);
        write_u16(&mut output, 80, self.payload_byte_count);
        write_u16(&mut output, 82, self.datagram_byte_count);
        Ok(output)
    }

    fn validate_structural(self) -> Result<()> {
        if !positive_safe(self.topology_generation)
            || !positive_safe(self.binding_generation)
            || self.config_ref == 0
            || !positive_safe(self.config_generation)
            || self.source_map_version == 0
            || self.key_epoch == 0
            || self.source_ref == 0
            || self.source_symbol_count == 0
            || !crate::safe(self.epoch_number)
            || !crate::safe(self.remote_pts)
            || !crate::safe(self.group_sequence)
            || !(1..=4_096).contains(&self.frame_samples)
            || self.payload_byte_count == 0
            || usize::from(self.payload_byte_count) > SST1_MAX_PAYLOAD_BYTES
            || usize::from(self.datagram_byte_count) < SST1_MIN_DATAGRAM_BYTES
            || usize::from(self.datagram_byte_count) > 1_500
        {
            return Err(StemError::new(StemErrorCode::InvalidHeader, "headerFields"));
        }
        let expected = SST1_HEADER_BYTES
            .checked_add(usize::from(self.payload_byte_count))
            .and_then(|value| value.checked_add(SST1_AEAD_TAG_BYTES))
            .ok_or_else(|| StemError::new(StemErrorCode::ArithmeticOverflow, "datagramSize"))?;
        if expected != usize::from(self.datagram_byte_count) {
            return Err(StemError::new(
                StemErrorCode::DatagramSizeMismatch,
                "datagramByteCount",
            ));
        }
        Ok(())
    }

    fn validate_config(self, config: &AuthoritativeStemConfig) -> Result<()> {
        if self.topology_generation != config.topology_generation() {
            return Err(StemError::new(
                StemErrorCode::TopologyGenerationMismatch,
                "topologyGeneration",
            ));
        }
        if self.binding_generation != config.binding_generation() {
            return Err(StemError::new(
                StemErrorCode::BindingGenerationMismatch,
                "bindingGeneration",
            ));
        }
        if self.config_ref != config.config_ref() {
            return Err(StemError::new(
                StemErrorCode::ConfigRefMismatch,
                "configRef",
            ));
        }
        if self.config_generation != config.config_generation() {
            return Err(StemError::new(
                StemErrorCode::ConfigGenerationMismatch,
                "configGeneration",
            ));
        }
        if u64::from(self.source_map_version) != config.source_map_version() {
            return Err(StemError::new(
                StemErrorCode::SourceMapVersionMismatch,
                "sourceMapVersion",
            ));
        }
        if self.key_epoch != config.key_epoch() {
            return Err(StemError::new(StemErrorCode::KeyEpochMismatch, "keyEpoch"));
        }
        let source = config
            .source_for_ref(self.source_ref)
            .ok_or_else(|| StemError::new(StemErrorCode::UnknownSourceRef, "sourceRef"))?;
        if !config.source_is_admitted(source.source_id()) {
            return Err(StemError::new(
                StemErrorCode::SourceNotAuthorized,
                "prioritySourceIds",
            ));
        }
        if self.epoch_number < config.effective_epoch() {
            return Err(StemError::new(
                StemErrorCode::ConfigNotEffective,
                "epochNumber",
            ));
        }
        if self.frame_samples != config.frame_samples() {
            return Err(StemError::new(
                StemErrorCode::FrameGeometryMismatch,
                "frameSamples",
            ));
        }
        if config.encoding_for_source(source.source_id()) != Some(self.encoding) {
            return Err(StemError::new(StemErrorCode::EncodingMismatch, "encoding"));
        }
        self.validate_fec(config)?;
        if self.datagram_byte_count > config.carrier().max_datagram_bytes() {
            return Err(StemError::new(
                StemErrorCode::CarrierMtuExceeded,
                "maxDatagramBytes",
            ));
        }
        Ok(())
    }

    fn validate_fec(self, config: &AuthoritativeStemConfig) -> Result<()> {
        if self.source_symbol_count != config.source_symbols()
            || self.repair_symbol_count != config.repair_symbols()
        {
            return Err(StemError::new(
                StemErrorCode::FecPolicyMismatch,
                "fecPolicy.symbols",
            ));
        }
        match config.fec_strategy() {
            FecStrategy::None => {
                if self.symbol_kind != SymbolKind::Source
                    || self.symbol_index != 0
                    || self.source_symbol_count != 1
                    || self.repair_symbol_count != 0
                {
                    return Err(StemError::new(
                        StemErrorCode::FecPolicyMismatch,
                        "fecPolicy.none",
                    ));
                }
            }
            _ => match self.symbol_kind {
                SymbolKind::Source if self.symbol_index >= self.source_symbol_count => {
                    return Err(StemError::new(
                        StemErrorCode::SourceSymbolOutOfRange,
                        "symbolIndex",
                    ));
                }
                SymbolKind::Repair => {
                    let end = self
                        .source_symbol_count
                        .checked_add(self.repair_symbol_count)
                        .ok_or_else(|| {
                            StemError::new(StemErrorCode::ArithmeticOverflow, "fecPolicy.symbols")
                        })?;
                    if self.symbol_index < self.source_symbol_count || self.symbol_index >= end {
                        return Err(StemError::new(
                            StemErrorCode::RepairSymbolOutOfRange,
                            "symbolIndex",
                        ));
                    }
                }
                SymbolKind::Source => {}
            },
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationOperation {
    Publish,
    Subscribe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationMediaClass {
    Program,
    Talkback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StemAuthorization {
    identity: CompositeIdentity,
    topology_generation: u64,
    binding_generation: u64,
    operation: AuthorizationOperation,
    media_class: AuthorizationMediaClass,
    allowed_source_ids: Vec<String>,
}

impl StemAuthorization {
    #[must_use]
    pub fn new(
        identity: CompositeIdentity,
        topology_generation: u64,
        binding_generation: u64,
        operation: AuthorizationOperation,
        media_class: AuthorizationMediaClass,
        allowed_source_ids: Vec<String>,
    ) -> Self {
        Self {
            identity,
            topology_generation,
            binding_generation,
            operation,
            media_class,
            allowed_source_ids,
        }
    }

    fn validate(
        &self,
        config: &AuthoritativeStemConfig,
        source_id: &str,
        expected_operation: AuthorizationOperation,
    ) -> Result<()> {
        if self.identity != *config.identity() {
            return Err(StemError::new(
                StemErrorCode::RouteIdentityMismatch,
                "identity",
            ));
        }
        if self.operation != expected_operation {
            return Err(StemError::new(
                StemErrorCode::OperationNotAuthorized,
                "operation",
            ));
        }
        if self.media_class != AuthorizationMediaClass::Program {
            return Err(StemError::new(
                StemErrorCode::MediaClassNotAuthorized,
                "mediaClass",
            ));
        }
        if self.topology_generation != config.topology_generation() {
            return Err(StemError::new(
                StemErrorCode::TopologyAuthorizationMismatch,
                "topologyGeneration",
            ));
        }
        if self.binding_generation != config.binding_generation() {
            return Err(StemError::new(
                StemErrorCode::BindingAuthorizationMismatch,
                "bindingGeneration",
            ));
        }
        if self.allowed_source_ids.is_empty()
            || self.allowed_source_ids.len() > 128
            || self
                .allowed_source_ids
                .iter()
                .any(|source| !valid_id(source))
            || self
                .allowed_source_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(StemError::new(
                StemErrorCode::NonCanonicalSourceScope,
                "allowedSourceIds",
            ));
        }
        if self
            .allowed_source_ids
            .iter()
            .any(|source| config.source_for_id(source).is_none())
        {
            return Err(StemError::new(
                StemErrorCode::SourceNotAuthorized,
                "allowedSourceIds",
            ));
        }
        if self
            .allowed_source_ids
            .binary_search_by(|source| source.as_str().cmp(source_id))
            .is_err()
        {
            return Err(StemError::new(
                StemErrorCode::SourceNotAuthorized,
                "sourceId",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AeadOpenError;

impl fmt::Display for AeadOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AEAD authentication failed")
    }
}

impl std::error::Error for AeadOpenError {}

/// Production adapters implement this with their session/key-epoch AEAD.
/// There is intentionally no permissive opener in this crate.
pub trait StemAeadOpener {
    /// Authenticate and decrypt one bounded symbol payload.
    ///
    /// # Errors
    ///
    /// Returns [`AeadOpenError`] when the key epoch, associated data, tag, or
    /// ciphertext cannot be authenticated and opened.
    fn open(
        &self,
        key_epoch: u32,
        associated_data: &[u8; SST1_HEADER_BYTES],
        ciphertext: &[u8],
        tag: &[u8; SST1_AEAD_TAG_BYTES],
    ) -> std::result::Result<Vec<u8>, AeadOpenError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedStemSymbol {
    header: StemDatagramHeader,
    source_id: String,
    required: bool,
    channel_count: u16,
    payload: Vec<u8>,
}

impl AuthenticatedStemSymbol {
    #[must_use]
    pub const fn header(&self) -> &StemDatagramHeader {
        &self.header
    }

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
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Parse, bind, authorize and authenticate one `SST1` symbol.
///
/// # Errors
///
/// Returns a stable closed error for any structural, config, authorization,
/// carrier, or AEAD failure. No authenticated symbol is returned on failure.
pub fn open_authenticated_datagram(
    datagram: &[u8],
    config: &AuthoritativeStemConfig,
    authorization: &StemAuthorization,
    opener: &impl StemAeadOpener,
) -> Result<AuthenticatedStemSymbol> {
    open_authenticated_datagram_for(
        datagram,
        config,
        authorization,
        AuthorizationOperation::Publish,
        opener,
    )
}

/// Parse, bind, authorize and authenticate one `SST1` symbol for an explicit
/// publish or subscribe boundary.
///
/// # Errors
///
/// Returns a stable closed error for any structural, config, authorization,
/// carrier, or AEAD failure. No authenticated symbol is returned on failure.
pub fn open_authenticated_datagram_for(
    datagram: &[u8],
    config: &AuthoritativeStemConfig,
    authorization: &StemAuthorization,
    expected_operation: AuthorizationOperation,
    opener: &impl StemAeadOpener,
) -> Result<AuthenticatedStemSymbol> {
    let header = StemDatagramHeader::decode(datagram)?;
    if datagram.len() != usize::from(header.datagram_byte_count) {
        return Err(StemError::new(
            StemErrorCode::DatagramSizeMismatch,
            "datagramByteCount",
        ));
    }
    header.validate_config(config)?;
    let source = config
        .source_for_ref(header.source_ref)
        .ok_or_else(|| StemError::new(StemErrorCode::UnknownSourceRef, "sourceRef"))?;
    authorization.validate(config, source.source_id(), expected_operation)?;

    let associated_data: &[u8; SST1_HEADER_BYTES] = datagram[..SST1_HEADER_BYTES]
        .try_into()
        .map_err(|_| StemError::new(StemErrorCode::InvalidHeader, "header"))?;
    let payload_end = SST1_HEADER_BYTES
        .checked_add(usize::from(header.payload_byte_count))
        .ok_or_else(|| StemError::new(StemErrorCode::ArithmeticOverflow, "payload"))?;
    let tag: &[u8; SST1_AEAD_TAG_BYTES] = datagram[payload_end..]
        .try_into()
        .map_err(|_| StemError::new(StemErrorCode::DatagramSizeMismatch, "aeadTag"))?;
    let payload = opener
        .open(
            header.key_epoch,
            associated_data,
            &datagram[SST1_HEADER_BYTES..payload_end],
            tag,
        )
        .map_err(|_| StemError::new(StemErrorCode::AuthenticationFailed, "aeadTag"))?;
    if payload.len() != usize::from(header.payload_byte_count) {
        return Err(StemError::new(
            StemErrorCode::AuthenticationFailed,
            "plaintextLength",
        ));
    }
    Ok(AuthenticatedStemSymbol {
        header,
        source_id: source.source_id().to_string(),
        required: source.required(),
        channel_count: source.channel_layout().channel_count(),
        payload,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FecRecoveryError;

impl fmt::Display for FecRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("stem FEC recovery failed")
    }
}

impl std::error::Error for FecRecoveryError {}

/// Strategy adapters reconstruct one complete independently decodable source
/// payload from authenticated symbols. The adapter never receives unauthenticated
/// bytes and cannot alter the frozen group identity.
pub trait StemFecRecoverer {
    /// Recover one complete source payload from already-authenticated symbols.
    ///
    /// # Errors
    ///
    /// Returns [`FecRecoveryError`] when the configured strategy cannot recover
    /// a complete independently decodable group.
    fn recover(
        &self,
        strategy: FecStrategy,
        source_symbol_count: u16,
        repair_symbol_count: u16,
        symbols: &[AuthenticatedStemSymbol],
    ) -> std::result::Result<Vec<u8>, FecRecoveryError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredStemGroup {
    header: StemDatagramHeader,
    source_id: String,
    required: bool,
    channel_count: u16,
    payload: Vec<u8>,
}

impl RecoveredStemGroup {
    #[must_use]
    pub const fn header(&self) -> &StemDatagramHeader {
        &self.header
    }

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
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Validate one exact symbol group and run its configured recovery strategy.
///
/// # Errors
///
/// Returns a closed error for mixed/duplicate/insufficient symbols, config
/// mismatch, recovery failure, or an empty/oversized recovered payload.
pub fn recover_authenticated_group(
    symbols: &[AuthenticatedStemSymbol],
    config: &AuthoritativeStemConfig,
    recoverer: &impl StemFecRecoverer,
) -> Result<RecoveredStemGroup> {
    let first = symbols
        .first()
        .ok_or_else(|| StemError::new(StemErrorCode::FecPolicyMismatch, "symbols"))?;
    first.header.validate_config(config)?;
    let mut indexes = HashSet::with_capacity(symbols.len());
    for symbol in symbols {
        symbol.header.validate_config(config)?;
        if !same_group(first, symbol) || !indexes.insert(symbol.header.symbol_index) {
            return Err(StemError::new(
                StemErrorCode::FecPolicyMismatch,
                "symbolGroup",
            ));
        }
    }
    if symbols.len() < usize::from(first.header.source_symbol_count) {
        return Err(StemError::new(
            StemErrorCode::FecPolicyMismatch,
            "sourceSymbolCount",
        ));
    }

    let payload = if config.fec_strategy() == FecStrategy::None {
        if symbols.len() != 1 || first.header.symbol_kind != SymbolKind::Source {
            return Err(StemError::new(
                StemErrorCode::FecPolicyMismatch,
                "fecPolicy.none",
            ));
        }
        first.payload.clone()
    } else {
        recoverer
            .recover(
                config.fec_strategy(),
                first.header.source_symbol_count,
                first.header.repair_symbol_count,
                symbols,
            )
            .map_err(|_| StemError::new(StemErrorCode::FecPolicyMismatch, "fecRecovery"))?
    };
    if payload.is_empty() || payload.len() > 16 * 1024 * 1024 {
        return Err(StemError::new(
            StemErrorCode::FecPolicyMismatch,
            "recoveredPayload",
        ));
    }
    if first.header.encoding == StemEncoding::PcmS24le {
        let expected_pcm_bytes = usize::try_from(first.header.frame_samples)
            .ok()
            .and_then(|frames| frames.checked_mul(usize::from(first.channel_count)))
            .and_then(|samples| samples.checked_mul(3))
            .ok_or_else(|| StemError::new(StemErrorCode::ArithmeticOverflow, "pcmPayloadLength"))?;
        if payload.len() != expected_pcm_bytes {
            return Err(StemError::new(
                StemErrorCode::FrameGeometryMismatch,
                "pcmPayloadLength",
            ));
        }
    }
    Ok(RecoveredStemGroup {
        header: first.header,
        source_id: first.source_id.clone(),
        required: first.required,
        channel_count: first.channel_count,
        payload,
    })
}

fn same_group(first: &AuthenticatedStemSymbol, candidate: &AuthenticatedStemSymbol) -> bool {
    let left = first.header;
    let right = candidate.header;
    first.source_id == candidate.source_id
        && first.required == candidate.required
        && first.channel_count == candidate.channel_count
        && left.topology_generation == right.topology_generation
        && left.binding_generation == right.binding_generation
        && left.config_ref == right.config_ref
        && left.config_generation == right.config_generation
        && left.source_map_version == right.source_map_version
        && left.key_epoch == right.key_epoch
        && left.source_ref == right.source_ref
        && left.source_symbol_count == right.source_symbol_count
        && left.repair_symbol_count == right.repair_symbol_count
        && left.epoch_number == right.epoch_number
        && left.remote_pts == right.remote_pts
        && left.group_sequence == right.group_sequence
        && left.frame_samples == right.frame_samples
        && left.encoding == right.encoding
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("fixed header slice"),
    )
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("fixed header slice"),
    )
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
