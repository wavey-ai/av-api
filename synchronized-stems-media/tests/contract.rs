use synchronized_stems_media::{
    open_authenticated_datagram, recover_authenticated_group, AeadOpenError,
    AuthenticatedStemSymbol, AuthoritativeStemConfig, AuthorizationMediaClass,
    AuthorizationOperation, EpochAssembler, EpochInsert, FecRecoveryError, FecStrategy,
    MissingReason, ReleaseReason, SourceStatus, StemAeadOpener, StemAuthorization,
    StemDatagramHeader, StemEncoding, StemErrorCode, StemFecRecoverer, SymbolKind,
    SST1_AEAD_TAG_BYTES, SST1_HEADER_BYTES,
};

const CONFIG_JSON: &[u8] = include_bytes!("fixtures/stem-stream-config.json");

fn config() -> AuthoritativeStemConfig {
    AuthoritativeStemConfig::from_json(CONFIG_JSON).expect("valid frozen config fixture")
}

fn authorization(
    config: &AuthoritativeStemConfig,
    operation: AuthorizationOperation,
    media_class: AuthorizationMediaClass,
    allowed_source_ids: Vec<&str>,
) -> StemAuthorization {
    StemAuthorization::new(
        config.identity().clone(),
        config.topology_generation(),
        config.binding_generation(),
        operation,
        media_class,
        allowed_source_ids.into_iter().map(str::to_string).collect(),
    )
}

#[derive(Clone, Copy)]
struct TestAead {
    accept: bool,
}

impl StemAeadOpener for TestAead {
    fn open(
        &self,
        key_epoch: u32,
        associated_data: &[u8; SST1_HEADER_BYTES],
        ciphertext: &[u8],
        tag: &[u8; SST1_AEAD_TAG_BYTES],
    ) -> Result<Vec<u8>, AeadOpenError> {
        if self.accept
            && key_epoch == 3
            && associated_data[..4] == *b"SST1"
            && tag.iter().all(|byte| *byte == 0xa5)
        {
            Ok(ciphertext.to_vec())
        } else {
            Err(AeadOpenError)
        }
    }
}

struct OrderedSourceRecoverer;

impl StemFecRecoverer for OrderedSourceRecoverer {
    fn recover(
        &self,
        strategy: FecStrategy,
        source_symbol_count: u16,
        _repair_symbol_count: u16,
        symbols: &[AuthenticatedStemSymbol],
    ) -> Result<Vec<u8>, FecRecoveryError> {
        if strategy != FecStrategy::ReedSolomon {
            return Err(FecRecoveryError);
        }
        let mut source = symbols
            .iter()
            .filter(|symbol| symbol.header().symbol_kind == SymbolKind::Source)
            .collect::<Vec<_>>();
        source.sort_by_key(|symbol| symbol.header().symbol_index);
        if source.len() != usize::from(source_symbol_count) {
            return Err(FecRecoveryError);
        }
        Ok(source[0].payload().to_vec())
    }
}

fn header(source_ref: u16, symbol_index: u16, epoch: u64, pts: u64) -> StemDatagramHeader {
    StemDatagramHeader {
        topology_generation: 11,
        binding_generation: 13,
        config_ref: 41,
        config_generation: 7,
        source_map_version: 4,
        key_epoch: 3,
        source_ref,
        symbol_kind: SymbolKind::Source,
        symbol_index,
        source_symbol_count: 8,
        repair_symbol_count: 2,
        epoch_number: epoch,
        remote_pts: pts,
        group_sequence: epoch,
        frame_samples: 240,
        encoding: StemEncoding::PcmS24le,
        payload_byte_count: 1,
        datagram_byte_count: 101,
    }
}

fn datagram(header: StemDatagramHeader, payload: &[u8], valid_tag: bool) -> Vec<u8> {
    assert_eq!(usize::from(header.payload_byte_count), payload.len());
    let mut output = header.encode().expect("valid test header").to_vec();
    output.extend_from_slice(payload);
    output.extend(std::iter::repeat_n(
        if valid_tag { 0xa5 } else { 0x5a },
        SST1_AEAD_TAG_BYTES,
    ));
    output
}

fn open_symbol(
    config: &AuthoritativeStemConfig,
    mut header: StemDatagramHeader,
    payload: &[u8],
) -> AuthenticatedStemSymbol {
    let authorization = authorization(
        config,
        AuthorizationOperation::Publish,
        AuthorizationMediaClass::Program,
        vec!["src_guitar", "src_vocal"],
    );
    header.payload_byte_count = u16::try_from(payload.len()).unwrap();
    header.datagram_byte_count =
        u16::try_from(SST1_HEADER_BYTES + payload.len() + SST1_AEAD_TAG_BYTES).unwrap();
    open_authenticated_datagram(
        &datagram(header, payload, true),
        config,
        &authorization,
        &TestAead { accept: true },
    )
    .expect("authenticated symbol")
}

fn recovered_group(
    config: &AuthoritativeStemConfig,
    source_ref: u16,
    epoch: u64,
    pts: u64,
    payload_seed: u8,
) -> synchronized_stems_media::RecoveredStemGroup {
    let symbols = (0..8)
        .map(|index| {
            let payload = vec![payload_seed.wrapping_add(u8::try_from(index).unwrap()); 720];
            open_symbol(config, header(source_ref, index, epoch, pts), &payload)
        })
        .collect::<Vec<_>>();
    recover_authenticated_group(&symbols, config, &OrderedSourceRecoverer)
        .expect("recovered stem group")
}

fn patched_config(mut patch: impl FnMut(&mut serde_json::Value)) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(CONFIG_JSON).unwrap();
    patch(&mut value);
    serde_json::to_vec(&value).unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid hex"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

#[test]
fn config_fixture_is_authoritative_and_round_trips_without_null_optionals() {
    let config = config();
    assert_eq!(config.identity().session_id(), "ses_demo");
    assert_eq!(config.source_map_version(), 4);
    assert_eq!(config.sources().len(), 2);
    assert_eq!(config.sources()[0].source_id(), "src_vocal");
    assert_eq!(config.sources()[1].source_ref(), 2);
    assert_eq!(config.expected_sources().len(), 2);

    let canonical = config.to_canonical_json().unwrap();
    assert!(!canonical.windows(5).any(|window| window == b":null"));
    let reparsed = AuthoritativeStemConfig::from_json(&canonical).unwrap();
    assert_eq!(reparsed, config);

    let unknown = patched_config(|value| value["unexpected"] = serde_json::json!(true));
    assert_eq!(
        AuthoritativeStemConfig::from_json(&unknown)
            .unwrap_err()
            .code(),
        StemErrorCode::InvalidConfig
    );
    let wrong_identity = patched_config(|value| {
        value["sourceMap"]["identity"]["sessionId"] = serde_json::json!("ses_other");
    });
    assert_eq!(
        AuthoritativeStemConfig::from_json(&wrong_identity)
            .unwrap_err()
            .code(),
        StemErrorCode::InvalidConfig
    );
}

#[test]
fn sst1_header_matches_the_frozen_84_byte_big_endian_vector() {
    let expected = decode_hex(
        "5353543101000100000000000000000b000000000000000d0000002900000000000000070000000400000003000100000008000200000000000000640000000000005dc00000000000000064000000f002d00334",
    );
    assert_eq!(expected.len(), SST1_HEADER_BYTES);
    let decoded = StemDatagramHeader::decode(&expected).unwrap();
    assert_eq!(decoded.topology_generation, 11);
    assert_eq!(decoded.binding_generation, 13);
    assert_eq!(decoded.config_ref, 41);
    assert_eq!(decoded.source_ref, 1);
    assert_eq!(decoded.epoch_number, 100);
    assert_eq!(decoded.remote_pts, 24_000);
    assert_eq!(decoded.payload_byte_count, 720);
    assert_eq!(decoded.datagram_byte_count, 820);
    assert_eq!(decoded.encode().unwrap().as_slice(), expected);
}

#[test]
#[allow(clippy::too_many_lines)]
fn exact_generation_geometry_fec_and_mtu_mismatches_are_closed() {
    let config = config();
    let authorization = authorization(
        &config,
        AuthorizationOperation::Publish,
        AuthorizationMediaClass::Program,
        vec!["src_guitar", "src_vocal"],
    );
    let open = |header: StemDatagramHeader, payload: Vec<u8>| {
        open_authenticated_datagram(
            &datagram(header, &payload, true),
            &config,
            &authorization,
            &TestAead { accept: true },
        )
        .map(|_| ())
        .map_err(|error| error.code())
    };
    let base = header(1, 0, 100, 24_000);
    for (mut candidate, expected) in [
        (
            {
                let mut h = base;
                h.topology_generation = 10;
                h
            },
            StemErrorCode::TopologyGenerationMismatch,
        ),
        (
            {
                let mut h = base;
                h.binding_generation = 12;
                h
            },
            StemErrorCode::BindingGenerationMismatch,
        ),
        (
            {
                let mut h = base;
                h.config_ref = 42;
                h
            },
            StemErrorCode::ConfigRefMismatch,
        ),
        (
            {
                let mut h = base;
                h.config_generation = 8;
                h
            },
            StemErrorCode::ConfigGenerationMismatch,
        ),
        (
            {
                let mut h = base;
                h.source_map_version = 5;
                h
            },
            StemErrorCode::SourceMapVersionMismatch,
        ),
        (
            {
                let mut h = base;
                h.key_epoch = 4;
                h
            },
            StemErrorCode::KeyEpochMismatch,
        ),
        (
            {
                let mut h = base;
                h.source_ref = 3;
                h
            },
            StemErrorCode::UnknownSourceRef,
        ),
        (
            {
                let mut h = base;
                h.epoch_number = 99;
                h
            },
            StemErrorCode::ConfigNotEffective,
        ),
        (
            {
                let mut h = base;
                h.frame_samples = 480;
                h
            },
            StemErrorCode::FrameGeometryMismatch,
        ),
        (
            {
                let mut h = base;
                h.encoding = StemEncoding::Opus;
                h
            },
            StemErrorCode::EncodingMismatch,
        ),
        (
            {
                let mut h = base;
                h.source_symbol_count = 9;
                h
            },
            StemErrorCode::FecPolicyMismatch,
        ),
        (
            {
                let mut h = base;
                h.symbol_index = 8;
                h
            },
            StemErrorCode::SourceSymbolOutOfRange,
        ),
        (
            {
                let mut h = base;
                h.symbol_kind = SymbolKind::Repair;
                h.symbol_index = 10;
                h
            },
            StemErrorCode::RepairSymbolOutOfRange,
        ),
    ] {
        candidate.datagram_byte_count = 101;
        assert_eq!(open(candidate, vec![0]), Err(expected));
    }

    let mut over_mtu = base;
    over_mtu.payload_byte_count = 1_101;
    over_mtu.datagram_byte_count = 1_201;
    assert_eq!(
        open(over_mtu, vec![0; 1_101]),
        Err(StemErrorCode::CarrierMtuExceeded)
    );

    let mut wrong_size = datagram(base, &[0], true);
    wrong_size.push(0);
    assert_eq!(
        open_authenticated_datagram(
            &wrong_size,
            &config,
            &authorization,
            &TestAead { accept: true }
        )
        .unwrap_err()
        .code(),
        StemErrorCode::DatagramSizeMismatch
    );
}

#[test]
fn route_operation_media_generation_and_source_scopes_are_enforced() {
    let config = config();
    let wire = datagram(header(1, 0, 100, 24_000), &[7], true);
    let attempt = |authorization: StemAuthorization| {
        open_authenticated_datagram(&wire, &config, &authorization, &TestAead { accept: true })
            .unwrap_err()
            .code()
    };
    assert_eq!(
        attempt(authorization(
            &config,
            AuthorizationOperation::Subscribe,
            AuthorizationMediaClass::Program,
            vec!["src_guitar", "src_vocal"]
        )),
        StemErrorCode::OperationNotAuthorized
    );
    assert_eq!(
        attempt(authorization(
            &config,
            AuthorizationOperation::Publish,
            AuthorizationMediaClass::Talkback,
            vec!["src_guitar", "src_vocal"]
        )),
        StemErrorCode::MediaClassNotAuthorized
    );
    assert_eq!(
        attempt(authorization(
            &config,
            AuthorizationOperation::Publish,
            AuthorizationMediaClass::Program,
            vec!["src_guitar"]
        )),
        StemErrorCode::SourceNotAuthorized
    );
    assert_eq!(
        attempt(authorization(
            &config,
            AuthorizationOperation::Publish,
            AuthorizationMediaClass::Program,
            vec!["src_vocal", "src_guitar"]
        )),
        StemErrorCode::NonCanonicalSourceScope
    );

    let mut stale_topology = authorization(
        &config,
        AuthorizationOperation::Publish,
        AuthorizationMediaClass::Program,
        vec!["src_guitar", "src_vocal"],
    );
    let other_config = AuthoritativeStemConfig::from_json(&patched_config(|value| {
        value["topologyGeneration"] = serde_json::json!(10);
    }))
    .unwrap();
    stale_topology = StemAuthorization::new(
        stale_topology_identity(&stale_topology, &config),
        other_config.topology_generation(),
        config.binding_generation(),
        AuthorizationOperation::Publish,
        AuthorizationMediaClass::Program,
        vec!["src_guitar".to_string(), "src_vocal".to_string()],
    );
    assert_eq!(
        attempt(stale_topology),
        StemErrorCode::TopologyAuthorizationMismatch
    );

    let other_identity = AuthoritativeStemConfig::from_json(&patched_config(|value| {
        value["identity"]["sessionId"] = serde_json::json!("ses_other");
        value["sourceMap"]["identity"]["sessionId"] = serde_json::json!("ses_other");
    }))
    .unwrap();
    let wrong_route = StemAuthorization::new(
        other_identity.identity().clone(),
        config.topology_generation(),
        config.binding_generation(),
        AuthorizationOperation::Publish,
        AuthorizationMediaClass::Program,
        vec!["src_guitar".to_string(), "src_vocal".to_string()],
    );
    assert_eq!(attempt(wrong_route), StemErrorCode::RouteIdentityMismatch);
}

fn stale_topology_identity(
    _authorization: &StemAuthorization,
    config: &AuthoritativeStemConfig,
) -> synchronized_stems_media::CompositeIdentity {
    config.identity().clone()
}

#[test]
fn payload_never_becomes_authenticated_when_the_tag_fails() {
    let config = config();
    let authorization = authorization(
        &config,
        AuthorizationOperation::Publish,
        AuthorizationMediaClass::Program,
        vec!["src_guitar", "src_vocal"],
    );
    let error = open_authenticated_datagram(
        &datagram(header(1, 0, 100, 24_000), &[42], false),
        &config,
        &authorization,
        &TestAead { accept: true },
    )
    .unwrap_err();
    assert_eq!(error.code(), StemErrorCode::AuthenticationFailed);
}

#[test]
fn authenticated_symbols_must_form_one_group_before_fec_recovery() {
    let config = config();
    let symbols = (0..8)
        .map(|index| {
            open_symbol(
                &config,
                header(1, index, 100, 24_000),
                &vec![u8::try_from(index).unwrap(); 720],
            )
        })
        .collect::<Vec<_>>();
    let recovered =
        recover_authenticated_group(&symbols, &config, &OrderedSourceRecoverer).unwrap();
    assert_eq!(recovered.source_id(), "src_vocal");
    assert_eq!(recovered.payload(), &[0; 720]);

    let mut mixed = symbols.clone();
    mixed[7] = open_symbol(&config, header(2, 7, 100, 24_000), &[7; 720]);
    assert_eq!(
        recover_authenticated_group(&mixed, &config, &OrderedSourceRecoverer)
            .unwrap_err()
            .code(),
        StemErrorCode::FecPolicyMismatch
    );
}

#[test]
fn complete_epoch_releases_in_source_map_order_after_reordered_arrival() {
    let config = config();
    let mut assembler = EpochAssembler::new(config.clone()).unwrap();
    let guitar = recovered_group(&config, 2, 100, 24_000, 20);
    let vocal = recovered_group(&config, 1, 100, 24_000, 10);
    assert_eq!(
        assembler.insert(guitar, 1_000_000).unwrap(),
        EpochInsert::Accepted
    );
    let EpochInsert::Released(released) = assembler.insert(vocal, 1_000_100).unwrap() else {
        panic!("complete epoch should release");
    };
    assert_eq!(released.release_reason(), ReleaseReason::Complete);
    assert!(released.is_safe_complete());
    assert_eq!(released.remote_pts(), 24_000);
    assert_eq!(released.groups()[0].source_id(), "src_vocal");
    assert_eq!(released.groups()[1].source_id(), "src_guitar");
    assert!(released
        .groups()
        .iter()
        .all(|group| group.status() == SourceStatus::Present));
}

#[test]
fn deadline_release_is_immutable_and_late_optional_source_is_discarded() {
    let config = config();
    let mut assembler = EpochAssembler::new(config.clone()).unwrap();
    let vocal = recovered_group(&config, 1, 100, 24_000, 10);
    assert_eq!(
        assembler.insert(vocal, 2_000_000).unwrap(),
        EpochInsert::Accepted
    );
    assert!(assembler.release_due(2_999_999).unwrap().is_empty());
    let released = assembler.release_due(3_000_000).unwrap();
    assert_eq!(released.len(), 1);
    assert_eq!(
        released[0].release_reason(),
        ReleaseReason::AggregationDeadline
    );
    assert_eq!(released[0].groups()[0].status(), SourceStatus::Present);
    assert_eq!(
        released[0].groups()[1].status(),
        SourceStatus::MissingOptional
    );
    assert_eq!(
        released[0].groups()[1].missing_reason(),
        Some(MissingReason::AggregationDeadline)
    );
    let guitar = recovered_group(&config, 2, 100, 24_000, 20);
    assert_eq!(
        assembler.insert(guitar, 3_000_001).unwrap(),
        EpochInsert::LateDiscarded
    );
}

#[test]
fn trusted_corruption_reason_survives_deadline_without_resetting_siblings() {
    let config = config();
    let mut assembler = EpochAssembler::new(config.clone()).unwrap();
    assembler
        .record_missing_source(100, 24_000, "src_guitar", MissingReason::Corrupt, 4_000_000)
        .unwrap();
    assembler
        .insert(recovered_group(&config, 1, 100, 24_000, 10), 4_000_100)
        .unwrap();
    let released = assembler.release_due(5_000_000).unwrap();
    assert_eq!(released[0].groups()[0].status(), SourceStatus::Present);
    assert_eq!(
        released[0].groups()[1].missing_reason(),
        Some(MissingReason::Corrupt)
    );
}

#[test]
fn duplicate_is_idempotent_but_conflicting_group_is_rejected() {
    let config = config();
    let mut assembler = EpochAssembler::new(config.clone()).unwrap();
    let first = recovered_group(&config, 1, 100, 24_000, 10);
    assert_eq!(
        assembler.insert(first.clone(), 6_000_000).unwrap(),
        EpochInsert::Accepted
    );
    assert_eq!(
        assembler.insert(first, 6_000_001).unwrap(),
        EpochInsert::DuplicateDiscarded
    );
    let conflict = recovered_group(&config, 1, 100, 24_000, 11);
    assert_eq!(
        assembler.insert(conflict, 6_000_002).unwrap_err().code(),
        StemErrorCode::DuplicateConflict
    );
}

#[test]
fn timeline_and_pending_capacity_are_bounded_before_state_growth() {
    let config = config();
    let mut assembler = EpochAssembler::with_pending_capacity(config.clone(), 1).unwrap();
    assembler
        .insert(recovered_group(&config, 1, 100, 24_000, 10), 7_000_000)
        .unwrap();
    let wrong_pts = recovered_group(&config, 1, 101, 24_241, 10);
    assert_eq!(
        assembler.insert(wrong_pts, 7_000_001).unwrap_err().code(),
        StemErrorCode::EpochGeometryMismatch
    );
    let next = recovered_group(&config, 1, 101, 24_240, 10);
    assert_eq!(
        assembler.insert(next, 7_000_002).unwrap_err().code(),
        StemErrorCode::PendingEpochCapacity
    );
    assert_eq!(assembler.pending_epoch_count(), 1);
}
