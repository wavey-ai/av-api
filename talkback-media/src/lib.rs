//! Transport-neutral v1 talkback media values.
//!
//! Talkback is deliberately a live monitor lane. The type does not expose a
//! conversion into a recordable frame, source object, take chunk, or archive
//! value. Carrier adapters may wrap it only in [`EphemeralTalkbackFrameV1`].

use bytes::Bytes;
use std::fmt;

pub const TALKBACK_SAMPLE_RATE: u32 = 48_000;
pub const TALKBACK_CHANNELS: u16 = 1;
pub const TALKBACK_FRAME_SAMPLES: u32 = 240;
pub const TALKBACK_MAX_PAYLOAD_BYTES: usize = 1_200;
pub const TALKBACK_MAX_LIFETIME_US: u64 = 250_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TalkbackFrameErrorCode {
    InvalidIdentifier,
    InvalidGeneration,
    InvalidFormat,
    InvalidPayload,
    InvalidDeadline,
    NotRecordable,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TalkbackFrameError {
    code: TalkbackFrameErrorCode,
    field: &'static str,
}

impl TalkbackFrameError {
    const fn new(code: TalkbackFrameErrorCode, field: &'static str) -> Self {
        Self { code, field }
    }

    #[must_use]
    pub const fn code(&self) -> TalkbackFrameErrorCode {
        self.code
    }

    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Debug for TalkbackFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TalkbackFrameError")
            .field("code", &self.code)
            .field("field", &self.field)
            .finish()
    }
}

impl fmt::Display for TalkbackFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: invalid {}", self.code, self.field)
    }
}

impl std::error::Error for TalkbackFrameError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TalkbackCodecV1 {
    Opus,
}

#[derive(Clone)]
pub struct TalkbackFrameV1Params {
    pub session_id: String,
    pub session_epoch: u64,
    pub media_authorization_epoch: u64,
    pub subject_grant_epoch: u64,
    pub talkback_epoch: u64,
    pub policy_version: u64,
    pub publisher_participant_id: String,
    pub publisher_endpoint_id: String,
    pub audience_id: String,
    pub sequence: u64,
    pub capture_pts_us: i64,
    pub codec: TalkbackCodecV1,
    pub sample_rate: u32,
    pub channels: u16,
    pub frame_samples: u32,
    pub payload: Bytes,
}

/// One capability-derived, audience-scoped microphone frame.
#[derive(Clone, Eq, PartialEq)]
pub struct TalkbackFrameV1 {
    session_id: String,
    session_epoch: u64,
    media_authorization_epoch: u64,
    subject_grant_epoch: u64,
    talkback_epoch: u64,
    policy_version: u64,
    publisher_participant_id: String,
    publisher_endpoint_id: String,
    audience_id: String,
    sequence: u64,
    capture_pts_us: i64,
    payload: Bytes,
}

impl TalkbackFrameV1 {
    pub fn new(params: TalkbackFrameV1Params) -> Result<Self, TalkbackFrameError> {
        for (field, value) in [
            ("session_id", params.session_id.as_str()),
            (
                "publisher_participant_id",
                params.publisher_participant_id.as_str(),
            ),
            (
                "publisher_endpoint_id",
                params.publisher_endpoint_id.as_str(),
            ),
            ("audience_id", params.audience_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        for (field, value) in [
            ("session_epoch", params.session_epoch),
            (
                "media_authorization_epoch",
                params.media_authorization_epoch,
            ),
            ("subject_grant_epoch", params.subject_grant_epoch),
            ("talkback_epoch", params.talkback_epoch),
            ("policy_version", params.policy_version),
        ] {
            if value == 0 {
                return Err(TalkbackFrameError::new(
                    TalkbackFrameErrorCode::InvalidGeneration,
                    field,
                ));
            }
        }
        if params.codec != TalkbackCodecV1::Opus
            || params.sample_rate != TALKBACK_SAMPLE_RATE
            || params.channels != TALKBACK_CHANNELS
            || params.frame_samples != TALKBACK_FRAME_SAMPLES
        {
            return Err(TalkbackFrameError::new(
                TalkbackFrameErrorCode::InvalidFormat,
                "audio_format",
            ));
        }
        if params.capture_pts_us < 0 {
            return Err(TalkbackFrameError::new(
                TalkbackFrameErrorCode::InvalidFormat,
                "capture_pts_us",
            ));
        }
        if params.payload.is_empty() || params.payload.len() > TALKBACK_MAX_PAYLOAD_BYTES {
            return Err(TalkbackFrameError::new(
                TalkbackFrameErrorCode::InvalidPayload,
                "payload",
            ));
        }
        Ok(Self {
            session_id: params.session_id,
            session_epoch: params.session_epoch,
            media_authorization_epoch: params.media_authorization_epoch,
            subject_grant_epoch: params.subject_grant_epoch,
            talkback_epoch: params.talkback_epoch,
            policy_version: params.policy_version,
            publisher_participant_id: params.publisher_participant_id,
            publisher_endpoint_id: params.publisher_endpoint_id,
            audience_id: params.audience_id,
            sequence: params.sequence,
            capture_pts_us: params.capture_pts_us,
            payload: params.payload,
        })
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
    pub const fn media_authorization_epoch(&self) -> u64 {
        self.media_authorization_epoch
    }

    #[must_use]
    pub const fn subject_grant_epoch(&self) -> u64 {
        self.subject_grant_epoch
    }

    #[must_use]
    pub const fn talkback_epoch(&self) -> u64 {
        self.talkback_epoch
    }

    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }

    #[must_use]
    pub fn publisher_participant_id(&self) -> &str {
        &self.publisher_participant_id
    }

    #[must_use]
    pub fn publisher_endpoint_id(&self) -> &str {
        &self.publisher_endpoint_id
    }

    #[must_use]
    pub fn audience_id(&self) -> &str {
        &self.audience_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn capture_pts_us(&self) -> i64 {
        self.capture_pts_us
    }

    #[must_use]
    pub const fn codec(&self) -> TalkbackCodecV1 {
        TalkbackCodecV1::Opus
    }

    #[must_use]
    pub const fn sample_rate(&self) -> u32 {
        TALKBACK_SAMPLE_RATE
    }

    #[must_use]
    pub const fn channels(&self) -> u16 {
        TALKBACK_CHANNELS
    }

    #[must_use]
    pub const fn frame_samples(&self) -> u32 {
        TALKBACK_FRAME_SAMPLES
    }

    #[must_use]
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }
}

impl fmt::Debug for TalkbackFrameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TalkbackFrameV1")
            .field("session_epoch", &self.session_epoch)
            .field("talkback_epoch", &self.talkback_epoch)
            .field("policy_version", &self.policy_version)
            .field("sequence", &self.sequence)
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// Carrier-local deadline wrapper. It has no retained-object representation.
#[derive(Clone, Eq, PartialEq)]
pub struct EphemeralTalkbackFrameV1 {
    frame: TalkbackFrameV1,
    accepted_at_unix_us: u64,
    deadline_unix_us: u64,
}

impl EphemeralTalkbackFrameV1 {
    pub fn new(
        frame: TalkbackFrameV1,
        accepted_at_unix_us: u64,
        deadline_unix_us: u64,
    ) -> Result<Self, TalkbackFrameError> {
        let lifetime = deadline_unix_us
            .checked_sub(accepted_at_unix_us)
            .ok_or_else(|| {
                TalkbackFrameError::new(TalkbackFrameErrorCode::InvalidDeadline, "deadline_unix_us")
            })?;
        if lifetime == 0 || lifetime > TALKBACK_MAX_LIFETIME_US {
            return Err(TalkbackFrameError::new(
                TalkbackFrameErrorCode::InvalidDeadline,
                "deadline_unix_us",
            ));
        }
        Ok(Self {
            frame,
            accepted_at_unix_us,
            deadline_unix_us,
        })
    }

    #[must_use]
    pub const fn frame(&self) -> &TalkbackFrameV1 {
        &self.frame
    }

    #[must_use]
    pub const fn accepted_at_unix_us(&self) -> u64 {
        self.accepted_at_unix_us
    }

    #[must_use]
    pub const fn deadline_unix_us(&self) -> u64 {
        self.deadline_unix_us
    }

    #[must_use]
    pub const fn is_expired(&self, now_unix_us: u64) -> bool {
        now_unix_us >= self.deadline_unix_us
    }

    #[must_use]
    pub fn into_frame(self) -> TalkbackFrameV1 {
        self.frame
    }
}

impl fmt::Debug for EphemeralTalkbackFrameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralTalkbackFrameV1")
            .field("frame", &self.frame)
            .field("accepted_at_unix_us", &self.accepted_at_unix_us)
            .field("deadline_unix_us", &self.deadline_unix_us)
            .finish()
    }
}

/// Media classes accepted by source/take recorders. Talkback has no variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordableMediaClassV1 {
    Program,
    Source,
    TakeChunk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizedMediaClassV1 {
    Program,
    Source,
    Talkback,
    Screen,
    Metadata,
    TakeChunk,
}

impl TryFrom<AuthorizedMediaClassV1> for RecordableMediaClassV1 {
    type Error = TalkbackFrameError;

    fn try_from(value: AuthorizedMediaClassV1) -> Result<Self, Self::Error> {
        match value {
            AuthorizedMediaClassV1::Program => Ok(Self::Program),
            AuthorizedMediaClassV1::Source => Ok(Self::Source),
            AuthorizedMediaClassV1::TakeChunk => Ok(Self::TakeChunk),
            AuthorizedMediaClassV1::Talkback
            | AuthorizedMediaClassV1::Screen
            | AuthorizedMediaClassV1::Metadata => Err(TalkbackFrameError::new(
                TalkbackFrameErrorCode::NotRecordable,
                "media_class",
            )),
        }
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), TalkbackFrameError> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || value.bytes().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(TalkbackFrameError::new(
            TalkbackFrameErrorCode::InvalidIdentifier,
            field,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> TalkbackFrameV1 {
        TalkbackFrameV1::new(TalkbackFrameV1Params {
            session_id: "ses_mix".into(),
            session_epoch: 9,
            media_authorization_epoch: 14,
            subject_grant_epoch: 3,
            talkback_epoch: 4,
            policy_version: 7,
            publisher_participant_id: "par_producer".into(),
            publisher_endpoint_id: "ep_logic".into(),
            audience_id: "aud_session_cue".into(),
            sequence: 1,
            capture_pts_us: 1_000_000,
            codec: TalkbackCodecV1::Opus,
            sample_rate: TALKBACK_SAMPLE_RATE,
            channels: TALKBACK_CHANNELS,
            frame_samples: TALKBACK_FRAME_SAMPLES,
            payload: Bytes::from_static(b"opus"),
        })
        .unwrap()
    }

    #[test]
    fn accepts_only_the_fixed_short_mono_opus_profile() {
        let accepted = frame();
        assert_eq!(accepted.sample_rate(), 48_000);
        assert_eq!(accepted.channels(), 1);
        assert_eq!(accepted.frame_samples(), 240);

        let mut wrong = TalkbackFrameV1Params {
            session_id: "ses_mix".into(),
            session_epoch: 9,
            media_authorization_epoch: 14,
            subject_grant_epoch: 3,
            talkback_epoch: 4,
            policy_version: 7,
            publisher_participant_id: "par_producer".into(),
            publisher_endpoint_id: "ep_logic".into(),
            audience_id: "aud_session_cue".into(),
            sequence: 1,
            capture_pts_us: 1_000_000,
            codec: TalkbackCodecV1::Opus,
            sample_rate: TALKBACK_SAMPLE_RATE,
            channels: 2,
            frame_samples: TALKBACK_FRAME_SAMPLES,
            payload: Bytes::from_static(b"opus"),
        };
        assert_eq!(
            TalkbackFrameV1::new(wrong.clone()).unwrap_err().code(),
            TalkbackFrameErrorCode::InvalidFormat
        );
        wrong.channels = 1;
        wrong.frame_samples = 960;
        assert_eq!(
            TalkbackFrameV1::new(wrong).unwrap_err().code(),
            TalkbackFrameErrorCode::InvalidFormat
        );
    }

    #[test]
    fn carrier_deadline_is_short_and_explicit() {
        let accepted = EphemeralTalkbackFrameV1::new(frame(), 1_000_000, 1_100_000).unwrap();
        assert!(!accepted.is_expired(1_099_999));
        assert!(accepted.is_expired(1_100_000));
        assert_eq!(
            EphemeralTalkbackFrameV1::new(frame(), 1_000_000, 1_500_001)
                .unwrap_err()
                .code(),
            TalkbackFrameErrorCode::InvalidDeadline
        );
    }

    #[test]
    fn recorders_have_no_talkback_admission_variant() {
        let before = b"source-artifact".to_vec();
        let mut artifact = before.clone();
        let admitted = RecordableMediaClassV1::try_from(AuthorizedMediaClassV1::Talkback);
        if admitted.is_ok() {
            artifact.extend_from_slice(frame().payload());
        }
        assert_eq!(
            admitted.unwrap_err().code(),
            TalkbackFrameErrorCode::NotRecordable
        );
        assert_eq!(artifact, before);
    }
}
