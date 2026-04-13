use http::{HeaderMap, HeaderValue};
use soundkit::audio_pipeline::{audio_to_mono_f32, f32s_from_le_bytes, f32s_to_le_bytes};
use soundkit::audio_types::AudioData;
use std::sync::Arc;
use upload_response::UploadResponseService;

pub const PCM_FORMAT_HEADER: &str = "x-av-pcm-format";
pub const PCM_SAMPLE_RATE_HEADER: &str = "x-av-pcm-sample-rate";
pub const PCM_CHANNELS_HEADER: &str = "x-av-pcm-channels";
pub const PCM_BITS_PER_SAMPLE_HEADER: &str = "x-av-pcm-bits";
pub const PCM_FORMAT_F32LE_INTERLEAVED: &str = "f32le-interleaved";
pub const PCM_FORMAT_S16LE_INTERLEAVED: &str = "s16le-interleaved";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedPcmFormat {
    F32LeInterleaved,
    S16LeInterleaved,
}

impl CachedPcmFormat {
    pub fn as_header_value(self) -> &'static str {
        match self {
            Self::F32LeInterleaved => PCM_FORMAT_F32LE_INTERLEAVED,
            Self::S16LeInterleaved => PCM_FORMAT_S16LE_INTERLEAVED,
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            PCM_FORMAT_F32LE_INTERLEAVED => Ok(Self::F32LeInterleaved),
            PCM_FORMAT_S16LE_INTERLEAVED => Ok(Self::S16LeInterleaved),
            other => Err(format!("unsupported cached PCM format {other:?}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedPcmDescriptor {
    pub format: CachedPcmFormat,
    pub sample_rate: u32,
    pub channels: u8,
    pub bits_per_sample: u8,
}

impl CachedPcmDescriptor {
    pub const fn new(
        format: CachedPcmFormat,
        sample_rate: u32,
        channels: u8,
        bits_per_sample: u8,
    ) -> Self {
        Self {
            format,
            sample_rate,
            channels,
            bits_per_sample,
        }
    }
}

pub struct CachedPcmWriter {
    service: Arc<UploadResponseService>,
    stream_id: u64,
    slot_bytes: usize,
}

pub struct CachedMonoPcmWriter {
    inner: CachedPcmWriter,
}

impl CachedPcmWriter {
    pub fn new(service: Arc<UploadResponseService>, stream_id: u64, slot_bytes: usize) -> Self {
        Self {
            service,
            stream_id,
            slot_bytes: slot_bytes.max(1),
        }
    }

    pub async fn append_bytes(&self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Ok(());
        }

        for chunk in bytes.chunks(self.slot_bytes) {
            if chunk.is_empty() {
                continue;
            }
            self.service
                .append_request_body(self.stream_id, bytes::Bytes::copy_from_slice(chunk))
                .await?;
        }

        Ok(())
    }

    pub async fn append_samples(&self, samples: &[f32]) -> Result<(), String> {
        if samples.is_empty() {
            return Ok(());
        }

        let bytes = f32s_to_le_bytes(samples);
        self.append_bytes(&bytes).await
    }
}

impl CachedMonoPcmWriter {
    pub fn new(service: Arc<UploadResponseService>, stream_id: u64, slot_bytes: usize) -> Self {
        Self {
            inner: CachedPcmWriter::new(service, stream_id, slot_bytes),
        }
    }

    pub async fn append_samples(&self, samples: &[f32]) -> Result<(), String> {
        self.inner.append_samples(samples).await
    }

    pub async fn append_audio(&self, audio: &AudioData) -> Result<(), String> {
        let mono = audio_to_mono_f32(audio)?;
        self.append_samples(&mono).await
    }
}

pub fn decode_cached_f32le_chunk(chunk: &[u8]) -> Result<Vec<f32>, String> {
    f32s_from_le_bytes(chunk)
}

pub fn apply_cached_pcm_descriptor_headers(
    headers: &mut HeaderMap,
    descriptor: CachedPcmDescriptor,
) -> Result<(), String> {
    headers.insert(
        PCM_FORMAT_HEADER,
        HeaderValue::from_static(descriptor.format.as_header_value()),
    );
    headers.insert(
        PCM_SAMPLE_RATE_HEADER,
        HeaderValue::from_str(&descriptor.sample_rate.to_string())
            .map_err(|error| format!("invalid sample rate header: {error}"))?,
    );
    headers.insert(
        PCM_CHANNELS_HEADER,
        HeaderValue::from_str(&descriptor.channels.to_string())
            .map_err(|error| format!("invalid channel header: {error}"))?,
    );
    headers.insert(
        PCM_BITS_PER_SAMPLE_HEADER,
        HeaderValue::from_str(&descriptor.bits_per_sample.to_string())
            .map_err(|error| format!("invalid bits-per-sample header: {error}"))?,
    );
    Ok(())
}

pub fn cached_pcm_descriptor_from_headers(headers: &HeaderMap) -> Result<CachedPcmDescriptor, String> {
    let format = headers
        .get(PCM_FORMAT_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "missing cached PCM format header".to_string())
        .and_then(CachedPcmFormat::parse)?;
    let sample_rate = parse_u32_header(headers, PCM_SAMPLE_RATE_HEADER)?;
    let channels = parse_u8_header(headers, PCM_CHANNELS_HEADER)?;
    let bits_per_sample = parse_u8_header(headers, PCM_BITS_PER_SAMPLE_HEADER)?;
    Ok(CachedPcmDescriptor::new(
        format,
        sample_rate,
        channels,
        bits_per_sample,
    ))
}

fn parse_u32_header(headers: &HeaderMap, name: &str) -> Result<u32, String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| format!("missing header {name}"))?
        .parse::<u32>()
        .map_err(|error| format!("invalid {name} header: {error}"))
}

fn parse_u8_header(headers: &HeaderMap, name: &str) -> Result<u8, String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| format!("missing header {name}"))?
        .parse::<u8>()
        .map_err(|error| format!("invalid {name} header: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_header::{EncodingFlag, Endianness};
    use soundkit::audio_bytes::interleave_vecs_i16;
    use upload_response::UploadResponseConfig;

    #[tokio::test]
    async fn cached_writer_appends_audio_as_f32_pcm() {
        let service = Arc::new(UploadResponseService::new(UploadResponseConfig::default()));
        let stream = service.open_stream().await.unwrap();
        let stream_id = stream.stream_id();
        let writer = CachedMonoPcmWriter::new(service.clone(), stream_id, 8);

        service
            .write_request_headers(
                stream_id,
                http_pack::stream::StreamHeaders::from_request(
                    stream_id,
                    &http::Request::builder().uri("/").body(()).unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let audio = AudioData::new(
            16,
            2,
            48_000,
            interleave_vecs_i16(&[vec![32767, -32768], vec![-32768, 32767]]),
            EncodingFlag::PCMSigned,
            Endianness::LittleEndian,
        );
        writer.append_audio(&audio).await.unwrap();

        let slot = service.request_get(stream_id, 2).await.unwrap();
        let decoded = decode_cached_f32le_chunk(&slot).unwrap();
        assert!(!decoded.is_empty());
        assert!(decoded[0].abs() < 0.01);

        stream.close().await;
    }
}
