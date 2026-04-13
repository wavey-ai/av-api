use anyhow::{bail, Context, Result};
use bytes::Bytes;
use soundkit::audio_pipeline::deserialize_audio;
use soundkit::audio_types::AudioData;
use soundkit::wav::generate_wav_buffer;
use soundkit_decoder::{DecodeOptions, DecodePipeline};

pub const PROGRAM_SAMPLE_RATE: u32 = 48_000;
pub const PROGRAM_CHANNELS: u8 = 2;
pub const PROGRAM_BITS_PER_SAMPLE: u8 = 16;

#[derive(Debug, Clone)]
pub struct UploadedAudioFile {
    pub filename: String,
    pub bytes: Bytes,
}

#[derive(Debug, Clone)]
pub struct PreparedAudioProgram {
    pub pcm_bytes: Vec<u8>,
    pub sample_rate: u32,
    pub channels: u8,
    pub bits_per_sample: u8,
    pub duration_seconds: f64,
    pub total_gap_seconds: f64,
}

pub fn prepare_audio_program(files: &[UploadedAudioFile], gap_seconds: f64) -> Result<PreparedAudioProgram> {
    if files.is_empty() {
        bail!("request did not include any audio file");
    }

    let gap_seconds = gap_seconds.max(0.0);
    let gap_frames = ((gap_seconds * PROGRAM_SAMPLE_RATE as f64).round() as usize).max(0);
    let bytes_per_frame = (PROGRAM_CHANNELS as usize) * (PROGRAM_BITS_PER_SAMPLE as usize / 8);
    let gap_bytes = vec![0u8; gap_frames * bytes_per_frame];

    let mut pcm_bytes = Vec::new();
    for (index, file) in files.iter().enumerate() {
        let decoded = decode_audio_file(file)
            .with_context(|| format!("failed to decode {:?}", file.filename))?;
        if decoded.is_empty() {
            bail!("decoded audio for {:?} was empty", file.filename);
        }

        for chunk in decoded {
            pcm_bytes.extend_from_slice(chunk.data());
        }

        if index + 1 < files.len() && !gap_bytes.is_empty() {
            pcm_bytes.extend_from_slice(&gap_bytes);
        }
    }

    let total_gap_seconds = if files.len() > 1 {
        gap_seconds * (files.len() - 1) as f64
    } else {
        0.0
    };
    let duration_seconds = pcm_duration_seconds(
        pcm_bytes.len(),
        PROGRAM_SAMPLE_RATE,
        PROGRAM_CHANNELS,
        PROGRAM_BITS_PER_SAMPLE,
    );

    Ok(PreparedAudioProgram {
        pcm_bytes,
        sample_rate: PROGRAM_SAMPLE_RATE,
        channels: PROGRAM_CHANNELS,
        bits_per_sample: PROGRAM_BITS_PER_SAMPLE,
        duration_seconds,
        total_gap_seconds,
    })
}

pub fn pcm_bytes_to_wav(
    pcm_bytes: &[u8],
    sample_rate: u32,
    channels: u8,
    bits_per_sample: u8,
) -> Result<Vec<u8>> {
    let pcm = deserialize_audio(pcm_bytes, bits_per_sample, channels)
        .map_err(|error| anyhow::anyhow!("failed to deserialize PCM: {error}"))?;
    generate_wav_buffer(&pcm, sample_rate)
        .map_err(|error| anyhow::anyhow!("failed to write WAV buffer: {error}"))
}

fn decode_audio_file(file: &UploadedAudioFile) -> Result<Vec<AudioData>> {
    let mut pipeline = DecodePipeline::spawn_with_options(DecodeOptions {
        output_bits_per_sample: Some(PROGRAM_BITS_PER_SAMPLE),
        output_sample_rate: Some(PROGRAM_SAMPLE_RATE),
        output_channels: Some(PROGRAM_CHANNELS),
    });

    pipeline
        .send(file.bytes.clone())
        .map_err(|error| anyhow::anyhow!("decoder send failed: {error}"))?;
    pipeline
        .send(Bytes::new())
        .map_err(|error| anyhow::anyhow!("decoder EOF failed: {error}"))?;

    let mut decoded = Vec::new();
    while let Some(output) = pipeline.recv() {
        let audio = output.map_err(|error| anyhow::anyhow!("decode failed: {error}"))?;
        decoded.push(audio);
    }

    Ok(decoded)
}

fn pcm_duration_seconds(bytes_len: usize, sample_rate: u32, channels: u8, bits_per_sample: u8) -> f64 {
    let bytes_per_frame = (channels as usize) * (bits_per_sample as usize / 8);
    if bytes_per_frame == 0 || sample_rate == 0 {
        return 0.0;
    }
    (bytes_len / bytes_per_frame) as f64 / sample_rate as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use soundkit::audio_types::PcmData;
    use soundkit::wav::generate_wav_buffer;

    fn stereo_wav(samples: &[i16]) -> Bytes {
        let left = samples.to_vec();
        let right = samples.to_vec();
        Bytes::from(generate_wav_buffer(&PcmData::I16(vec![left, right]), PROGRAM_SAMPLE_RATE).unwrap())
    }

    #[test]
    fn prepares_single_track_program() {
        let file = UploadedAudioFile {
            filename: "one.wav".into(),
            bytes: stereo_wav(&[0, 1000, -1000, 0]),
        };

        let program = prepare_audio_program(&[file], 0.0).unwrap();
        assert_eq!(program.sample_rate, PROGRAM_SAMPLE_RATE);
        assert_eq!(program.channels, PROGRAM_CHANNELS);
        assert_eq!(program.bits_per_sample, PROGRAM_BITS_PER_SAMPLE);
        assert!(!program.pcm_bytes.is_empty());
        assert_eq!(program.total_gap_seconds, 0.0);
    }

    #[test]
    fn inserts_gap_between_tracks() {
        let files = vec![
            UploadedAudioFile {
                filename: "one.wav".into(),
                bytes: stereo_wav(&[0, 1000]),
            },
            UploadedAudioFile {
                filename: "two.wav".into(),
                bytes: stereo_wav(&[0, -1000]),
            },
        ];

        let gap_seconds = 0.5;
        let program = prepare_audio_program(&files, gap_seconds).unwrap();
        assert!(program.total_gap_seconds >= 0.49);
        assert!(program.duration_seconds > gap_seconds);
    }
}
