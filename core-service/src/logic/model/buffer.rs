//! Sequence Buffer - Buffer management for ML input
//!
//! Quản lý buffer chứa sequence vectors cho prediction.

use parking_lot::RwLock;
use crate::logic::features::FEATURE_COUNT;
use super::inference::get_sequence_length;

// ============================================================================
// STATE
// ============================================================================

/// Sequence buffer cho recent vectors
static SEQUENCE_BUFFER: RwLock<Vec<[f32; FEATURE_COUNT]>> = RwLock::new(Vec::new());

// ============================================================================
// BUFFER OPERATIONS
// ============================================================================

/// Push vector vào global buffer
pub fn push_to_buffer(features: [f32; FEATURE_COUNT]) {
    let max_len = get_sequence_length() * 2;

    let mut buffer = SEQUENCE_BUFFER.write();
    buffer.push(features);

    while buffer.len() > max_len {
        buffer.remove(0);
    }
}

/// Get recent sequence từ buffer
pub fn get_sequence_from_buffer() -> Option<Vec<[f32; FEATURE_COUNT]>> {
    let seq_len = get_sequence_length();
    let buffer = SEQUENCE_BUFFER.read();

    if buffer.len() < seq_len {
        return None;
    }

    let start = buffer.len() - seq_len;
    Some(buffer[start..].to_vec())
}

/// Check if buffer has enough data
pub fn has_enough_data() -> bool {
    let seq_len = get_sequence_length();
    SEQUENCE_BUFFER.read().len() >= seq_len
}

/// Get buffer size
pub fn buffer_size() -> usize {
    SEQUENCE_BUFFER.read().len()
}

/// Clear buffer
pub fn clear_buffer() {
    SEQUENCE_BUFFER.write().clear();
}

/// Get buffer status
pub fn get_buffer_status() -> BufferStatus {
    let buffer = SEQUENCE_BUFFER.read();
    let seq_len = get_sequence_length();

    BufferStatus {
        current_size: buffer.len(),
        required_size: seq_len,
        is_ready: buffer.len() >= seq_len,
        fill_percent: if seq_len > 0 {
            (buffer.len() as f32 / seq_len as f32 * 100.0).min(100.0)
        } else {
            0.0
        },
    }
}

/// Buffer status information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BufferStatus {
    pub current_size: usize,
    pub required_size: usize,
    pub is_ready: bool,
    pub fill_percent: f32,
}

// ============================================================================
// HIGH-LEVEL API
// ============================================================================

/// Push features and predict if ready
pub fn push_and_predict(features: [f32; FEATURE_COUNT]) -> Option<super::PredictionResult> {
    push_to_buffer(features);

    if has_enough_data() {
        let sequence = get_sequence_from_buffer()?;
        Some(super::inference::predict(&sequence))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_operations() {
        clear_buffer();

        assert_eq!(buffer_size(), 0);
        assert!(!has_enough_data());

        for _ in 0..10 {
            push_to_buffer([1.0; FEATURE_COUNT]);
        }

        assert!(buffer_size() >= 5);
    }
}
