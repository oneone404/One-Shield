use super::types::VersionedBaseline;
use super::validate::{validate_baseline, BaselineError};
use super::storage::{save_baseline, load_baseline};
use crate::logic::features::layout::{FEATURE_VERSION, layout_hash};

#[test]
fn test_baseline_creation() {
    let b = VersionedBaseline::new("test");
    assert_eq!(b.feature_version, FEATURE_VERSION);
    assert_eq!(b.layout_hash, layout_hash());
    assert_eq!(b.samples, 0);
    assert_eq!(b.mean.len(), 15);
}

#[test]
fn test_baseline_validation_success() {
    let b = VersionedBaseline::new("valid");
    assert!(validate_baseline(&b).is_ok());
}

#[test]
fn test_reject_version_mismatch() {
    let mut b = VersionedBaseline::new("invalid_version");
    b.feature_version = FEATURE_VERSION + 1; // Simulate future version

    let result = validate_baseline(&b);
    assert!(result.is_err());

    match result {
        Err(BaselineError::LayoutMismatch { expected_version, actual_version, .. }) => {
            assert_eq!(expected_version, FEATURE_VERSION);
            assert_eq!(actual_version, FEATURE_VERSION + 1);
        },
        _ => panic!("Expected LayoutMismatch error"),
    }
}

#[test]
fn test_reject_layout_hash_mismatch() {
    let mut b = VersionedBaseline::new("invalid_hash");
    b.layout_hash = !layout_hash(); // Flip bits to ensure mismatch

    let result = validate_baseline(&b);
    assert!(result.is_err());

    match result {
        Err(BaselineError::LayoutMismatch { expected_hash, actual_hash, .. }) => {
            assert_eq!(expected_hash, layout_hash());
            assert_ne!(actual_hash, layout_hash());
        },
        _ => panic!("Expected LayoutMismatch error"),
    }
}

#[test]
fn test_save_load_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("baseline.json");

    let mut original = VersionedBaseline::new("persist");
    original.samples = 100;
    original.mean[0] = 42.0;

    save_baseline(&original, &path).unwrap();

    let loaded = load_baseline(&path).unwrap();

    assert_eq!(loaded.id, original.id);
    assert_eq!(loaded.samples, 100);
    assert_eq!(loaded.mean[0], 42.0);
    assert!(validate_baseline(&loaded).is_ok());
}

#[test]
fn test_reset_stats() {
    let mut b = VersionedBaseline::new("reset_test");
    b.samples = 50;
    b.mean[0] = 10.0;
    b.feature_version = 0; // Old version

    b.reset_stats();

    assert_eq!(b.samples, 0);
    assert_eq!(b.mean[0], 0.0);
    assert_eq!(b.feature_version, FEATURE_VERSION); // Should be updated to current
    assert_eq!(b.layout_hash, layout_hash());
}
