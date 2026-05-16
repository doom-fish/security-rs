#![allow(dead_code, clippy::missing_panics_doc, clippy::must_use_candidate)]
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

pub fn fixture(name: &str) -> Vec<u8> {
    fs::read(fixture_path(name)).expect("fixture should exist")
}

pub fn unique_service(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("security-rs.test.{prefix}.{}.{}", std::process::id(), nanos)
}
