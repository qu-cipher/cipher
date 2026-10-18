use crate::engine::singbox::config::SingBoxConfig;
use serde_json::Value;

/// Parses a fixture into `SingBoxConfig` and back, and checks nothing was lost or added.
fn assert_round_trip(fixture: &str) {
    let expected: Value = serde_json::from_str(fixture).unwrap();
    let config: SingBoxConfig = serde_json::from_str(fixture).unwrap();
    let actual = serde_json::to_value(&config).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn vless_reality_round_trip() {
    assert_round_trip(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vless_reality.json")));
}

#[test]
fn hysteria2_round_trip() {
    assert_round_trip(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/hysteria2.json")));
}

#[test]
fn wireguard_round_trip() {
    assert_round_trip(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/wireguard.json")));
}

/// Checks the fixtures themselves are valid for the real sing-box: `cargo test -- --ignored`
#[test]
#[ignore = "needs sing-box in PATH"]
fn fixtures_pass_sing_box_check() {
    let binary = crate::engine::paths::find_binary("sing-box").expect("sing-box not installed");
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    for entry in std::fs::read_dir(fixtures).unwrap() {
        let path = entry.unwrap().path();
        if let Err(e) = crate::engine::singbox::check(&binary, &path) {
            panic!("{} rejected: {e}", path.display());
        }
    }
}
