#![doc = include_str!("../README.md")]

use std::process::{Child, Command};

/// Prepare for integration testing by starting up the processor API
fn setup() -> Child {
    Command::new("./heyering-processor-api")
        .current_dir("../target/debug")
        .spawn()
        .expect("processor API ought to start")
}

/// Clean up after running the integration test
fn teardown(api_process: &mut Child) {
    let _ = api_process.kill();
}

/// Full-flow integration test
#[test]
fn full_flow_integration_test() {
    let mut api_process = setup();

    let status = Command::new("./heyering-cli")
        .current_dir("../target/debug")
        .args([
            "--path",
            "../../heyering-integration-test/data/test_data.csv",
        ])
        .status()
        .expect("CLI app should execute successfully");

    assert!(status.success());

    teardown(&mut api_process);
}
