use log::info;
use nomic::utils::{poll_for_blocks, setup_test_app, setup_time_context};
use orga::abci::Node;
use serial_test::serial;
use std::sync::Once;
use std::time::Duration;
use tempfile::tempdir;

static INIT: Once = Once::new();

#[tokio::test]
#[serial]
#[ignore]
async fn node_shutdown() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        setup_time_context();
    });

    for _ in 0..5 {
        let home = tempdir().unwrap();
        let path = home.into_path();

        let node_path = path.clone();

        std::env::set_var("NOMIC_HOME_DIR", &path);

        let _ = setup_test_app(&path, 4, None, None, None);

        info!("Starting Nomic node...");
        let _child = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default())
            .await
            .run()
            .await
            .unwrap();

        poll_for_blocks().await;
    }
}
