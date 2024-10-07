use chrono::{TimeZone, Utc};
use log::info;
use nomic::utils::{poll_for_blocks, set_time, setup_test_app};
use orga::abci::Node;
use orga::plugins::Time;
use serial_test::serial;
use std::sync::Once;
use tempfile::tempdir;

static INIT: Once = Once::new();

#[tokio::test]
#[serial]
#[ignore]
async fn node_shutdown() {
    INIT.call_once(|| {
        pretty_env_logger::init();
        let genesis_time = Utc.with_ymd_and_hms(2022, 10, 5, 0, 0, 0).unwrap();
        let time = Time::from_seconds(genesis_time.timestamp());
        set_time(time);
    });

    for _ in 0..5 {
        let home = tempdir().unwrap();
        let path = home.into_path();

        let node_path = path.clone();

        std::env::set_var("NOMIC_HOME_DIR", &path);

        let _ = setup_test_app(&path, 4, None, None, None, None);

        info!("Starting Nomic node...");
        let _child = Node::<nomic::app::App>::new(node_path, Some("nomic-e2e"), Default::default())
            .await
            .run()
            .await
            .unwrap();

        poll_for_blocks().await;
    }
}
