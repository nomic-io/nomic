use std::time::{SystemTime, UNIX_EPOCH};

pub fn time_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn sleep(seconds: u64) {
    let duration = std::time::Duration::from_secs(seconds);
    std::thread::sleep(duration);
}
