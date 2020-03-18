#[post("/address", data = "<address>")]
fn add_address(address: Vec<u8>) {}

pub struct AddressPool {
    count: u32,
}

impl AddressPool {
    pub fn new() -> Self {
        Self { count: 0 }
    }
}

fn start() {
    let pool = AddressPool::new();
}
