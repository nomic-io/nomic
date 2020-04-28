use log::{debug, info};
use rocket::http::Status;
use rocket::State;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

pub struct AddressPool {
    addresses: Arc<Mutex<HashSet<Vec<u8>>>>,
}

#[post("/addresses/<address>")]
fn add_address(address: String, addresses: State<Arc<Mutex<HashSet<Vec<u8>>>>>) -> Status {
    debug!("Incoming request to add address: {:?}", &address);
    let address = match hex::decode(address) {
        Ok(address) => address,
        Err(_) => return Status::NotAcceptable,
    };

    if address.len() != 33 {
        return Status::NotAcceptable;
    }

    addresses.lock().unwrap().insert(address);
    Status::Ok
}

impl AddressPool {
    pub fn new() -> Self {
        let address_pool = Self {
            addresses: Arc::new(Mutex::new(Default::default())),
        };
        address_pool.spawn_server();
        address_pool
    }

    fn spawn_server(&self) {
        let addresses = self.addresses.clone();
        let port = 8880;
        info!("Address pool server listening on port {}", &port);
        std::thread::spawn(move || {
            use rocket::config::{Config, Environment};

            let config = Config::build(Environment::Production)
                .address("0.0.0.0")
                .port(port)
                .finalize()
                .unwrap();

            rocket::custom(config)
                .manage(addresses)
                .mount("/", routes![add_address])
                .launch();
        });
    }

    pub fn drain_addresses(&self) -> HashSet<Vec<u8>> {
        self.addresses.lock().unwrap().drain().collect()
    }
}
