use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use simple_server::{Server, Request, Response, ResponseBuilder, ResponseResult};
use log::{info, debug};

pub struct AddressPool {
    addresses: Arc<Mutex<HashSet<Vec<u8>>>>
}

impl AddressPool {
    pub fn new() -> Self {
        let address_pool = Self {
            addresses: Arc::new(Mutex::new(Default::default()))
        };
        address_pool.spawn_server();
        address_pool
    }

    fn spawn_server(&self) {
        let addresses = self.addresses.clone();
        std::thread::spawn(move || {
            let handle_request = move |req: Request<Vec<u8>>, mut res: ResponseBuilder| {
                debug!("Incoming request: {:?}", req);

                let mut response = |code: u16, message: &[u8]| {
                    res.status(code);
                    Ok(res.body(message.to_vec())?)
                };

                if req.method() != "POST" {
                    return response(401, b"")
                }
                if req.uri().to_string() != "/addresses" {
                    return response(404, b"")
                }

                let body = req.body();
                let address = match hex::decode(body) {
                    Ok(address) => address,
                    Err(_) => return response(400, b"")
                };
                if address.len() != 32 {
                    return response(400, b"")
                }

                addresses.lock().unwrap().insert(address);

                response(200, b"")
            };

            let server = Server::new(handle_request);
            let port = "8080";
            info!("Address pool server listening on port {}", &port);
            server.listen("0.0.0.0", port);
        });
    }

    pub fn drain_addresses(&self) -> HashSet<Vec<u8>> {
        self.addresses
            .lock()
            .unwrap()
            .drain()
            .collect()
    }
}
