pub struct Client {}

impl Client {
    pub fn new() -> Result<Self, ClientError> {
        Ok(Client {})
    }

    /// Get the Bitcoin headers currently used by the peg zone's on-chain SPV client.
    pub fn get_bitcoin_headers() {}
}

pub struct ClientError {}

impl ClientError {
    fn new() -> Self {
        ClientError {}
    }
}
