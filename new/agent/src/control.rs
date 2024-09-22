struct Control {
    endpoint: String,
}

impl Control {
    pub fn new(endpoint: String) -> Control {
        Control { endpoint }
    }
    pub async fn connect(&self) {
        println!("Connecting to control endpoint: {}", self.endpoint);
    }
}
