#[derive(Clone)]
pub struct Message {
    sender : String,
    receiver : String,
    message : String,
}

impl Message {
    pub(crate) fn new(sender : &str, receiver : &str, message : &str) -> Message {
        Message {
            sender : String::from(sender),
            receiver : String::from(receiver),
            message : String::from(message),
        }
    }

    pub fn get_sender(&self) -> &String {
        &self.sender
    }

    pub fn get_receiver(&self) -> &String {
        &self.receiver
    }

    pub fn get_message(&self) -> &String {
        &self.message
    }
}
