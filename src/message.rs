pub(crate) struct PublicKey {
    pub(crate) n : u128,
    pub(crate) public_exp :u128,
}

#[derive(Clone)]
pub enum MessageType {
    Message,
    PublicKey,
}

#[derive(Clone)]
pub struct Message {
    sender : String,
    receiver : String,
    message : String,
    message_type : MessageType,
}

impl Message {
    pub(crate) fn new(sender : &str, receiver : &str, message : &str, message_type : MessageType) -> Message {
        Message {
            sender : String::from(sender),
            receiver : String::from(receiver),
            message : String::from(message),
            message_type : message_type,
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

    pub fn get_message_type(&self) -> MessageType {
        self.message_type.clone()
    }
}
