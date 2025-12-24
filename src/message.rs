use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub enum MessageType {
    Message,
    PublicKey,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::Message => write!(f, "Message"),
            MessageType::PublicKey => write!(f, "Public key"),
        }
    }
}

#[derive(Clone)]
pub struct Message {
    sender: String,
    session_key: usize,
    receiver: String,
    message: String,
    message_type: MessageType,
    timestamp: SystemTime,
}

impl Message {
    pub(crate) fn new(
        sender: &str,
        session_key: usize,
        receiver: &str,
        message: &str,
        message_type: MessageType,
    ) -> Message {
        Message {
            sender: String::from(sender),
            session_key: session_key,
            receiver: String::from(receiver),
            message: String::from(message),
            message_type: message_type,
            timestamp: SystemTime::now(),
        }
    }

    pub fn get_sender(&self) -> &String {
        &self.sender
    }

    pub(crate) fn get_session_key(&self) -> usize {
        self.session_key
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

    pub fn get_timestamp(&self) -> SystemTime {
        self.timestamp.clone()
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sender: '{}'; receiver: '{}'; message type: '{}'; message text: '{}'; session key: '{}'; timestamp: '{:?}'",
            self.sender,
            self.receiver,
            self.message_type,
            self.message,
            self.session_key,
            self.timestamp.duration_since(UNIX_EPOCH).unwrap()
        )
    }
}
