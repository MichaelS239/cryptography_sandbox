//! Infrastructure for messages
//!
//! This module contains a struct for messages and a enum for message types.
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Type of the message.
///
/// A message can have two types:
/// 1. Ordinary message
/// 2. Public key
#[derive(Clone)]
pub enum MessageType {
    /// Ordinary message (it is sent only to the receiver).
    Message,
    /// Public key (it is broadcasted to all users).
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

/// Message struct.
///
/// Contains information about sender, session key, receiver, text of the message,
/// message type and timestamp.
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
            session_key,
            receiver: String::from(receiver),
            message: String::from(message),
            message_type,
            timestamp: SystemTime::now(),
        }
    }

    /// Returns the name of the sender.
    pub fn get_sender(&self) -> &String {
        &self.sender
    }

    pub(crate) fn get_session_key(&self) -> usize {
        self.session_key
    }

    /// Returns the name of the receiver.
    pub fn get_receiver(&self) -> &String {
        &self.receiver
    }

    /// Returns the text of the message.
    pub fn get_message(&self) -> &String {
        &self.message
    }

    /// Returns the message type.
    pub fn get_message_type(&self) -> MessageType {
        self.message_type.clone()
    }

    /// Returns the timestamp of the message.
    pub fn get_timestamp(&self) -> SystemTime {
        self.timestamp
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
