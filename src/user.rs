//! User infrastructure
//!
//! A user is responsible for creating keys, creating and reading messages.
use crate::encryption_protocol::EncryptionProtocol;
use crate::message::{Message, MessageType};
use std::collections::HashMap;

/// User struct.
///
/// A user is responsible for creating keys, creating and reading messages.
/// It can create new public/private key pairs, create encrypted messages
/// using known public keys of other users. A user also maintains the buffer
/// of received messages: it can read a specific message using their own
/// private key or delete a message from the buffer.
pub struct User<T: EncryptionProtocol> {
    name: String,
    private_key_map: HashMap<usize, T::PrivateKey>,
    public_key: Option<T::PublicKey>,
    session_key: usize,
    pub(crate) public_key_cache: HashMap<String, T::PublicKey>,
    pub(crate) session_key_cache: HashMap<String, usize>,
    pub(crate) message_buffer: Vec<Message>,
}

impl<T: EncryptionProtocol> User<T> {
    pub(crate) fn new(user_name: &str) -> Self {
        Self {
            name: String::from(user_name),
            private_key_map: HashMap::new(),
            public_key: None,
            session_key: 0,
            public_key_cache: HashMap::new(),
            session_key_cache: HashMap::new(),
            message_buffer: Vec::new(),
        }
    }

    /// Returns the name of the user.
    pub fn get_name(&self) -> &String {
        &self.name
    }

    /// Returns the public key of the user.
    pub fn get_public_key(&self) -> Option<&T::PublicKey> {
        self.public_key.as_ref()
    }

    fn decrypt_message(&self, mes: Message) -> Message {
        match mes.get_message_type() {
            MessageType::Message => {
                let private_key: &T::PrivateKey =
                    self.private_key_map.get(&mes.get_session_key()).unwrap();
                let trimmed_message = mes.get_message().trim();
                let chunks = trimmed_message.split(' ');
                let mut decrypted_message: String = String::new();
                for chunk in chunks {
                    decrypted_message += &T::decrypt(chunk, private_key);
                }
                Message::new(
                    mes.get_sender(),
                    mes.get_session_key(),
                    mes.get_receiver(),
                    &decrypted_message,
                    mes.get_message_type(),
                )
            }
            MessageType::PublicKey => mes.clone(),
        }
    }

    /// Reads the last message from the buffer.
    pub fn read_last_message(&self) -> Message {
        User::<T>::decrypt_message(
            self,
            self.message_buffer[self.message_buffer.len() - 1].clone(),
        )
    }

    /// Reads the message by its index in the buffer.
    pub fn read_message(&self, index: usize) -> Message {
        User::<T>::decrypt_message(self, self.message_buffer[index].clone())
    }

    /// Reads all messages from the buffer.
    pub fn read_all_messages(&self) -> Vec<Message> {
        let mut messages: Vec<Message> = Vec::with_capacity(self.message_buffer.len());
        for message in &self.message_buffer {
            messages.push(User::<T>::decrypt_message(self, message.clone()));
        }
        messages
    }

    /// Deletes last message from the buffer.
    pub fn delete_last_message(&mut self) {
        self.message_buffer.pop();
    }

    /// Deletes the message by its index in the buffer.
    pub fn delete_message(&mut self, index: usize) {
        self.message_buffer.remove(index);
    }

    /// Deletes all messages from the buffer.
    pub fn delete_all_messages(&mut self) {
        self.message_buffer.clear();
    }

    /// Creates an encrypted message.
    ///
    /// Accepts the name of the receiver and the text of the message as parameters.
    /// If the public key of the receiver is known by the user, the message
    /// is encrypted using this key.
    pub fn create_message(&self, receiver: &str, message: &str) -> Message {
        let receiver_string: String = String::from(receiver);
        if !self.public_key_cache.contains_key(&receiver_string) {
            panic!("receiver's public key not found");
        }
        let pub_key = self.public_key_cache.get(&receiver_string).unwrap();
        let mut cur_mes = message;
        let mut encrypted_message: String = String::new();
        for _i in 0..=((message.len() - 1) / 8) {
            let split = cur_mes.split_at_checked(8);
            match split {
                Some(_) => {
                    let (head, tail) = split.unwrap();
                    cur_mes = tail;
                    encrypted_message += &(T::encrypt(head, pub_key) + " ");
                }
                None => {
                    encrypted_message += &(T::encrypt(cur_mes, pub_key) + " ");
                }
            }
        }
        Message::new(
            &self.name.clone(),
            *self.session_key_cache.get(&receiver_string).unwrap(),
            receiver,
            &encrypted_message,
            MessageType::Message,
        )
    }

    /// Creates new public/private key pair.
    ///
    /// Note that the resulting message should be broadcasted to all users
    /// through the environment in order for the user to be able to receive encrypted messages.
    pub fn create_keys(&mut self) -> Message {
        let (public_key, private_key) = T::create_keys();
        self.session_key += 1;
        self.public_key = Some(public_key);
        self.private_key_map.insert(self.session_key, private_key);
        let mes: String = T::to_string(self.public_key.as_ref().unwrap());
        Message::new(
            &self.name.clone(),
            self.session_key,
            "",
            &mes,
            MessageType::PublicKey,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::message::MessageType;
    use crate::rsa::RSA;
    use crate::user::User;

    #[test]
    fn test_create_keys() {
        let mut user: User<RSA> = User::new("Alice");
        let mes = user.create_keys();

        assert!(user.public_key.is_some());
        assert!(!user.private_key_map.is_empty());
        assert_eq!(mes.get_sender(), "Alice");
        assert_eq!(mes.get_receiver(), "");
        let is_public_key_type = match mes.get_message_type() {
            MessageType::Message => false,
            MessageType::PublicKey => true,
        };
        assert!(is_public_key_type);

        let (num, exp) = mes.get_message().split_once(' ').unwrap();
        let n: u128 = num.parse().unwrap();
        let public_exp: u128 = exp.parse().unwrap();

        assert_eq!(user.get_public_key().unwrap().n, n);
        assert_eq!(user.get_public_key().unwrap().public_exp, public_exp);
    }

    #[test]
    #[should_panic(expected = "receiver's public key not found")]
    fn test_nonexisting_receiver() {
        let user: User<RSA> = User::new("Alice");
        user.create_message("Bob", "Hello, Bob!");
    }

    #[test]
    fn test_send_to_myself() {
        let mut user: User<RSA> = User::new("Alice");
        user.create_keys();
        user.public_key_cache
            .insert("Alice".to_string(), user.public_key.clone().unwrap());
        user.session_key_cache
            .insert("Alice".to_string(), user.session_key);
        let encrypted_message = user.create_message("Alice", "Hello, me!");
        assert_eq!(encrypted_message.get_sender(), "Alice");
        assert_eq!(encrypted_message.get_receiver(), "Alice");
        assert_eq!(encrypted_message.get_session_key(), 1);
        let is_message_type = match encrypted_message.get_message_type() {
            MessageType::Message => true,
            MessageType::PublicKey => false,
        };
        assert!(is_message_type);
        let decrypted_message = user.decrypt_message(encrypted_message);
        assert_eq!(decrypted_message.get_message(), "Hello, me!");
    }

    #[test]
    fn test_change_keys() {
        let mut user: User<RSA> = User::new("Alice");
        user.create_keys();
        assert_eq!(user.session_key, 1);
        assert_eq!(user.private_key_map.len(), 1);
        assert!(user.private_key_map.contains_key(&1));
        assert!(!user.private_key_map.contains_key(&2));
        user.create_keys();
        assert_eq!(user.session_key, 2);
        assert_eq!(user.private_key_map.len(), 2);
        assert!(user.private_key_map.contains_key(&1));
        assert!(user.private_key_map.contains_key(&2));
    }

    #[test]
    fn test_send_to_myself_and_change_keys() {
        let mut user: User<RSA> = User::new("Alice");
        user.create_keys();
        user.public_key_cache
            .insert("Alice".to_string(), user.public_key.clone().unwrap());
        user.session_key_cache
            .insert("Alice".to_string(), user.session_key);
        let encrypted_message = user.create_message("Alice", "Hello, me!");

        user.create_keys();
        user.public_key_cache
            .insert("Alice".to_string(), user.public_key.clone().unwrap());
        user.session_key_cache
            .insert("Alice".to_string(), user.session_key);

        let decrypted_message = user.decrypt_message(encrypted_message);
        assert_eq!(decrypted_message.get_message(), "Hello, me!");
    }

    #[test]
    fn test_read_last_message() {
        let mut user: User<RSA> = User::new("Alice");
        user.create_keys();
        user.public_key_cache
            .insert("Alice".to_string(), user.public_key.clone().unwrap());
        user.session_key_cache
            .insert("Alice".to_string(), user.session_key);
        let encrypted_message = user.create_message("Alice", "Hello, me!");
        assert_eq!(encrypted_message.get_session_key(), 1);
        user.message_buffer.push(encrypted_message);
        let decrypted_message = user.read_last_message();
        assert_eq!(decrypted_message.get_message(), "Hello, me!");

        user.create_keys();
        user.public_key_cache
            .insert("Alice".to_string(), user.public_key.clone().unwrap());
        user.session_key_cache
            .insert("Alice".to_string(), user.session_key);
        let new_encrypted_message = user.create_message("Alice", "Hello, again!");
        assert_eq!(new_encrypted_message.get_session_key(), 2);
        user.message_buffer.push(new_encrypted_message);
        let new_decrypted_message = user.read_last_message();
        assert_eq!(new_decrypted_message.get_message(), "Hello, again!");
    }

    #[test]
    fn test_read_message() {
        let mut user: User<RSA> = User::new("Alice");
        user.create_keys();
        user.public_key_cache
            .insert("Alice".to_string(), user.public_key.clone().unwrap());
        user.session_key_cache
            .insert("Alice".to_string(), user.session_key);
        let encrypted_message = user.create_message("Alice", "Hello, me!");
        user.message_buffer.push(encrypted_message);
        let decrypted_message = user.read_message(0);
        assert_eq!(decrypted_message.get_message(), "Hello, me!");

        user.create_keys();
        user.public_key_cache
            .insert("Alice".to_string(), user.public_key.clone().unwrap());
        user.session_key_cache
            .insert("Alice".to_string(), user.session_key);
        let new_encrypted_message = user.create_message("Alice", "Hello, again!");
        user.message_buffer.push(new_encrypted_message);
        let new_decrypted_message = user.read_message(1);
        assert_eq!(new_decrypted_message.get_message(), "Hello, again!");
        let old_decrypted_message = user.read_message(0);
        assert_eq!(old_decrypted_message.get_message(), "Hello, me!");
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_read_message_out_of_bounds() {
        let mut user: User<RSA> = User::new("Alice");
        user.create_keys();
        user.public_key_cache
            .insert("Alice".to_string(), user.public_key.clone().unwrap());
        user.session_key_cache
            .insert("Alice".to_string(), user.session_key);
        let encrypted_message = user.create_message("Alice", "Hello, me!");
        user.message_buffer.push(encrypted_message);
        user.read_message(1);
    }

    fn setup() -> User<RSA> {
        let mut user: User<RSA> = User::new("Alice");
        user.create_keys();
        user.public_key_cache
            .insert("Alice".to_string(), user.public_key.clone().unwrap());
        user.session_key_cache
            .insert("Alice".to_string(), user.session_key);
        let encrypted_message = user.create_message("Alice", "Hello, me!");
        user.message_buffer.push(encrypted_message);

        user.create_keys();
        user.public_key_cache
            .insert("Alice".to_string(), user.public_key.clone().unwrap());
        user.session_key_cache
            .insert("Alice".to_string(), user.session_key);
        let new_encrypted_message = user.create_message("Alice", "Hello, again!");
        user.message_buffer.push(new_encrypted_message);

        user
    }

    #[test]
    fn test_read_all_messages() {
        let mut user: User<RSA> = setup();
        let another_encrypted_message = user.create_message("Alice", "Hello, there!");
        user.message_buffer.push(another_encrypted_message);
        let decrypted_messages = user.read_all_messages();
        assert_eq!(decrypted_messages.len(), 3);
        assert_eq!(decrypted_messages[0].get_message(), "Hello, me!");
        assert_eq!(decrypted_messages[1].get_message(), "Hello, again!");
        assert_eq!(decrypted_messages[2].get_message(), "Hello, there!");
    }

    #[test]
    fn test_delete_last_message() {
        let mut user: User<RSA> = setup();

        assert_eq!(user.message_buffer.len(), 2);
        let decrypted_message = user.read_last_message();
        assert_eq!(decrypted_message.get_message(), "Hello, again!");
        user.delete_last_message();
        assert_eq!(user.message_buffer.len(), 1);
        let old_decrypted_message = user.read_last_message();
        assert_eq!(old_decrypted_message.get_message(), "Hello, me!");
    }

    #[test]
    fn test_delete_message() {
        let mut user: User<RSA> = setup();

        assert_eq!(user.message_buffer.len(), 2);
        let decrypted_message = user.read_message(0);
        assert_eq!(decrypted_message.get_message(), "Hello, me!");
        user.delete_message(0);
        assert_eq!(user.message_buffer.len(), 1);
        let old_decrypted_message = user.read_message(0);
        assert_eq!(old_decrypted_message.get_message(), "Hello, again!");
    }

    #[test]
    #[should_panic(expected = "removal index")]
    fn test_delete_message_out_of_bounds() {
        let mut user: User<RSA> = User::new("Alice");
        user.create_keys();
        user.public_key_cache
            .insert("Alice".to_string(), user.public_key.clone().unwrap());
        user.session_key_cache
            .insert("Alice".to_string(), user.session_key);
        let encrypted_message = user.create_message("Alice", "Hello, me!");
        user.message_buffer.push(encrypted_message);
        user.delete_message(1);
    }

    #[test]
    fn test_delete_all_messages() {
        let mut user: User<RSA> = setup();

        assert_eq!(user.message_buffer.len(), 2);
        user.delete_all_messages();
        assert_eq!(user.message_buffer.len(), 0);
    }
}
