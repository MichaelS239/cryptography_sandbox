use std::collections::HashMap;
use std::fs;
use std::io::Write;
use crate::user::User;
use crate::message::{Message, MessageType};
use crate::encryption_protocol::EncryptionProtocol;

pub struct Env<T: EncryptionProtocol> {
    users : HashMap<String, User<T>>,
    log : fs::File,
}

impl<T: EncryptionProtocol> Env<T> {
    pub fn new() -> Self {
        Self {
            users : HashMap::new(),
            log : fs::OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .open("log.txt")
                .expect("failed to open file"),
        }
    }

    pub fn from_file(file_name : &str) -> Self {
        Self {
            users : HashMap::new(),
            log : fs::OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .open(file_name)
                .expect("failed to open file"),
        }
    }

    pub fn create_user(&mut self, user_name: &str) {
        if user_name.is_empty() {
            panic!("name should not be empty");
        }
        match self.users.get(&String::from(user_name)) {
            Some(_) => panic!("this name is already taken!"),
            None => self.users.insert(String::from(user_name), User::<T>::new(user_name))
        };
    }

    pub fn get_user(&self, user_name: &str) -> Option<&User<T>> {
        self.users.get(&String::from(user_name))
    }

    pub fn get_mut_user(&mut self, user_name: &str) -> Option<&mut User<T>> {
        self.users.get_mut(&String::from(user_name))
    }

    pub fn find_user(&self, user_name: &str) -> bool {
        self.users.contains_key(&String::from(user_name))
    }

    pub fn send_message(&mut self, message : Message) {
        if !self.users.contains_key(message.get_sender()) {
            panic!("sender not found");
        }
        else if message.get_receiver().is_empty() {
            let _ = writeln!(self.log, "{}", message.clone());
            for (_, receiver) in &mut self.users {
                receiver.message_buffer.push(message.clone());
                match message.get_message_type() {
                    MessageType::PublicKey => {
                        receiver.public_key_cache.insert(message.get_sender().clone(), T::to_public_key(message.get_message()));
                        receiver.session_key_cache.insert(message.get_sender().clone(), message.get_session_key());
                        ()
                    },
                    _ => (),
                }
            }
        }
        else if !self.users.contains_key(message.get_receiver()) {
            panic!("receiver not found");
        }
        else{
            let _ = writeln!(self.log, "{}", message.clone());
            let receiver : &mut User<T> = self.users.get_mut(message.get_receiver()).unwrap();
            receiver.message_buffer.push(message);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use crate::env::Env;
    use crate::rsa::RSA;
    use crate::message::{Message, MessageType};

    #[test]
    fn test_new() {
        let _env : Env<RSA> = Env::new();
        assert!(fs::exists("log.txt").unwrap());
    }

    #[test]
    fn test_from_file() {
        let _env : Env<RSA> = Env::from_file("my_crazy_log777.txt");
        assert!(fs::exists("my_crazy_log777.txt").unwrap());
    }

    #[test]
    #[should_panic(expected = "name should not be empty")]
    fn test_create_empty_user() {
        let mut env : Env<RSA> = Env::new();
        env.create_user("");
    }

    #[test]
    fn test_create_user() {
        let mut env : Env<RSA> = Env::new();
        env.create_user("Alice");
        assert!(env.find_user("Alice"));
    }

    #[test]
    #[should_panic(expected = "this name is already taken!")]
    fn test_create_duplicate_user() {
        let mut env : Env<RSA> = Env::new();
        env.create_user("Alice");
        env.create_user("Alice");
    }

    #[test]
    fn test_find_user() {
        let mut env : Env<RSA> = Env::new();
        env.create_user("Alice");
        env.create_user("Bob");
        assert!(env.find_user("Alice"));
        assert!(env.find_user("Bob"));
        assert!(!env.find_user("Bobb"));
    }

    #[test]
    fn test_get_existing_user() {
        let mut env : Env<RSA> = Env::new();
        env.create_user("Alice");
        assert!(env.get_user("Alice").is_some());
    }

    #[test]
    fn test_get_nonexisting_user() {
        let mut env : Env<RSA> = Env::new();
        env.create_user("Alice");
        assert!(env.get_user("Bob").is_none());
    }

    #[test]
    fn test_get_mut_user() {
        let mut env : Env<RSA> = Env::new();
        env.create_user("Alice");
        assert!(env.get_mut_user("Alice").is_some());
    }

    #[test]
    #[should_panic(expected = "sender not found")]
    fn test_nonexisting_sender() {
        let mut env : Env<RSA> = Env::new();
        env.create_user("Bob");
        let message = Message::new("Alice", 1, "Bob", "Hello, Bob!", MessageType::Message);
        env.send_message(message);
    }

    #[test]
    #[should_panic(expected = "receiver not found")]
    fn test_nonexisting_receiver() {
        let mut env : Env<RSA> = Env::new();
        env.create_user("Alice");
        let message = Message::new("Alice", 1, "Bob", "Hello, Bob!", MessageType::Message);
        env.send_message(message);
    }

    #[test]
    fn test_log() {
        let mut env : Env<RSA> = Env::from_file("my_crazy_log777.txt");
        env.create_user("Alice");
        env.create_user("Bob");
        let message = Message::new("Alice", 1, "Bob", "Hello, Bob!", MessageType::Message);
        env.send_message(message);
        let mut file = fs::File::open("my_crazy_log777.txt").expect("failed to open file");
        let mut log_message = String::new();
        let _ = file.read_to_string(&mut log_message);
        assert!(log_message.contains("sender: 'Alice'; receiver: 'Bob'; message type: 'Message'; message text: 'Hello, Bob!'; session key: '1'; timestamp: '"));
    }
}
