use std::collections::HashMap;
use crate::user::User;
use crate::message::Message;
use crate::message::MessageType;
use crate::message::PublicKey;

pub struct Env {
    users : HashMap<String, User>,
    log : Vec<Message>,
}

impl Env {
    pub fn new() -> Env {
        Env {
            users : HashMap::new(),
            log : Vec::new(),
        }
    }

    pub fn create_user(&mut self, user_name: &str) {
        if user_name.is_empty() {
            panic!("name should not be empty");
        }
        match self.users.get(&String::from(user_name)) {
            Some(_) => panic!("this name is already taken!"),
            None => self.users.insert(String::from(user_name), User::new(user_name))
        };
    }

    pub fn get_user(&self, user_name: &str) -> Option<&User> {
        self.users.get(&String::from(user_name))
    }

    pub fn get_mut_user(&mut self, user_name: &str) -> Option<&mut User> {
        self.users.get_mut(&String::from(user_name))
    }

    pub fn find_user(&self, user_name: &str) -> bool {
        self.users.contains_key(&String::from(user_name))
    }

    fn to_public_key(message : &String) -> PublicKey {
        let (num, exp) = message.split_once(' ').unwrap();
        let n : u128 = num.parse().unwrap();
        let public_exp : u128 = exp.parse().unwrap();

        PublicKey {n, public_exp}
    }

    pub fn send_message(&mut self, message : Message) {
        if !self.users.contains_key(message.get_sender()) {
            panic!("sender not found");
        }
        else if message.get_receiver().is_empty() {
            self.log.push(message.clone());
            for (_, receiver) in &mut self.users {
                receiver.message_buffer.push(message.clone());
                match message.get_message_type() {
                    MessageType::PublicKey => {
                        receiver.public_key_cache.insert(message.get_sender().clone(), Self::to_public_key(message.get_message()));
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
            self.log.push(message.clone());
            let receiver : &mut User = self.users.get_mut(message.get_receiver()).unwrap();
            receiver.message_buffer.push(message);
        }
    }
}
