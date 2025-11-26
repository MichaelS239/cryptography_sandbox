use std::collections::HashMap;
use crate::user::User;
use crate::message::Message;

pub struct Env {
    users : HashMap<String, User>,
    log : Vec<String>,
}

impl Env {
    pub fn new() -> Env {
        Env {
            users : HashMap::new(),
            log : Vec::new(),
        }
    }

    pub fn create_user(&mut self, user_name: &str) {
        match self.users.get(&String::from(user_name)) {
            Some(_) => panic!("this name is already taken!"),
            None => self.users.insert(String::from(user_name), User::new(user_name))
        };
    }

    pub fn get_user(&self, user_name: &str) -> Option<&User> {
        self.users.get(&String::from(user_name))
    }

    pub fn find_user(&self, user_name: &str) -> bool {
        self.users.contains_key(&String::from(user_name))
    }

    pub fn send_message(&mut self, message : Message) {
        if !self.users.contains_key(message.get_sender()) {
            panic!("sender not found");
        }
        else if !self.users.contains_key(message.get_receiver()) {
            panic!("receiver not found");
        }
        else{
            self.log.push(String::from(message.get_message()));
        }
    }
}
