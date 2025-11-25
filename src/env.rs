use std::collections::HashSet;
use crate::user::User;

pub struct Env {
    users : HashSet<String>,
}

impl Env {
    pub fn new() -> Env {
        Env {
            users : HashSet::new(),
        }
    }

    pub fn create_user(& mut self, user_name: &str) -> User {
        if !self.users.contains(&String::from(user_name)) {
            self.users.insert(String::from(user_name));
            User::new(user_name)
        }
        else {
            panic!("this name is already taken!");
        }
    }

    pub fn find_user(&self, user_name: &String) -> bool {
        self.users.contains(user_name)
    }

    fn send_message(& mut self, sender: &User, receiver: &User, message: &String) {
        unimplemented!();
    }
}
