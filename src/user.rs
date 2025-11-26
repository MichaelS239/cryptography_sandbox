use crate::message::Message;

pub struct User {
    name : String,
    pub(crate) buf : Vec<String>,
}

impl User {
    pub(crate) fn new(user_name: &str) -> User {
        User {
            name : String::from(user_name),
            buf : Vec::new(),
        }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn create_message(&self,receiver: &str, message: &str) -> Message {
        Message::new(&self.name.clone(), receiver, message)
    }
}
