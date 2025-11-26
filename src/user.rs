use crate::message::Message;

pub struct User {
    name : String,
    pub(crate) message_buffer : Vec<Message>,
}

impl User {
    pub(crate) fn new(user_name: &str) -> User {
        User {
            name : String::from(user_name),
            message_buffer : Vec::new(),
        }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn create_message(&self,receiver: &str, message: &str) -> Message {
        Message::new(&self.name.clone(), receiver, message)
    }

    pub fn read_last_message(&self) -> Message {
        self.message_buffer[self.message_buffer.len() - 1].clone()
    }

    pub fn read_message(&self, index: usize) -> Message {
        self.message_buffer[index].clone()
    }

    pub fn read_all_messages(&self) -> Vec<Message> {
        let mut messages : Vec<Message> = Vec::new();
        messages.reserve(self.message_buffer.len());
        for message in &self.message_buffer {
            messages.push(message.clone());
        }
        messages
    }

    pub fn delete_last_message(&mut self) {
        self.message_buffer.pop();
    }

    pub fn delete_message(&mut self, index: usize){
        self.message_buffer.remove(index);
    }

    pub fn delete_all_messages(&mut self) {
        self.message_buffer.clear();
    }
}
