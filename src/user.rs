use std::collections::HashMap;
use crate::message::{Message, MessageType};
use crate::encryption_protocol::{EncryptionProtocol, PublicKey, PrivateKey};

pub struct User<T: EncryptionProtocol> {
    protocol : T,
    name : String,
    private_key_map : HashMap<usize, PrivateKey>,
    public_key : Option<PublicKey>,
    session_key : usize,
    pub(crate) public_key_cache : HashMap<String, PublicKey>,
    pub(crate) session_key_cache : HashMap<String, usize>,
    pub(crate) message_buffer : Vec<Message>,
}

impl<T: EncryptionProtocol> User<T> {
    pub(crate) fn new(user_name: &str) -> Self {
        Self {
            protocol : T::new(),
            name : String::from(user_name),
            private_key_map : HashMap::new(),
            public_key : None,
            session_key : 0,
            public_key_cache : HashMap::new(),
            session_key_cache : HashMap::new(),
            message_buffer : Vec::new(),
        }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_public_key(&self) -> u128 {
        self.public_key.as_ref().unwrap().public_exp
    }

    fn decrypt_message(&self, mes : Message) -> Message {
        match mes.get_message_type() {
            MessageType::Message => {
                let private_key : &PrivateKey = self.private_key_map.get(&mes.get_session_key()).unwrap();
                let trimmed_message = mes.get_message().trim();
                let chunks = trimmed_message.split(' ');
                let mut decrypted_message : String = String::new();
                for chunk in chunks {
                    decrypted_message += &T::decrypt(chunk, private_key);
                }
                Message::new(&mes.get_sender(), mes.get_session_key(), &mes.get_receiver(), &decrypted_message, mes.get_message_type())
            },
            MessageType::PublicKey => {
                mes.clone()
            }
        }
    }

    pub fn read_last_message(&self) -> Message {
        User::<T>::decrypt_message(&self, self.message_buffer[self.message_buffer.len() - 1].clone())
    }

    pub fn read_message(&self, index: usize) -> Message {
        User::<T>::decrypt_message(&self, self.message_buffer[index].clone())
    }

    pub fn read_all_messages(&self) -> Vec<Message> {
        let mut messages : Vec<Message> = Vec::new();
        messages.reserve(self.message_buffer.len());
        for message in &self.message_buffer {
            messages.push(User::<T>::decrypt_message(&self, message.clone()));
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

    pub fn create_message(&self,receiver: &str, message: &str) -> Message {
        let receiver_string : String = String::from(receiver);
        if !self.public_key_cache.contains_key(&receiver_string) {
            panic!("receiver's public key not found");
        }
        let pub_key = self.public_key_cache.get(&receiver_string).unwrap();
        let mut cur_mes = message;
        let mut encrypted_message : String = String::new();
        for _i in 0..=((message.len() - 1) / 8) {
            let split = cur_mes.split_at_checked(8);
            match split {
                Some(_) => {
                    let (head, tail) = split.unwrap();
                    cur_mes = tail;
                    encrypted_message += &(T::encrypt(head, &pub_key) + " ");
                },
                None => {
                    encrypted_message += &(T::encrypt(cur_mes, &pub_key) + " ");
                },
            }
        }
        Message::new(&self.name.clone(), *self.session_key_cache.get(&receiver_string).unwrap(), receiver, &encrypted_message, MessageType::Message)
    }

    pub fn create_keys(&mut self) -> Message {
        let (public_key, private_key) = T::create_keys();
        self.session_key += 1;
        self.public_key = Some(public_key);
        self.private_key_map.insert(self.session_key, private_key);
        let mes : String = self.public_key.as_ref().unwrap().n.to_string() + " " + &self.public_key.as_ref().unwrap().public_exp.to_string();
        Message::new(&self.name.clone(), self.session_key, "", &mes, MessageType::PublicKey)
    }
}
