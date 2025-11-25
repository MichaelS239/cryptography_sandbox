pub struct User {
    name : String,
}

impl User {
    pub(crate) fn new(user_name: &str) -> User {
        User {
            name : String::from(user_name),
        }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    fn send_message(&self, receiver_name: &String, message: &String){
        unimplemented!();
    }
}
