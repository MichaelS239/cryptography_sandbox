use cryptography_sandbox::user::User;
use cryptography_sandbox::env::Env;
use cryptography_sandbox::message::Message;

fn main() {
    let mut env : Env = Env::new();

    env.create_user("Alice");
    env.create_user("Bob");

    let user1 : &User = env.get_user("Alice").expect("name not found");
    let user2 : &User = env.get_user("Bob").expect("name not found");

    println!("Users: {0}, {1}", user1.get_name(),user2.get_name());
    println!("Found: {0}, {1}", env.find_user("Alice"), env.find_user("Bob"));
    //env.create_user("Alice");
    let sent_message : Message = user1.create_message("Bob", "Hello, Bob!");
    println!("User '{0}' sent a message to user '{1}': '{2}'", sent_message.get_sender(), sent_message.get_receiver(), sent_message.get_message());
    env.send_message(sent_message);
    let user2 : &User = env.get_user("Bob").expect("name not found");
    let received_message : Message = user2.read_last_message();
    println!("User '{0}' got a message from user '{1}': '{2}'",received_message.get_receiver(), received_message.get_sender(), received_message.get_message());
}
