use cryptography_sandbox::env::Env;
use cryptography_sandbox::message::Message;
use cryptography_sandbox::rsa::RSA;
use std::time::UNIX_EPOCH;

fn main() {
    let mut env: Env<RSA> = Env::from_file("my_log.txt");

    env.create_user("Alice");
    env.create_user("Bob");

    let key = env
        .get_mut_user("Bob")
        .expect("name not found")
        .create_keys();
    env.send_message(key);

    let user1 = env.get_user("Alice").expect("name not found");
    let user2 = env.get_user("Bob").expect("name not found");

    println!("Users: {0}, {1}", user1.get_name(), user2.get_name());
    println!(
        "Found: {0}, {1}",
        env.find_user("Alice"),
        env.find_user("Bob")
    );
    //env.create_user("Alice");
    let sent_message: Message = user1.create_message("Bob", "Hello, Bob!");
    println!(
        "User '{0}' sent a message to user '{1}': '{2}'",
        sent_message.get_sender(),
        sent_message.get_receiver(),
        sent_message.get_message()
    );
    env.send_message(sent_message);
    let user2 = env.get_user("Bob").expect("name not found");
    let received_message: Message = user2.read_last_message();
    println!(
        "User '{0}' got a message from user '{1}': '{2}'",
        received_message.get_receiver(),
        received_message.get_sender(),
        received_message.get_message()
    );
    println!(
        "Timestamp: {:?}",
        received_message
            .get_timestamp()
            .duration_since(UNIX_EPOCH)
            .unwrap()
    );
    let new_key = env
        .get_mut_user("Bob")
        .expect("name not found")
        .create_keys();
    env.send_message(new_key);
    let user3 = env.get_user("Bob").expect("name not found");
    let received_message: Message = user3.read_last_message();
    println!(
        "User '{0}' got a message from user '{1}': '{2}'",
        received_message.get_receiver(),
        received_message.get_sender(),
        received_message.get_message()
    );
    println!(
        "Timestamp: {:?}",
        received_message
            .get_timestamp()
            .duration_since(UNIX_EPOCH)
            .unwrap()
    );
    let user4 = env.get_mut_user("Bob").expect("name not found");
    user4.delete_last_message();
    let received_message: Message = user4.read_last_message();
    println!(
        "User '{0}' got a message from user '{1}': '{2}'",
        received_message.get_receiver(),
        received_message.get_sender(),
        received_message.get_message()
    );
    println!(
        "Timestamp: {:?}",
        received_message
            .get_timestamp()
            .duration_since(UNIX_EPOCH)
            .unwrap()
    );
    println!("{}", received_message);
}
