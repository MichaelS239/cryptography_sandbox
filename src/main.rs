use cryptography_sandbox::env::Env;
use cryptography_sandbox::message::Message;
use cryptography_sandbox::rsa::RSA;
use std::time::UNIX_EPOCH;

fn main() {
    // Firstly, we create an environment that uses RSA protocol and specify the log file.
    // Environment is responsible for handling users and sending messages.
    let mut env: Env<RSA> = Env::from_file("my_log.txt");

    // We create two users: Alice and Bob.
    env.create_user("Alice");
    env.create_user("Bob");

    // To be able to receivq encrypted messages, Bob creates a public/private key pair.
    // The public key is returned in a message; the private key is secret and is known only by Bob.
    let key = env
        .get_mut_user("Bob")
        .expect("name not found")
        .create_keys();

    // The environment broadcasts the public key to all users
    env.send_message(key);

    let user1 = env.get_user("Alice").expect("name not found");
    let user2 = env.get_user("Bob").expect("name not found");

    // Let's print the names of the users and check if they are present in the environment.
    println!("Users: {0}, {1}", user1.get_name(), user2.get_name());
    println!(
        "Found: {0}, {1}",
        env.find_user("Alice"),
        env.find_user("Bob")
    );

    // Note that the following commented command would result in an error because we
    // cannot create two users with the same name.
    //env.create_user("Alice");

    // To create an encrypted message, we specify the receiver and the text of the message.
    let sent_message: Message = user1.create_message("Bob", "Hello, Bob!");
    println!(
        "User '{0}' sent a message to user '{1}': '{2}'",
        sent_message.get_sender(),
        sent_message.get_receiver(),
        sent_message.get_message()
    );

    // The environment sends the message from Alice to Bob.
    // Note that information about all of the encrypted messages is written to the log.
    env.send_message(sent_message);

    // Bob reads the message
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

    // In order to change the key pair, we simply execute the corresponding method once again.
    let new_key = env
        .get_mut_user("Bob")
        .expect("name not found")
        .create_keys();

    // We shouldn't forget to notify others about the change
    env.send_message(new_key);

    // Let's read the last message from the buffer.
    // It is the broadcast message with public key that Bob has just sent.
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

    // Let's delete this message from the buffer.
    // The old message is still present there.
    let user4 = env.get_mut_user("Bob").expect("name not found");
    user4.delete_last_message();

    // Let's check that the old message still decrypts with the correct key
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
