use cryptography_sandbox::env::Env;
use cryptography_sandbox::message::MessageType;
use cryptography_sandbox::rsa::RSA;

#[test]
fn test_get_user() {
    let mut env : Env<RSA> = Env::new();

    env.create_user("Alice");
    env.create_user("Bob");

    assert!(env.find_user("Alice"));
    assert!(env.find_user("Bob"));
    assert!(!env.find_user("Bobb"));

    let user = env.get_user("Alice").unwrap();
    assert_eq!(user.get_name(), "Alice");
    let user1 = env.get_user("Bob").unwrap();
    assert_eq!(user1.get_name(), "Bob");
}

#[test]
fn test_create_keys() {
    let mut env : Env<RSA> = Env::new();

    env.create_user("Alice");
    env.create_user("Bob");

    let key = env.get_mut_user("Bob").expect("name not found").create_keys();
    assert_eq!(key.get_receiver(), "");
    let is_public_key_type = match key.get_message_type(){
        MessageType::Message => false,
        MessageType::PublicKey => true,
    };
    assert!(is_public_key_type);
    let key_message : String = String::from(key.get_message());
    env.send_message(key);

    assert!(env.get_user("Bob").expect("name not found").get_public_key().is_some());
    let mes = env.get_user("Alice").expect("name not found").read_last_message();
    let user_message : String = String::from(mes.get_message());
    assert_eq!(key_message, user_message);
}

#[test]
fn test_send_message() {
    let mut env : Env<RSA> = Env::new();

    env.create_user("Alice");
    env.create_user("Bob");

    let key = env.get_mut_user("Bob").expect("name not found").create_keys();
    env.send_message(key);

    let message = env.get_user("Alice").expect("name not found").create_message("Bob", "Hello, Bob!");
    assert_eq!(message.get_sender(), "Alice");
    assert_eq!(message.get_receiver(), "Bob");
    let is_message_type = match message.get_message_type(){
        MessageType::Message => true,
        MessageType::PublicKey => false,
    };
    assert!(is_message_type);
    env.send_message(message);
    let received_message = env.get_user("Bob").expect("name not found").read_last_message();
    assert_eq!(received_message.get_message(), "Hello, Bob!");
}

#[test]
#[should_panic(expected = "receiver's public key not found")]
fn test_nonexisting_public_key() {
    let mut env : Env<RSA> = Env::new();

    env.create_user("Alice");
    env.create_user("Bob");

    env.get_user("Alice").expect("name not found").create_message("Bob", "Hello, Bob!");
}

#[test]
fn test_change_keys() {
    let mut env : Env<RSA> = Env::new();

    env.create_user("Alice");
    env.create_user("Bob");

    let key = env.get_mut_user("Bob").expect("name not found").create_keys();
    env.send_message(key);

    let message = env.get_user("Alice").expect("name not found").create_message("Bob", "Hello, Bob!");
    env.send_message(message);

    let new_key = env.get_mut_user("Bob").expect("name not found").create_keys();
    env.send_message(new_key);

    let last_message = env.get_user("Bob").expect("name not found").read_last_message();
    let is_public_key_type = match last_message.get_message_type(){
        MessageType::Message => false,
        MessageType::PublicKey => true,
    };
    assert!(is_public_key_type);
    let first_message = env.get_user("Bob").expect("name not found").read_message(0);
    let is_public_key_type = match first_message.get_message_type(){
        MessageType::Message => false,
        MessageType::PublicKey => true,
    };
    assert!(is_public_key_type);
    let received_message = env.get_user("Bob").expect("name not found").read_message(1);
    assert_eq!(received_message.get_message(), "Hello, Bob!");
}

#[test]
fn test_send_to_myself() {
    let mut env : Env<RSA> = Env::new();

    env.create_user("Alice");

    let key = env.get_mut_user("Alice").expect("name not found").create_keys();
    env.send_message(key);

    let message = env.get_user("Alice").expect("name not found").create_message("Alice", "Hello, me!");
    env.send_message(message);

    let received_message = env.get_user("Alice").expect("name not found").read_last_message();
    assert_eq!(received_message.get_message(), "Hello, me!");
}

#[test]
fn test_communication() {
    let mut env : Env<RSA> = Env::new();

    env.create_user("Alice");
    env.create_user("Bob");

    let bob_key = env.get_mut_user("Bob").expect("name not found").create_keys();
    env.send_message(bob_key);

    let alice_key = env.get_mut_user("Alice").expect("name not found").create_keys();
    env.send_message(alice_key);

    let first_message = env.get_user("Alice").expect("name not found").create_message("Bob", "Hello, Bob!");
    env.send_message(first_message);
    let new_bob_key = env.get_mut_user("Bob").expect("name not found").create_keys();
    env.send_message(new_bob_key);
    let second_message = env.get_user("Bob").expect("name not found").create_message("Alice", "Hello, Alice! How are you?");
    env.send_message(second_message);
    let new_alice_key = env.get_mut_user("Alice").expect("name not found").create_keys();
    env.send_message(new_alice_key);
    let third_message = env.get_user("Alice").expect("name not found").create_message("Bob", "I'm OK, thanks. And you?");
    env.send_message(third_message);

    let alice_messages = env.get_user("Alice").expect("name not found").read_all_messages();
    assert_eq!(alice_messages.len(), 5);
    let first_message = &alice_messages[0];
    assert_eq!(first_message.get_sender(), "Bob");
    assert_eq!(first_message.get_receiver(), "");
    let second_message = &alice_messages[1];
    assert_eq!(second_message.get_sender(), "Alice");
    assert_eq!(second_message.get_receiver(), "");
    let third_message = &alice_messages[2];
    assert_eq!(third_message.get_sender(), "Bob");
    assert_eq!(third_message.get_receiver(), "");
    let forth_message = &alice_messages[3];
    assert_eq!(forth_message.get_sender(), "Bob");
    assert_eq!(forth_message.get_receiver(), "Alice");
    assert_eq!(forth_message.get_message(), "Hello, Alice! How are you?");
    let fifth_message = &alice_messages[4];
    assert_eq!(fifth_message.get_sender(), "Alice");
    assert_eq!(fifth_message.get_receiver(), "");

    let bob_messages = env.get_user("Bob").expect("name not found").read_all_messages();
    assert_eq!(bob_messages.len(), 6);
    let first_message = &bob_messages[0];
    assert_eq!(first_message.get_sender(), "Bob");
    assert_eq!(first_message.get_receiver(), "");
    let second_message = &bob_messages[1];
    assert_eq!(second_message.get_sender(), "Alice");
    assert_eq!(second_message.get_receiver(), "");
    let third_message = &bob_messages[2];
    assert_eq!(third_message.get_sender(), "Alice");
    assert_eq!(third_message.get_receiver(), "Bob");
    assert_eq!(third_message.get_message(), "Hello, Bob!");
    let forth_message = &bob_messages[3];
    assert_eq!(forth_message.get_sender(), "Bob");
    assert_eq!(forth_message.get_receiver(), "");
    let fifth_message = &bob_messages[4];
    assert_eq!(fifth_message.get_sender(), "Alice");
    assert_eq!(fifth_message.get_receiver(), "");
    let sixth_message = &bob_messages[5];
    assert_eq!(sixth_message.get_sender(), "Alice");
    assert_eq!(sixth_message.get_receiver(), "Bob");
    assert_eq!(sixth_message.get_message(), "I'm OK, thanks. And you?");
}
