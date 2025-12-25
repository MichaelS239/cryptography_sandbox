[![Build status](https://github.com/MichaelS239/cryptography_sandbox/actions/workflows/rust.yml/badge.svg)](https://github.com/MichaelS239/cryptography_sandbox/actions/workflows/rust.yml)

# About

This is a library for simulating the process of secure communication. The library allows for creating users, sending and receiving messages using various cryptographic protocols.

# Features

- Simple and easy-to-use, which is excellent for educational purposes
- Supports RSA cryptographic protocol
- Allows for easily integrating other protocols via a simple trait
- Blazingly fast and memory-safe, as all Rust projects are

# Usage example

The following code shows a simple usage example. The extended version of this example is located in `main.rs`.
```rust
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

    // To be able to receive encrypted messages, Bob creates a public/private key pair.
    // The public key is returned in a message; the private key is secret and is known only by Bob.
    let key = env
        .get_mut_user("Bob")
        .expect("name not found")
        .create_keys();

    // The environment broadcasts the public key to all users.
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
}
```

# Prerequisites
The following software is required to build the project:
- Rust, version 1.91+

# Build instructions
Firstly, clone the repository and change the current directory to the project directory.

In order to build the project, run the following command in the terminal:
```sh
cargo build
```

# Usage
In order to execute the usage example, run the following command:
```sh
cargo run
```
In order to run tests, run the following command:
```sh
cargo test
```
If you want to use the library in your own project, add the following lines to your `Cargo.toml`:
```
[dependencies]
cryptography_sandbox = { path = "<path/to/cryptography_sandbox>" }
```
# Documentation
In order to see the documentation for the library, run the following command:
```sh
cargo doc --open
```
