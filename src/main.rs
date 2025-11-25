use cryptography_sandbox::user::User;
use cryptography_sandbox::env::Env;

fn main() {
    let mut env : Env = Env::new();
    let user1 : User = env.create_user("Alice");
    let user2 : User = env.create_user("Bob");

    println!("Users: {0}, {1}", user1.get_name(), user2.get_name());
    println!("Found: {0}, {1}", env.find_user(user1.get_name()), env.find_user(user2.get_name()));
    //let user3 : User = env.create_user("Alice");
}
