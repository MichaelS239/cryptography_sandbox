#[derive(Clone)]
pub struct PublicKey {
    pub(crate) n : u128,
    pub(crate) public_exp :u128,
}

pub struct PrivateKey {
    pub(crate) n : u128,
    pub(crate) private_exp :u128,
}

pub trait EncryptionProtocol {
    fn new() -> Self;
    fn encrypt(message: &str, pub_key: &PublicKey) -> String;
    fn decrypt(message: &str, priv_key: &PrivateKey) -> String;
    fn create_keys() -> (PublicKey, PrivateKey);
}
