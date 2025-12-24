pub trait EncryptionProtocol {
    type PublicKey: Clone;
    type PrivateKey;

    fn encrypt(message: &str, pub_key: &Self::PublicKey) -> String;
    fn decrypt(message: &str, priv_key: &Self::PrivateKey) -> String;
    fn create_keys() -> (Self::PublicKey, Self::PrivateKey);
    fn to_public_key(message: &str) -> Self::PublicKey;
    fn to_string(pub_key: &Self::PublicKey) -> String;
}
