//! Trait for encryption protocols
//!
//! This module contains a simple trait that allows for the integration of encryption protocols.
/// Trait for encryption protocols.
///
/// Implementations of this trait need to create custom structs for public and private keys,
/// and implement several methods for creating keys, encrypting and decrypting messages, and
/// string conversion.
pub trait EncryptionProtocol {
    /// Type for public keys. Public key is known to all users in the environment.
    type PublicKey: Clone;

    /// Type for private keys. Private key is known only to its owner.
    type PrivateKey;

    /// Method for encrypting messages. Accepts a message as a parameter and
    /// encrypts it using the public key. To encrypt the message, the sender uses
    /// the public key of the receiver of this message.
    fn encrypt(message: &str, pub_key: &Self::PublicKey) -> String;

    /// Method for decrypting messages. Accepts an encrypted message as a parameter and
    /// decrypts it using the private key. To decrypt the message, the receiver uses
    /// their own private key.
    fn decrypt(message: &str, priv_key: &Self::PrivateKey) -> String;

    /// Method for creating public and private keys. Public/private key pair is used for
    /// encrypting and decrypting messages.
    fn create_keys() -> (Self::PublicKey, Self::PrivateKey);

    /// Method for converting a string to a public key. The method is needed
    /// to obtain public keys of other users from messages.
    fn to_public_key(message: &str) -> Self::PublicKey;

    /// Method for converting a public key to a string. The method is needed
    /// to send public keys to other users as a message.
    fn to_string(pub_key: &Self::PublicKey) -> String;
}
