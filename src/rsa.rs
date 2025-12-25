//! Implementaion of RSA encryption protocol
//!
//! This module contains the implementation of the trait `EncryptionProtocol`.
use crate::encryption_protocol::EncryptionProtocol;
use num_bigint::BigUint;
use num_bigint::ToBigUint;
use num_traits::cast::ToPrimitive;
use rand::Rng;

/// Struct for public key in RSA.
///
/// RSA public key consists of a number `n = p * q` (`p, q` - primes)
/// and a public exponent `e < n` (`gcd(e, \phi(n)) = 1`,
/// `e * d % \phi(n) = 1`, `d` - private exponent, `\phi(n)` - Euler's function).
#[derive(Clone)]
pub struct PublicKey {
    pub(crate) n: u128,
    pub(crate) public_exp: u128,
}

/// Struct for private key in RSA.
///
/// RSA private key consists of a number `n = p * q` (`p, q` - primes)
/// and a private exponent `d < n` (`e * d % \phi(n) = 1`, `e` - public exponent,
/// `\phi(n)` - Euler's function).
pub struct PrivateKey {
    pub(crate) n: u128,
    pub(crate) private_exp: u128,
}

/// Implementation of the trait `EncryptionProtocol`.
///
/// Contains helper methods for creating keys and the implementation of trait methods.
pub struct RSA {}

impl RSA {
    fn generate_prime(lower_bound: u128, upper_bound: u128, first_primes: &Vec<u128>) -> u128 {
        loop {
            let prime_candidate: u128 = rand::thread_rng().gen_range(lower_bound..=upper_bound);

            let mut is_divided = false;
            for prime in first_primes {
                if prime_candidate.is_multiple_of(*prime) {
                    is_divided = true;
                    break;
                }
            }

            if is_divided {
                continue;
            }

            let is_prime = Self::rabin_miller_test(prime_candidate);

            if is_prime {
                return prime_candidate;
            }
        }
    }

    fn generate_first_primes(num: usize) -> Vec<u128> {
        let mut primes: Vec<u128> = Vec::with_capacity(num);
        let mut candidates: Vec<usize> = Vec::with_capacity(num);
        for i in 0..num {
            candidates.push(i);
        }

        for i in 2..num {
            if candidates[i] != 0 {
                primes.push(i as u128);
                for k in (i * i..num).step_by(i) {
                    candidates[k] = 0;
                }
            }
        }

        primes
    }

    fn rabin_miller_test(prime_candidate: u128) -> bool {
        let mut max_divisions_by_two: usize = 0;
        let mut even_component = prime_candidate - 1;
        while even_component.is_multiple_of(2) {
            even_component /= 2;
            max_divisions_by_two += 1;
        }

        let num_iterations = 20;
        for _i in 0..num_iterations {
            let random: u128 = rand::thread_rng().gen_range(2..=prime_candidate);
            if Self::trial(
                random,
                even_component,
                prime_candidate,
                max_divisions_by_two,
            ) {
                return false;
            }
        }

        true
    }

    fn trial(
        random: u128,
        mut even_component: u128,
        prime_candidate: u128,
        max_divisions_by_two: usize,
    ) -> bool {
        if Self::expmod(random, even_component, prime_candidate) == 1 {
            return false;
        }

        for _i in 0..max_divisions_by_two {
            if Self::expmod(random, even_component, prime_candidate) == prime_candidate - 1 {
                return false;
            }
            even_component *= 2;
        }

        true
    }

    fn expmod(base: u128, exp: u128, modulo: u128) -> u128 {
        if exp == 0 {
            return 1;
        }

        if exp.is_multiple_of(2) {
            let expm: u128 = Self::expmod(base, exp / 2, modulo);
            let big_expm: BigUint = expm.to_biguint().unwrap();
            let big_modulo: BigUint = modulo.to_biguint().unwrap();
            let res: BigUint = big_expm.clone() * big_expm % big_modulo;
            res.to_u128().unwrap()
        } else {
            let expm: u128 = Self::expmod(base, exp - 1, modulo);
            let big_base: BigUint = base.to_biguint().unwrap();
            let big_expm: BigUint = expm.to_biguint().unwrap();
            let big_modulo: BigUint = modulo.to_biguint().unwrap();
            let res: BigUint = big_base * big_expm % big_modulo;
            res.to_u128().unwrap()
        }
    }

    fn gcd(a: u128, b: u128) -> u128 {
        if b == 0 { a } else { Self::gcd(b, a % b) }
    }

    fn generate_public_key(modulo: u128) -> u128 {
        let mut key = 65537_u128;
        while Self::gcd(modulo, key) != 1 {
            key = rand::thread_rng().gen_range(65537_u128..modulo);
        }

        key
    }

    fn calculate_inverse(num: u128, modulo: u128, x: &mut i128, y: &mut i128) -> u128 {
        if num == 0 {
            *x = 0;
            *y = 1;
            return modulo;
        }

        let mut x1: i128 = 0;
        let mut y1: i128 = 0;
        let gcd: u128 = Self::calculate_inverse(modulo % num, num, &mut x1, &mut y1);
        *x = y1 - (modulo as i128 / num as i128) * x1;
        *y = x1;

        gcd
    }
}

impl EncryptionProtocol for RSA {
    /// Implementation of `PublicKey` for RSA is used.
    type PublicKey = PublicKey;
    /// Implementation of `PrivateKey` for RSA is used.
    type PrivateKey = PrivateKey;

    /// The message is encrypted using RSA protocol: `m -> m^e % n`
    /// (`m` - message, `e` - public exponent).
    fn encrypt(message: &str, pub_key: &PublicKey) -> String {
        let mut res: u128 = 0;
        let mut base: u128 = 1;
        for c in message.chars() {
            res += base * ((c as u8) as u128);
            base *= 256;
        }

        let encrypted_res = Self::expmod(res, pub_key.public_exp, pub_key.n);

        encrypted_res.to_string()
    }

    /// The message is decrypted using RSA protocol: `m -> m^d % n`
    /// (`m` - message, `d` - private exponent).
    fn decrypt(message: &str, priv_key: &PrivateKey) -> String {
        let message_num: u128 = message.parse().unwrap();
        let mut decrypted_num = Self::expmod(message_num, priv_key.private_exp, priv_key.n);
        let mut decrypted_message: String = String::new();
        while decrypted_num > 0 {
            let cur_char: char = (decrypted_num % 256) as u8 as char;
            decrypted_message.push(cur_char);
            decrypted_num /= 256;
        }

        decrypted_message
    }

    /// The method generates 128-bit keys for RSA.
    ///
    /// The method generates two prime numbers `p` and `q`,
    /// calculates `n = p * q`, chooses a public exponent `e`
    /// and calculates the private exponent: `e * d % \phi(n) = 1`.
    fn create_keys() -> (PublicKey, PrivateKey) {
        let lower_bound: u128 = 2_u128.pow(62) + 1;
        let upper_bound: u128 = 2_u128.pow(63) - 1;

        let first_primes: Vec<u128> = Self::generate_first_primes(100);
        let p = Self::generate_prime(lower_bound, upper_bound, &first_primes);
        let q = Self::generate_prime(lower_bound, upper_bound, &first_primes);

        let n = p * q;
        let eulers_func: u128 = (p - 1) * (q - 1);
        let public_exp = Self::generate_public_key(eulers_func);

        let mut x: i128 = 0;
        let mut y: i128 = 0;
        Self::calculate_inverse(public_exp, eulers_func, &mut x, &mut y);
        let private_exp = (x.rem_euclid(eulers_func as i128)) as u128;

        let public_key: PublicKey = PublicKey { n, public_exp };
        let private_key: PrivateKey = PrivateKey { n, private_exp };

        (public_key, private_key)
    }

    /// Parses a string `"a b"` to public key (`n = a, e = b`).
    fn to_public_key(message: &str) -> PublicKey {
        let (num, exp) = message.split_once(' ').unwrap();
        let n: u128 = num.parse().unwrap();
        let public_exp: u128 = exp.parse().unwrap();

        PublicKey { n, public_exp }
    }

    /// Creates a string from public key: `n, e -> "n e"`.
    fn to_string(pub_key: &Self::PublicKey) -> String {
        pub_key.n.to_string() + " " + &pub_key.public_exp.to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::encryption_protocol::EncryptionProtocol;
    use crate::rsa::{PublicKey, RSA};

    #[test]
    fn test_encrypt_decrypt() {
        let (public_key, private_key) = RSA::create_keys();
        let encrypted_message = RSA::encrypt("hello", &public_key);
        let decrypted_message = RSA::decrypt(&encrypted_message, &private_key);
        assert_eq!(decrypted_message, "hello");
    }

    #[test]
    fn test_identity_encryption() {
        let (public_key, _private_key) = RSA::create_keys();
        let mut identity_message = String::new();
        identity_message.push(char::from_u32(1).unwrap());
        let encrypted_message = RSA::encrypt(&identity_message, &public_key);
        assert_eq!(encrypted_message.as_bytes()[0], b'1');
    }

    #[test]
    fn test_to_public_key() {
        let key = RSA::to_public_key("123 456");

        assert_eq!(key.n, 123);
        assert_eq!(key.public_exp, 456);
    }

    #[test]
    fn test_to_string() {
        let key = PublicKey {
            n: 123_u128,
            public_exp: 456_u128,
        };
        let mes = RSA::to_string(&key);

        assert_eq!(mes, "123 456");
    }
}
