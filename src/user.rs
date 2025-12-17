use std::collections::HashMap;
use rand::Rng;
use num_bigint::BigUint;
use num_bigint::ToBigUint;
use num_traits::cast::ToPrimitive;
use crate::message::Message;
use crate::message::MessageType;
use crate::message::PublicKey;

pub struct User {
    name : String,
    private_key : Option<u128>,
    public_key : Option<u128>,
    n : Option<u128>,
    pub(crate) public_key_cache : HashMap<String, PublicKey>,
    pub(crate) message_buffer : Vec<Message>,
}

impl User {
    pub(crate) fn new(user_name: &str) -> User {
        User {
            name : String::from(user_name),
            private_key : None,
            public_key : None,
            n : None,
            public_key_cache : HashMap::new(),
            message_buffer : Vec::new(),
        }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_public_key(&self) -> Option<u128> {
        self.public_key
    }

    fn decrypt(&self, mes : Message) -> Message {
        match mes.get_message_type() {
            MessageType::Message => {
                let trimmed_message = mes.get_message().trim();
                let chunks = trimmed_message.split(' ');
                let mut decrypted_message : String = String::new();
                for chunk in chunks {
                    let chunk_num : u128 = chunk.parse().unwrap();
                    let mut decrypted_num = Self::expmod(chunk_num, self.private_key.unwrap(), self.n.unwrap());
                    while decrypted_num > 0 {
                        let cur_char : char = (decrypted_num % 256) as u8 as char;
                        decrypted_message.push(cur_char);
                        decrypted_num /= 256;
                    }
                }
                Message::new(&mes.get_sender(), &mes.get_receiver(), &decrypted_message, mes.get_message_type())
            },
            MessageType::PublicKey => {
                mes.clone()
            }
        }
    }

    pub fn read_last_message(&self) -> Message {
        self.decrypt(self.message_buffer[self.message_buffer.len() - 1].clone())
    }

    pub fn read_message(&self, index: usize) -> Message {
        self.decrypt(self.message_buffer[index].clone())
    }

    pub fn read_all_messages(&self) -> Vec<Message> {
        let mut messages : Vec<Message> = Vec::new();
        messages.reserve(self.message_buffer.len());
        for message in &self.message_buffer {
            messages.push(self.decrypt(message.clone()));
        }
        messages
    }

    pub fn delete_last_message(&mut self) {
        self.message_buffer.pop();
    }

    pub fn delete_message(&mut self, index: usize){
        self.message_buffer.remove(index);
    }

    pub fn delete_all_messages(&mut self) {
        self.message_buffer.clear();
    }

    fn encrypt(message: &str, pub_key: &PublicKey) -> String {
        let mut res : u128 = 0;
        let mut base : u128 = 1;
        for c in message.chars() {
            res += base * ((c as u8) as u128);
            base *= 256;
        }

        let encrypted_res = Self::expmod(res, pub_key.public_exp, pub_key.n);

        encrypted_res.to_string()
    }

    pub fn create_message(&self,receiver: &str, message: &str) -> Message {
        let receiver_string : String = String::from(receiver);
        if !self.public_key_cache.contains_key(&receiver_string) {
            panic!("receiver's public key not found");
        }
        let pub_key = self.public_key_cache.get(&receiver_string).unwrap();
        let mut cur_mes = message;
        let mut encrypted_message : String = String::new();
        for _i in 0..=((message.len() - 1) / 8) {
            let split = cur_mes.split_at_checked(8);
            match split {
                Some(_) => {
                    let (head, tail) = split.unwrap();
                    cur_mes = tail;
                    encrypted_message += &(Self::encrypt(head, &pub_key) + " ");
                },
                None => {
                    encrypted_message += &(Self::encrypt(cur_mes, &pub_key) + " ");
                },
            }
        }
        Message::new(&self.name.clone(), receiver, &encrypted_message, MessageType::Message)
    }

    pub fn create_keys(&mut self) -> Message {
        let lower_bound : u128 = 2_u128.pow(62) + 1;
        let upper_bound : u128 = 2_u128.pow(63) - 1;

        let first_primes : Vec<u128> = Self::generate_first_primes(100);
        let p = Self::generate_prime(lower_bound,upper_bound, &first_primes);
        let q = Self::generate_prime(lower_bound,upper_bound, &first_primes);
        //println!("{} {}", p, q);
        self.n = Some(p * q);
        let eulers_func : u128 = (p - 1) * (q - 1);
        self.public_key = Some(Self::generate_public_key(eulers_func));
        let mut x : i128 = 0;
        let mut y : i128 = 0;
        Self::calculate_inverse(self.public_key.unwrap(), eulers_func, &mut x , &mut y);
        self.private_key = Some((x.rem_euclid(eulers_func as i128)) as u128);
        //println!("{} {}", self.public_key.unwrap(), self.private_key.unwrap());
        /*let big_pub : BigUint = self.public_key.unwrap().to_biguint().unwrap();
        let big_priv : BigUint = self.private_key.unwrap().to_biguint().unwrap();
        let big_eul : BigUint = eulers_func.to_biguint().unwrap();
        let res : BigUint = big_pub * big_priv % big_eul;
        println!("{}", res.to_u128().unwrap());*/
        let mes : String = self.n.unwrap().to_string() + " " + &self.public_key.unwrap().to_string();
        Message::new(&self.name.clone(), "", &mes, MessageType::PublicKey)
    }

    fn generate_prime(lower_bound : u128, upper_bound : u128, first_primes : &Vec<u128>) -> u128 {
        loop{
            let prime_candidate : u128 = rand::thread_rng().gen_range(lower_bound..=upper_bound);

            let mut is_divided = false;
            for prime in first_primes {
                if prime_candidate % prime == 0 {
                    is_divided = true;
                    break;
                }
            }

            if is_divided {
                continue;
            }

            let is_prime = Self::rabin_miller_test(prime_candidate);

            if is_prime{
                return prime_candidate;
            }
        }
    }

    fn generate_first_primes(num : usize) -> Vec<u128> {
        let mut primes : Vec<u128> = Vec::with_capacity(num);
        let mut candidates : Vec<usize> = Vec::with_capacity(num);
        for i in 0..num {
            candidates.push(i);
        }

        for i in 2..num {
            if candidates[i] != 0 {
                primes.push(i as u128);
                for k in (i * i .. num).step_by(i) {
                    candidates[k] = 0;
                }
            }
        }

        primes
    }

    fn rabin_miller_test(prime_candidate : u128) -> bool {
        let mut max_divisions_by_two : usize = 0;
        let mut even_component = prime_candidate - 1;
        while even_component % 2 == 0 {
            even_component /= 2;
            max_divisions_by_two += 1;
        }

        let num_iterations = 20;
        for _i in 0..num_iterations {
            let random : u128 = rand::thread_rng().gen_range(2..=prime_candidate);
            if Self::trial(random, even_component, prime_candidate, max_divisions_by_two){
                return false;
            }
        }

        true
    }

    fn trial(random : u128, mut even_component : u128, prime_candidate : u128, max_divisions_by_two : usize) -> bool {
        if Self::expmod(random, even_component, prime_candidate) == 1 {
            return false;
        }

        for _i in 0..max_divisions_by_two {
            if Self::expmod(random, even_component, prime_candidate) == prime_candidate -1 {
                return false;
            }
            even_component *= 2;
        }

        true
    }

    fn expmod(base : u128, exp : u128, modulo : u128) -> u128 {
        if exp == 0 {
            return 1;
        }

        if exp % 2 == 0 {
            let expm : u128 = Self::expmod(base, exp / 2, modulo);
            let big_expm : BigUint = expm.to_biguint().unwrap();
            let big_modulo : BigUint = modulo.to_biguint().unwrap();
            let res : BigUint = big_expm.clone() * big_expm % big_modulo;
            res.to_u128().unwrap()
        }
        else {
            let expm : u128 = Self::expmod(base, exp - 1, modulo);
            let big_base : BigUint = base.to_biguint().unwrap();
            let big_expm : BigUint = expm.to_biguint().unwrap();
            let big_modulo : BigUint = modulo.to_biguint().unwrap();
            let res : BigUint = big_base * big_expm % big_modulo;
            res.to_u128().unwrap()
        }
    }

    fn gcd(a : u128, b : u128) -> u128 {
        if b == 0 {
            a
        }
        else {
            Self::gcd(b, a%b)
        }
    }

    fn generate_public_key(modulo : u128) -> u128 {
        let mut key = 65537_u128;
        while Self::gcd(modulo, key) != 1 {
            key = rand::thread_rng().gen_range(65537_u128..modulo);
        }

        key
    }

    fn calculate_inverse(num : u128, modulo : u128, x : &mut i128, y : &mut i128) -> u128 {
        if num == 0 {
            *x = 0;
            *y = 1;
            return modulo;
        }

        let mut x1 : i128 = 0;
        let mut y1 : i128 = 0;
        let gcd : u128 = Self::calculate_inverse(modulo % num, num, &mut x1, &mut y1);
        *x = y1 - (modulo as i128 / num as i128) * x1;
        *y = x1;

        gcd
    }

}
