use crate::dh;
use crate::digest::{hmac, sha256};
use crate::encode::from_ascii;
use num_bigint::BigUint;
use rand::Rng;
use std::collections::HashMap;

fn modmult(x: BigUint, y: &BigUint) -> BigUint {
    (x * y) % p()
}

fn modsum(x: BigUint, y: &BigUint) -> BigUint {
    (x + y) % p()
}

const K: u8 = 3;
const G: u8 = 2;
const P: &[u8; 391] = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff";

fn k() -> BigUint {
    BigUint::from(K)
}

fn g() -> BigUint {
    BigUint::from(G)
}

fn p() -> BigUint {
    BigUint::from_bytes_be(P)
}

pub struct Server {
    privkey: BigUint,
    credentials: HashMap<String, (BigUint, u128)>,
}

impl Server {
    pub fn init() -> Self {
        Self {
            privkey: dh::dh_keys(&p(), g(), &mut rand::thread_rng()).0,
            credentials: HashMap::new(),
        }
    }

    pub fn add_client(&mut self, email: &str, cred: BigUint, salt: u128) {
        self.credentials.insert(String::from(email), (cred, salt));
    }

    pub fn identify(&self, email: &str) -> (BigUint, u128) {
        let (v, s) = self.credentials.get(email).expect("client not registered");
        ((modsum(modmult(k(), v), &g().modpow(&self.privkey, &p()))), *s)
    }

    fn calc_u(&self, client_email: &str, client_pubkey: &BigUint) -> BigUint {
        let mut pubkeys = client_pubkey.to_bytes_be();
        pubkeys.extend(self.identify(client_email).0.to_bytes_be());
        BigUint::from_bytes_be(&sha256(&pubkeys))
    }

    pub fn validate_srp(&self, email: &str, pubkey: &BigUint, digest: [u8; 32]) -> bool {
        let p = p();
        let u = self.calc_u(email, pubkey);
        let (v, salt) = self.credentials.get(email).expect("client not registered");
        let s = modmult(v.clone().modpow(&u, &p), pubkey).modpow(&self.privkey, &p);
        let k = sha256(&s.to_bytes_be());

        let res = hmac(&k, &salt.to_be_bytes(), sha256);
        println!("exp: {:?}", digest);
        println!("prov {:?}", res);
        res == digest
    }
}

pub struct Client {
    email: String,
    password: String,
    privkey: BigUint,
    pubkey: BigUint,
}

impl Client {
    pub fn init(email: String, password: String) -> Self {
        let (privkey, pubkey) = dh::dh_keys(&p(), g(), &mut rand::thread_rng());
        Self {
            email,
            password,
            privkey,
            pubkey,
        }
    }

    pub fn identify(&self) -> (&str, &BigUint) {
        (&self.email, &self.pubkey)
    }

    fn gen_salt(&self) -> u128 {
        let mut rng = rand::thread_rng();
        rng.gen()
    }

    fn gen_key(&self, salt: u128) -> BigUint {
        let mut x_h = Vec::from(salt.to_be_bytes());
        x_h.extend(from_ascii(&self.password));
        BigUint::from_bytes_be(&sha256(&x_h))
    }

    pub fn register(&self, server: &mut Server) {
        let salt = self.gen_salt();
        let x = self.gen_key(salt);
        let v = g().modpow(&x, &p());
        server.add_client(&self.email, v, salt)
    }

    fn calc_u(&self, server_pubkey: &BigUint) -> BigUint {
        let mut pubkeys = self.pubkey.to_bytes_be();
        pubkeys.extend(server_pubkey.to_bytes_be());
        BigUint::from_bytes_be(&sha256(&pubkeys))
    }

    pub fn get_digest(&self, server_pubkey: &BigUint, salt: u128) -> [u8; 32] {
        let u = self.calc_u(&server_pubkey);
        let x = self.gen_key(salt);
        let neg_k_gx = modmult(p() - g().modpow(&x, &p()), &k());
        let exp = modsum(u * x, &self.privkey);
        let s = modsum(neg_k_gx, server_pubkey).modpow(&exp, &p());
        let k = &sha256(&s.to_bytes_be());
        hmac(k, &salt.to_be_bytes(), sha256)
    }

    pub fn get_zero_digest(&self, salt: u128) -> [u8; 32] {
        let k0 = &sha256(&0u8.to_be_bytes());
        hmac(k0, &salt.to_be_bytes(), sha256)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn auth_works() {
        let mut server = Server::init();
        let client1 = Client::init(String::from("email1"), String::from("pass1"));
        let client2 = Client::init(String::from("email2"), String::from("pass2"));
        client1.register(&mut server);
        client2.register(&mut server);

        let (email1, pubkey1) = client1.identify();
        let (server_pubkey1, salt1) = server.identify(email1);
        let digest1 = client1.get_digest(&server_pubkey1, salt1);
        assert!(server.validate_srp(email1, pubkey1, digest1));

        // client2 tries to auth as client1
        let (email2, pubkey2) = client1.identify();
        let (server_pubkey2, salt2) = server.identify(&email2);
        let digest2 = client2.get_digest(&server_pubkey2, salt2);
        assert!(!server.validate_srp(email2, pubkey2, digest2));

        // client2 auths as client1
        let email0 = email1;
        let pubkey0 = &BigUint::from(0u8);
        let (_, salt0) = server.identify(email0);
        let digest0 = client2.get_zero_digest(salt0);
        assert!(server.validate_srp(email0, pubkey0, digest0));
        //assert!(server.validate_srp(email0, &p(), digest0));
    }
}
