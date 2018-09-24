use sodiumoxide::crypto::scalarmult;
use sodiumoxide::randombytes;
use sodiumoxide::utils;
use tree::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Zero {}

#[derive(PartialEq, Eq, Clone)]
pub struct X25519PublicKey {
    group_element: scalarmult::curve25519::GroupElement,
}

#[derive(PartialEq, Clone)]
pub struct X25519PrivateKey {
    scalar: scalarmult::curve25519::Scalar,
}

pub const X25519PRIVATEKEYBYTES: usize = scalarmult::SCALARBYTES;

impl X25519PrivateKey {
    pub fn shared_secret(&self, p: &X25519PublicKey) -> Result<[u8; 32], Zero> {
        scalarmult::curve25519::scalarmult(&self.scalar, &p.group_element)
            .map(|ge| ge.0)
            .map_err(|()| Zero {})
    }
    pub fn derive_public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            group_element: scalarmult::curve25519::scalarmult_base(&self.scalar),
        }
    }
    pub fn from_bytes(bytes: [u8; X25519PRIVATEKEYBYTES]) -> X25519PrivateKey {
        X25519PrivateKey {
            scalar: scalarmult::curve25519::Scalar(bytes),
        }
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.0
    }
}

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        utils::memzero(&mut self.scalar.0)
    }
}

pub struct X25519KeyPair {
    pub private_key: X25519PrivateKey,
    pub public_key: X25519PublicKey,
}

impl X25519KeyPair {
    pub fn new_random() -> X25519KeyPair {
        let random_bytes = randombytes::randombytes(scalarmult::curve25519::SCALARBYTES);
        let mut private_key: scalarmult::curve25519::Scalar =
            scalarmult::curve25519::Scalar([0u8; scalarmult::curve25519::SCALARBYTES]);
        private_key.0[..scalarmult::curve25519::SCALARBYTES]
            .clone_from_slice(&random_bytes[..scalarmult::curve25519::SCALARBYTES]);
        let public_key = scalarmult::curve25519::scalarmult_base(&private_key);

        X25519KeyPair {
            private_key: X25519PrivateKey {
                scalar: private_key,
            },
            public_key: X25519PublicKey {
                group_element: public_key,
            },
        }
    }
    pub fn new_from_secret(secret: &NodeSecret) -> X25519KeyPair {
        let private_key = scalarmult::curve25519::Scalar::from_slice(&secret.0[..]).unwrap();
        let public_key = scalarmult::curve25519::scalarmult_base(&private_key);

        X25519KeyPair {
            private_key: X25519PrivateKey {
                scalar: private_key,
            },
            public_key: X25519PublicKey {
                group_element: public_key,
            },
        }
    }
}

pub const INITSECRETBYTES: usize = 32;

pub struct InitSecret(pub [u8; INITSECRETBYTES]);

#[derive(PartialEq, Clone)]
pub struct LeafKey {
    pub private_key: Option<X25519PrivateKey>,
    pub public_key: X25519PublicKey,
    pub name: String,
}

#[derive(Clone)]
pub struct SignaturePublicKey {}

#[derive(Clone)]
pub struct SignaturePrivateKey {}

#[derive(Clone)]
pub struct SignatureScheme {}

#[derive(Clone)]
pub struct Signature {}

pub type CipherSuite = u16;

pub const AES126GCM_P256_SHA256: CipherSuite = 0;
pub const AES126GCM_CURVE25519_SHA256: CipherSuite = 1;

#[derive(Clone)]
pub struct UserInitKey {
    pub cipher_suite: Vec<CipherSuite>,
    pub init_keys: Vec<X25519PublicKey>, /* [2^16-1] */
    pub identity_key: SignaturePublicKey,
    pub algorithm: SignatureScheme,
    pub signature: Signature,
}

// Legacy stuff
// --------------------------------------------------------------

/*

pub struct GroupInitKey {
    epoch: u32,
    group_size: u32,
    group_id: Vec<u8>, /* <0..2^16-1>; */
    cipher_suite: CipherSuite,
    add_key: X25519PublicKey,
    //identity_frontier: Vec<MerkleNode>, /* <0..2^16-1>; */
    ratchet_frontier: Vec<X25519PublicKey>, /* <0..2^16-1>; */
}

*/

#[test]
fn test_constants() {
    use sodiumoxide::crypto::hash::sha256::*;
    assert_eq!(DIGESTBYTES, NODESECRETBYTES);
}
