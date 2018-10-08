use codec::*;
use sodiumoxide::crypto::scalarmult;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::randombytes;
use sodiumoxide::utils;
use std::hash::{Hash, Hasher};
use tree::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Zero {}

#[derive(Clone, Debug)]
pub struct X25519PublicKey {
    pub group_element: scalarmult::curve25519::GroupElement,
}

impl Hash for X25519PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.group_element.0.hash(state);
    }
}

impl PartialEq for X25519PublicKey {
    fn eq(&self, other: &X25519PublicKey) -> bool {
        self.group_element.0 == other.group_element.0
    }
}

impl Codec for X25519PublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.group_element.0);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes = decode_vec_u8(cursor)?;
        Ok(X25519PublicKey {
            group_element: scalarmult::curve25519::GroupElement::from_slice(&bytes).unwrap(),
        })
    }
}

#[derive(PartialEq, Clone, Debug)]
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

pub type SignaturePublicKey = ed25519::PublicKey;

impl Codec for SignaturePublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.0);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes = decode_vec_u8(cursor)?;
        Ok(SignaturePublicKey::from_slice(&bytes).unwrap())
    }
}

pub type SignaturePrivateKey = ed25519::SecretKey;

pub type Signature = ed25519::Signature;

impl Codec for Signature {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.0);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes = decode_vec_u8(cursor)?;
        Ok(Signature::from_slice(&bytes).unwrap())
    }
}

pub type SignatureScheme = u16;

pub const ED25519: SignatureScheme = 0;

#[repr(u8)]
pub enum CredentialType {
    Basic = 0,
    X509 = 1,
    Default = 255,
}

#[derive(Clone)]
pub struct BasicCredential {
    pub identity: Vec<u8>, // <0..2^16-1>;
    pub public_key: SignaturePublicKey,
}

impl Codec for BasicCredential {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.identity);
        self.public_key.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let identity = decode_vec_u8(cursor)?;
        let public_key = SignaturePublicKey::decode(cursor)?;
        Ok(BasicCredential {
            identity,
            public_key,
        })
    }
}

pub type CipherSuite = u16;

pub const AES128GCM_P256_SHA256: CipherSuite = 0;
pub const AES128GCM_CURVE25519_SHA256: CipherSuite = 1;

#[derive(Clone)]
pub struct UserInitKey {
    pub cipher_suite: Vec<CipherSuite>,
    pub init_keys: Vec<X25519PublicKey>, /* [2^16-1] */
    pub identity_key: SignaturePublicKey,
    pub algorithm: SignatureScheme,
    pub signature: Signature,
}

impl UserInitKey {
    pub fn fake() -> Self {
        // FIXME
        UserInitKey {
            cipher_suite: vec![0],
            init_keys: vec![],
            identity_key: SignaturePublicKey::from_slice(&[0u8; ed25519::PUBLICKEYBYTES]).unwrap(),
            algorithm: ED25519,
            signature: Signature::from_slice(&[0u8; ed25519::SIGNATUREBYTES]).unwrap(),
        }
    }
    pub fn sign() {}
    pub fn verify() -> bool {
        true // FIXME
    }
    pub fn unsigned_payload(&self) -> Cursor {
        let buffer = vec![];
        let cursor: Cursor = Cursor::new(&buffer);

        cursor
    }
}

impl Codec for UserInitKey {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u16(buffer, &self.cipher_suite);
        encode_vec_u16(buffer, &self.init_keys);
        self.identity_key.encode(buffer);
        self.algorithm.encode(buffer);
        self.signature.encode(buffer);
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let cipher_suite: Vec<CipherSuite> = decode_vec_u16(cursor)?;
        let init_keys: Vec<X25519PublicKey> = decode_vec_u16(cursor)?;
        let identity_key = SignaturePublicKey::decode(cursor)?;
        let algorithm = SignatureScheme::decode(cursor)?;
        let signature = Signature::decode(cursor)?;
        Ok(UserInitKey {
            cipher_suite,
            init_keys,
            identity_key,
            algorithm,
            signature,
        })
    }
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
