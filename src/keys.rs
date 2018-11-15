// Wire
// Copyright (C) 2018 Wire Swiss GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use codec::*;
use sodiumoxide::crypto::scalarmult;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::randombytes;
use tree::*;
use utils::*;

pub const PUBLICKEYBYTES: usize = 32;
pub const PRIVATEKEYBYTES: usize = 32;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Zero {}

#[derive(Hash, PartialEq, Clone, Copy, Debug)]
pub struct X25519PublicKey([u8; PUBLICKEYBYTES]);

pub const X25519PUBLICKEYBYTES: usize = scalarmult::GROUPELEMENTBYTES;

impl X25519PublicKey {
    pub fn from_slice(bytes: &[u8]) -> X25519PublicKey {
        let mut inner = <[u8; X25519PRIVATEKEYBYTES]>::default();
        inner.copy_from_slice(&bytes[..X25519PUBLICKEYBYTES]);
        X25519PublicKey(inner)
    }
}

impl Codec for X25519PublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.0);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let mut value = [0u8; X25519PUBLICKEYBYTES];
        value.clone_from_slice(&decode_vec_u8(cursor)?[..X25519PUBLICKEYBYTES]);
        Ok(X25519PublicKey(value))
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct X25519PrivateKey([u8; PRIVATEKEYBYTES]);

pub const X25519PRIVATEKEYBYTES: usize = scalarmult::SCALARBYTES;

impl X25519PrivateKey {
    pub fn shared_secret(&self, p: &X25519PublicKey) -> Result<[u8; 32], Zero> {
        let group_element = scalarmult::curve25519::GroupElement::from_slice(&p.0).unwrap();
        let scalar = scalarmult::curve25519::Scalar::from_slice(&self.0).unwrap();
        scalarmult::curve25519::scalarmult(&scalar, &group_element)
            .map(|ge| ge.0)
            .map_err(|()| Zero {})
    }
    pub fn derive_public_key(&self) -> X25519PublicKey {
        let scalar = scalarmult::curve25519::Scalar::from_slice(&self.0).unwrap();
        X25519PublicKey(scalarmult::curve25519::scalarmult_base(&scalar).0)
    }
    pub fn from_slice(bytes: &[u8]) -> X25519PrivateKey {
        let mut inner = <[u8; X25519PRIVATEKEYBYTES]>::default();
        inner.copy_from_slice(&bytes[..X25519PRIVATEKEYBYTES]);
        X25519PrivateKey(inner)
    }
    pub fn to_bytes(&self) -> [u8; PRIVATEKEYBYTES] {
        self.0
    }
}

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        erase(&mut self.0)
    }
}

impl Codec for X25519PrivateKey {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.0);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let mut value = [0u8; PRIVATEKEYBYTES];
        value.clone_from_slice(&decode_vec_u8(cursor)?[..PRIVATEKEYBYTES]);
        Ok(X25519PrivateKey(value))
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
            private_key: X25519PrivateKey(private_key.0),
            public_key: X25519PublicKey(public_key.0),
        }
    }
    pub fn new_from_secret(secret: &NodeSecret) -> X25519KeyPair {
        let private_key = scalarmult::curve25519::Scalar::from_slice(&secret.0[..]).unwrap();
        let public_key = scalarmult::curve25519::scalarmult_base(&private_key);

        X25519KeyPair {
            private_key: X25519PrivateKey(private_key.0),
            public_key: X25519PublicKey(public_key.0),
        }
    }
}

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

impl Codec for SignaturePrivateKey {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.0);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes = decode_vec_u8(cursor)?;
        Ok(SignaturePrivateKey::from_slice(&bytes).unwrap())
    }
}

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

#[derive(Clone)]
pub struct Identity {
    pub id: Vec<u8>,
    pub public_key: SignaturePublicKey,
    private_key: SignaturePrivateKey,
}

impl Codec for Identity {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.id);
        self.public_key.encode(buffer);
        self.private_key.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let id = decode_vec_u8(cursor)?;
        let public_key = SignaturePublicKey::decode(cursor)?;
        let private_key = SignaturePrivateKey::decode(cursor)?;
        Ok(Identity {
            id,
            public_key,
            private_key,
        })
    }
}

impl Identity {
    pub fn random() -> Self {
        let id = randombytes::randombytes(4).to_vec();
        let (public_key, private_key) = ed25519::gen_keypair();
        Self {
            id,
            public_key,
            private_key,
        }
    }

    pub fn sign(&self, payload: &[u8]) -> Signature {
        ed25519::sign_detached(payload, &self.private_key)
    }
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        ed25519::verify_detached(signature, payload, &self.public_key)
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        erase(&mut self.private_key.0);
        erase(&mut self.public_key.0);
        erase(&mut self.id);
    }
}

pub trait Signable: Sized {
    fn unsigned_payload(&self) -> Vec<u8>;

    fn sign(&mut self, id: &Identity) -> Signature {
        id.sign(&self.unsigned_payload())
    }
    fn verify(&self, id: &Identity, signature: &Signature) -> bool {
        id.verify(&self.unsigned_payload(), signature)
    }
}

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

impl BasicCredential {
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        ed25519::verify_detached(signature, payload, &self.public_key)
    }
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
    pub cipher_suites: Vec<CipherSuite>,
    pub init_keys: Vec<X25519PublicKey>, /* [2^16-1] */
    pub identity_key: SignaturePublicKey,
    pub algorithm: SignatureScheme,
    pub signature: Signature,
}

impl UserInitKey {
    pub fn new(init_keys: &[X25519PublicKey], identity: &Identity) -> Self {
        let mut init_key = Self {
            cipher_suites: vec![AES128GCM_CURVE25519_SHA256],
            init_keys: init_keys.to_owned(),
            identity_key: identity.public_key,
            algorithm: ED25519,
            signature: Signature::from_slice(&[0u8; ed25519::SIGNATUREBYTES]).unwrap(),
        };
        init_key.signature = identity.sign(&init_key.unsigned_payload());
        init_key
    }
    pub fn self_verify(&self) -> bool {
        ed25519::verify_detached(
            &self.signature,
            &self.unsigned_payload(),
            &self.identity_key,
        )
    }
}

impl Signable for UserInitKey {
    fn unsigned_payload(&self) -> Vec<u8> {
        let buffer = &mut Vec::new();
        encode_vec_u16(buffer, &self.cipher_suites);
        encode_vec_u16(buffer, &self.init_keys);
        self.identity_key.encode(buffer);
        self.algorithm.encode(buffer);
        buffer.to_vec()
    }
}

impl Codec for UserInitKey {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.cipher_suites);
        encode_vec_u16(buffer, &self.init_keys);
        self.identity_key.encode(buffer);
        self.algorithm.encode(buffer);
        self.signature.encode(buffer);
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let cipher_suites: Vec<CipherSuite> = decode_vec_u8(cursor)?;
        let init_keys: Vec<X25519PublicKey> = decode_vec_u16(cursor)?;
        let identity_key = SignaturePublicKey::decode(cursor)?;
        let algorithm = SignatureScheme::decode(cursor)?;
        let signature = Signature::decode(cursor)?;
        Ok(UserInitKey {
            cipher_suites,
            init_keys,
            identity_key,
            algorithm,
            signature,
        })
    }
}

pub struct UserInitKeyBundle {
    pub init_key: UserInitKey,
    _private_keys: Vec<X25519PrivateKey>,
}

impl UserInitKeyBundle {
    pub fn new(identity: &Identity) -> Self {
        let kp = X25519KeyPair::new_random();
        let private_keys = vec![kp.private_key];
        let public_keys = [kp.public_key];
        let init_key = UserInitKey::new(&public_keys, identity);
        UserInitKeyBundle {
            init_key,
            _private_keys: private_keys,
        }
    }
}

impl Codec for UserInitKeyBundle {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.init_key.encode(buffer);
        encode_vec_u16(buffer, &self._private_keys);
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let init_key: UserInitKey = UserInitKey::decode(cursor)?;
        let _private_keys: Vec<X25519PrivateKey> = decode_vec_u16(cursor)?;
        Ok(UserInitKeyBundle {
            init_key,
            _private_keys,
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

#[test]
fn test_signature() {
    use utils::*;

    let payload = vec![0, 1, 2, 3];
    let pk = SignaturePublicKey::from_slice(&hex_to_bytes(
        "6f8a35bff581235d8757b2f3cea6e6bfa7c5005852ac8ccf3c63a2c45c514d0d",
    ))
    .unwrap();
    let sig = Signature::from_slice(&hex_to_bytes("4d51569eb56fc808cad8d8707110bcbf5c3daae9d394af77d48e840b2750ab15ea04c0fd30658625a20d0446fbd8ae09c6cc67f1004ed8c79818b74bef4fa107")).unwrap();
    assert!(ed25519::verify_detached(&sig, &payload, &pk));
}

#[test]
fn generate_user_init_key() {
    let (signature_public_key, signature_private_key) = ed25519::gen_keypair();
    println!(
        "Signature: Private key: {:?}, public key: {:?}",
        bytes_to_hex(&signature_private_key.0),
        bytes_to_hex(&signature_public_key.0)
    );
    let dh_kp = X25519KeyPair::new_random();
    println!(
        "X25519: Private key: {:?}, Public key: {:?}",
        bytes_to_hex(&dh_kp.private_key.0),
        bytes_to_hex(&dh_kp.public_key.0)
    );
}

#[test]
fn test_user_init_key() {
    let signature_private_key_hex =
        "AA5A90D1AA3DEECB657F43630680A0001FC910506DC8D3D363095E5E7A7D1B6C5F334D034259E2D6670D6CA8F5A937EA7CE9438259292F8872AEA6C7BB8AA2C0";
    let signature_private_key =
        ed25519::SecretKey::from_slice(&hex_to_bytes(signature_private_key_hex)).unwrap();
    let signature_public_key_hex =
        "5F334D034259E2D6670D6CA8F5A937EA7CE9438259292F8872AEA6C7BB8AA2C0";
    let signature_public_key =
        ed25519::PublicKey::from_slice(&hex_to_bytes(signature_public_key_hex)).unwrap();

    let dh_private_key_hex = "EC332FA1FFEF173E1807B2896D86F25A85231070993A3542AE582D2D563ED42C";
    let _dh_private_key = X25519PrivateKey::from_slice(&hex_to_bytes(dh_private_key_hex));

    let dh_public_key_hex = "3CB3FC6B9271B308EFEDC029502278DED42FC4AF181A44E31549F53B9BF7436C";
    let dh_public_key = X25519PublicKey::from_slice(&hex_to_bytes(dh_public_key_hex));

    let empty_signature_inner: [u8; ed25519::SIGNATUREBYTES] = [0u8; ed25519::SIGNATUREBYTES];
    let empty_signature = ed25519::Signature::from_slice(&empty_signature_inner).unwrap();

    let mut uik = UserInitKey {
        cipher_suites: vec![AES128GCM_CURVE25519_SHA256],
        init_keys: vec![dh_public_key],
        identity_key: signature_public_key,
        algorithm: ED25519,
        signature: empty_signature,
    };

    let signature = ed25519::sign_detached(&uik.unsigned_payload(), &signature_private_key);
    uik.signature = signature;

    let mut buffer = Vec::new();
    uik.encode(&mut buffer);

    let uik_hex = "0200010021203CB3FC6B9271B308EFEDC029502278DED42FC4AF181A44E31549F53B9BF7436C205F334D034259E2D6670D6CA8F5A937EA7CE9438259292F8872AEA6C7BB8AA2C0000040F5CAFFED4C5E5F5F0E8B1807A09112268A195252A868AB1B9D5E930D2484189918F4989030DC5291BBFB0711E95529F3E54470BA31F465892886D511B74FF807";

    assert_eq!(bytes_to_hex(&buffer), uik_hex);
}
