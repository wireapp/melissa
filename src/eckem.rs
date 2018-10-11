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

use aesgcm;
use codec::*;
use keys::*;
use sodiumoxide::crypto::aead;
use sodiumoxide::crypto::auth;
use std::*;

pub type EcKemError = aesgcm::AesError;

pub struct X25519AES {}
#[derive(Clone, Debug, Hash)]
pub struct X25519AESCiphertext {
    public_key: X25519PublicKey,
    sealed_box: Vec<u8>,
}

impl Codec for X25519AESCiphertext {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.public_key.encode(buffer);
        encode_vec_u8(buffer, &self.sealed_box);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let public_key = X25519PublicKey::decode(cursor)?;
        let sealed_box = decode_vec_u8(cursor)?;
        Ok(X25519AESCiphertext {
            public_key,
            sealed_box,
        })
    }
}

pub fn derive_ecies_secrets(shared_secret: &[u8]) -> (aesgcm::Aes128Key, aesgcm::Nonce) {
    let mut key_label_str = b"mls10 ecies key".to_vec();
    key_label_str.push(0x01);
    let key_key = auth::hmacsha256::Key::from_slice(shared_secret).unwrap();
    let key_tag = auth::hmacsha256::authenticate(&key_label_str, &key_key);
    let key_truncated_hmac = &key_tag[0..aesgcm::AES128KEYBYTES];
    let ecies_key: aesgcm::Aes128Key = aesgcm::Aes128Key::from_slice(key_truncated_hmac);
    let mut nonce_label_str = b"mls10 ecies nonce".to_vec();
    nonce_label_str.push(0x01);
    let nonce_key = auth::hmacsha256::Key::from_slice(shared_secret).unwrap();
    let nonce_tag = auth::hmacsha256::authenticate(&nonce_label_str, &nonce_key);
    let ecies_nonce: aesgcm::Nonce = aesgcm::Nonce::from_slice(&nonce_tag[0..aesgcm::NONCEBYTES]);
    (ecies_key, ecies_nonce)
}

impl X25519AES {
    pub fn encrypt(
        public_key: &X25519PublicKey,
        payload: &[u8],
    ) -> Result<X25519AESCiphertext, EcKemError> {
        let kp = X25519KeyPair::new_random();
        let secret = kp.private_key.shared_secret(public_key).unwrap();
        let (key, nonce) = derive_ecies_secrets(&secret);
        let sealed_box = aesgcm::aes_128_seal(payload, &key, &nonce)?;
        Ok(X25519AESCiphertext {
            public_key: kp.public_key,
            sealed_box,
        })
    }
    pub fn decrypt(
        private_key: &X25519PrivateKey,
        ciphertext: &X25519AESCiphertext,
    ) -> Result<Vec<u8>, EcKemError> {
        let secret = private_key.shared_secret(&ciphertext.public_key).unwrap();
        let (key, nonce) = derive_ecies_secrets(&secret);
        aesgcm::aes_128_open(&ciphertext.sealed_box[..], &key, &nonce)
    }
}

#[test]
fn encrypt_decrypt_x25519_aes() {
    let kp = X25519KeyPair::new_random();
    let cleartext = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let encrypted = X25519AES::encrypt(&kp.public_key, &cleartext).unwrap();
    let decrypted = X25519AES::decrypt(&kp.private_key, &encrypted).unwrap();

    assert_eq!(cleartext, decrypted);
}

#[test]
fn encrypt_decrypt_x25519_aes_random() {
    use sodiumoxide::randombytes;
    for _ in 0..1000 {
        let kp = X25519KeyPair::new_random();
        let cleartext = randombytes::randombytes(1000);

        let encrypted = X25519AES::encrypt(&kp.public_key, &cleartext).unwrap();
        let decrypted = X25519AES::decrypt(&kp.private_key, &encrypted).unwrap();

        assert_eq!(cleartext, decrypted);
    }
}

pub struct X25519ChaCha20 {}
pub struct X25519ChaCha20Ciphertext {
    public_key: X25519PublicKey,
    nonce: aead::Nonce,
    ciphertext: Vec<u8>,
}

impl X25519ChaCha20 {
    pub fn encrypt(public_key: &X25519PublicKey, payload: &[u8]) -> X25519ChaCha20Ciphertext {
        let kp = X25519KeyPair::new_random();
        let secret = kp.private_key.shared_secret(public_key).unwrap();
        let key = aead::Key::from_slice(&secret[..]).unwrap();
        let nonce = aead::gen_nonce();
        let ciphertext = aead::seal(payload, None, &nonce, &key);
        X25519ChaCha20Ciphertext {
            public_key: kp.public_key,
            nonce,
            ciphertext,
        }
    }

    pub fn decrypt(
        private_key: &X25519PrivateKey,
        ciphertext: &X25519ChaCha20Ciphertext,
    ) -> Vec<u8> {
        let secret = private_key.shared_secret(&ciphertext.public_key).unwrap();
        let key = aead::Key::from_slice(&secret[..]).unwrap();
        aead::open(&ciphertext.ciphertext, None, &ciphertext.nonce, &key).unwrap()
    }
}

#[test]
fn encrypt_decrypt_x25519_chacha20() {
    let kp = X25519KeyPair::new_random();
    let cleartext = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let encrypted = X25519ChaCha20::encrypt(&kp.public_key, &cleartext);
    let decrypted = X25519ChaCha20::decrypt(&kp.private_key, &encrypted);

    assert_eq!(cleartext, decrypted);
}

#[test]
fn encrypt_decrypt_x25519_chacha20_random() {
    use sodiumoxide::randombytes;
    for _ in 0..1000 {
        let kp = X25519KeyPair::new_random();
        let cleartext = randombytes::randombytes(1000);

        let encrypted = X25519ChaCha20::encrypt(&kp.public_key, &cleartext);
        let decrypted = X25519ChaCha20::decrypt(&kp.private_key, &encrypted);

        assert_eq!(cleartext, decrypted);
    }
}
