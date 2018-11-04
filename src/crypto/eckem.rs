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
use crypto::aesgcm;
use crypto::hkdf;
use keys::*;
use sodiumoxide::crypto::aead;
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
    let prk = hkdf::Prk::from_slice(&shared_secret).unwrap();
    let key_hkdf = hkdf::expand(prk, hkdf::Info(&key_label_str), aesgcm::AES128KEYBYTES);
    let ecies_key: aesgcm::Aes128Key = aesgcm::Aes128Key::from_slice(&key_hkdf);
    let mut nonce_label_str = b"mls10 ecies nonce".to_vec();
    nonce_label_str.push(0x01);
    let prk = hkdf::Prk::from_slice(&shared_secret).unwrap();
    let nonce_hkdf = hkdf::expand(prk, hkdf::Info(&nonce_label_str), aesgcm::NONCEBYTES);
    let ecies_nonce: aesgcm::Nonce = aesgcm::Nonce::from_slice(&nonce_hkdf);
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

#[test]
fn generate_ecies_secrets() {
    use utils::*;

    let shared_secret = sodiumoxide::randombytes::randombytes(32);

    let (key, nonce) = derive_ecies_secrets(&shared_secret);

    println!("Shared secret: {}", bytes_to_hex(&shared_secret));
    println!("Key: {}", bytes_to_hex(&key.0));
    println!("Nonce: {}", bytes_to_hex(&nonce.0));
}

#[test]
fn test_ecies_secrets() {
    use utils::*;

    let shared_secret_hex = "626409A3109BC704CA0B39BBC7F9CB3748904509E5A4564B66B2A10B315BC6D5";
    let shared_secret = hex_to_bytes(&shared_secret_hex);

    let key_hex = "2BF6DE51B5C8CD8E45EA63B4B4D997DF";
    let mut key_inner = <[u8; 16]>::default();
    key_inner.copy_from_slice(&hex_to_bytes(&key_hex)[..16]);
    let key = aesgcm::Aes128Key(key_inner);

    let nonce_hex = "E66BE7FD5C91BB999D7903D9";
    let mut nonce_inner = <[u8; 12]>::default();
    nonce_inner.copy_from_slice(&hex_to_bytes(&nonce_hex)[..12]);
    let nonce = aesgcm::Nonce(nonce_inner);

    assert_eq!(derive_ecies_secrets(&shared_secret), (key, nonce));
}

#[test]
fn test_eckem() {
    use utils::*;

    let alice_dh_private_key_hex =
        "5D43BE92D01AAD353B9B4B1DC32E6C828B00DD20B46BDEB98976E13D881DC39A";
    let alice_dh_private_key =
        X25519PrivateKey::from_slice(&hex_to_bytes(alice_dh_private_key_hex));

    let alice_dh_public_key_hex =
        "626848EAB66583E12FB94577D2399D32B1EA13D2E3B9EC07C9D54778F9E27910";
    let alice_dh_public_key = X25519PublicKey::from_slice(&hex_to_bytes(alice_dh_public_key_hex));

    let bob_dh_private_key_hex = "FF629FC551E4B0657172E992AC543E89E0EB12EB11A8B413F140D88808B0EC40";
    let _bob_dh_private_key = X25519PrivateKey::from_slice(&hex_to_bytes(bob_dh_private_key_hex));

    let bob_dh_public_key_hex = "A724AB6198B4D07A3E1E4FD788EF73BF8C0E8120AC7DA4C228948D408943D774";
    let bob_dh_public_key = X25519PublicKey::from_slice(&hex_to_bytes(bob_dh_public_key_hex));

    let cleartext = hex_to_bytes("00010203040506070809");

    let ciphertext = hex_to_bytes("8127F756973BF391AE3B0891332864D367787406F306C7DD3175");

    let alice_kp = X25519KeyPair {
        private_key: alice_dh_private_key,
        public_key: alice_dh_public_key,
    };

    let secret = alice_kp
        .private_key
        .shared_secret(&bob_dh_public_key)
        .unwrap();
    let (key, nonce) = derive_ecies_secrets(&secret);
    let sealed_box = aesgcm::aes_128_seal(&cleartext, &key, &nonce).unwrap();

    assert_eq!(&sealed_box, &ciphertext);
}
