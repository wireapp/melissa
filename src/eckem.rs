extern crate sodiumoxide;

use aesgcm;
use keys::*;
use sodiumoxide::crypto::aead;
use std::*;

pub struct X25519AES {}
#[derive(Clone)]
pub struct X25519AESCiphertext {
    public_key: X25519PublicKey,
    sealed_box: Vec<u8>,
}

impl X25519AES {
    pub fn encrypt(public_key: &X25519PublicKey, payload: &[u8]) -> X25519AESCiphertext {
        let kp = X25519KeyPair::new_random();
        let secret = kp.private_key.shared_secret(public_key).unwrap();
        let key = aesgcm::Key::from_slice(&secret[..]);
        let sealed_box = aesgcm::seal(payload, &key);

        X25519AESCiphertext {
            public_key: kp.public_key,
            sealed_box,
        }
    }
    pub fn decrypt(private_key: &X25519PrivateKey, ciphertext: &X25519AESCiphertext) -> Vec<u8> {
        let secret = private_key.shared_secret(&ciphertext.public_key).unwrap();
        let key = aesgcm::Key::from_slice(&secret[..]);
        aesgcm::open(&ciphertext.sealed_box[..], &key)
    }
}

#[test]
fn encrypt_decrypt_x25519_aes() {
    let kp = X25519KeyPair::new_random();
    let cleartext = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let encrypted = X25519AES::encrypt(&kp.public_key, &cleartext);
    let decrypted = X25519AES::decrypt(&kp.private_key, &encrypted);

    assert_eq!(cleartext, decrypted);
}

#[test]
fn encrypt_decrypt_x25519_aes_random() {
    use sodiumoxide::randombytes;
    for _ in 0..1000 {
        let kp = X25519KeyPair::new_random();
        let cleartext = randombytes::randombytes(1000);

        let encrypted = X25519AES::encrypt(&kp.public_key, &cleartext);
        let decrypted = X25519AES::decrypt(&kp.private_key, &encrypted);

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
