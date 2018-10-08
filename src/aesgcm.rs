extern crate libsodium_sys;
extern crate sodiumoxide;

use libsodium_sys::{
    crypto_aead_aes256gcm_ABYTES, crypto_aead_aes256gcm_NPUBBYTES,
    crypto_aead_aes256gcm_decrypt_detached, crypto_aead_aes256gcm_encrypt_detached,
};
use sodiumoxide::randombytes;
use std::*;

#[derive(Debug)]
pub enum AesError {
    EncryptionError,
    DecryptionError,
}

pub const NONCEBYTES: usize = crypto_aead_aes256gcm_NPUBBYTES as usize;
pub const KEYBYTES: usize = 32;
pub const TAGBYTES: usize = crypto_aead_aes256gcm_ABYTES as usize;

pub struct Nonce(pub [u8; NONCEBYTES]);

impl Nonce {
    pub fn new_random() -> Nonce {
        let random_bytes = randombytes::randombytes(NONCEBYTES);
        let mut bytes: [u8; NONCEBYTES] = [0u8; NONCEBYTES];
        bytes[..NONCEBYTES].clone_from_slice(&random_bytes[..NONCEBYTES]);
        Nonce(bytes)
    }
}

pub struct Key(pub [u8; KEYBYTES]);

impl Key {
    pub fn from_slice(slice: &[u8]) -> Key {
        assert_eq!(slice.len(), KEYBYTES);
        let mut key = [0u8; KEYBYTES];
        key[..KEYBYTES].clone_from_slice(&slice[..KEYBYTES]);
        Key(key)
    }
}

impl From<Vec<u8>> for Key {
    fn from(v: Vec<u8>) -> Key {
        assert_eq!(v.len(), KEYBYTES);
        let mut key = [0u8; KEYBYTES];
        key[..KEYBYTES].clone_from_slice(&v[..KEYBYTES]);
        Key(key)
    }
}

pub fn seal(payload: &[u8], key: &Key) -> Result<Vec<u8>, AesError> {
    let nonce = Nonce::new_random();
    let mut ciphertext: Vec<u8> = vec![0; payload.len()];
    let mut tag: Vec<u8> = vec![0; TAGBYTES];
    let mut maclen: u64 = 0;
    let mut sealed_box = Vec::with_capacity(NONCEBYTES + TAGBYTES + payload.len());
    unsafe {
        crypto_aead_aes256gcm_encrypt_detached(
            ciphertext.as_mut_ptr(),
            tag.as_mut_ptr(),
            &mut maclen,
            payload.as_ptr(),
            payload.len() as u64,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            nonce.0.as_ptr(),
            key.0.as_ptr(),
        );
    }
    if maclen != TAGBYTES as u64 {
        return Err(AesError::EncryptionError);
    }
    sealed_box.extend_from_slice(&nonce.0);
    sealed_box.append(&mut ciphertext);
    sealed_box.append(&mut tag);
    if sealed_box.len() != (NONCEBYTES + TAGBYTES + payload.len()) {
        return Err(AesError::EncryptionError);
    }
    Ok(sealed_box)
}

pub fn open(sealed_box: &[u8], key: &Key) -> Result<Vec<u8>, AesError> {
    let sb_len = sealed_box.len();
    let payload_len = sb_len - NONCEBYTES - TAGBYTES;
    if sb_len <= (NONCEBYTES + TAGBYTES) {
        return Err(AesError::DecryptionError);
    }
    let (nonce, attached) = sealed_box.split_at(NONCEBYTES);
    let (ciphertext, tag) = attached.split_at(payload_len);
    let mut payload = vec![0; payload_len];

    unsafe {
        let r = crypto_aead_aes256gcm_decrypt_detached(
            payload.as_mut_ptr(),
            ptr::null_mut(),
            ciphertext[..].as_ptr(),
            ciphertext.len() as u64,
            tag[..].as_ptr(),
            ptr::null_mut(),
            0,
            nonce.as_ptr(),
            key.0.as_ptr(),
        );
        if r != 0 {
            return Err(AesError::DecryptionError);
        }
    }
    Ok(payload)
}

#[test]
fn seal_open() {
    let payload = vec![1, 2, 3];
    let key: Key = Key::from(randombytes::randombytes(KEYBYTES));
    let encrypted = seal(&payload, &key).unwrap();
    let decrypted = open(&encrypted, &key).unwrap();
    assert_eq!(decrypted, payload);
}
