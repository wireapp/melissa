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

use libsodium_sys::{
    crypto_aead_aes256gcm_decrypt_detached, crypto_aead_aes256gcm_encrypt_detached,
};
use ring::aead as ring_aead;
use sodiumoxide::randombytes;
use std::*;
use utils::*;

pub enum ALGORITHM {
    AES128GCM,
    AES256GCM,
}

#[derive(Debug)]
pub enum AesError {
    EncryptionError,
    DecryptionError,
}

pub const NONCEBYTES: usize = 12;
pub const AES128KEYBYTES: usize = 16;
pub const AES256KEYBYTES: usize = 32;
pub const TAGBYTES: usize = 16;

pub struct Nonce(pub [u8; NONCEBYTES]);

impl Nonce {
    pub fn new_random() -> Nonce {
        let random_bytes = randombytes::randombytes(NONCEBYTES);
        let mut bytes: [u8; NONCEBYTES] = [0u8; NONCEBYTES];
        bytes[..NONCEBYTES].clone_from_slice(&random_bytes[..NONCEBYTES]);
        Nonce(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Nonce {
        assert_eq!(slice.len(), NONCEBYTES);
        let mut bytes = [0u8; NONCEBYTES];
        bytes.copy_from_slice(slice);
        Nonce(bytes)
    }
}

pub struct Aes128Key(pub [u8; AES128KEYBYTES]);

impl Aes128Key {
    pub fn from_slice(slice: &[u8]) -> Aes128Key {
        assert_eq!(slice.len(), AES128KEYBYTES);
        let mut key = [0u8; AES128KEYBYTES];
        key[..AES128KEYBYTES].clone_from_slice(&slice[..AES128KEYBYTES]);
        Aes128Key(key)
    }
}

impl From<Vec<u8>> for Aes128Key {
    fn from(v: Vec<u8>) -> Aes128Key {
        Aes128Key::from_slice(v.as_slice())
    }
}

impl Drop for Aes128Key {
    fn drop(&mut self) {
        erase(&mut self.0)
    }
}

pub struct Aes256Key(pub [u8; AES256KEYBYTES]);

impl Aes256Key {
    pub fn from_slice(slice: &[u8]) -> Aes256Key {
        assert_eq!(slice.len(), AES256KEYBYTES);
        let mut key = [0u8; AES256KEYBYTES];
        key[..AES256KEYBYTES].clone_from_slice(&slice[..AES256KEYBYTES]);
        Aes256Key(key)
    }
}

impl From<Vec<u8>> for Aes256Key {
    fn from(v: Vec<u8>) -> Aes256Key {
        Aes256Key::from_slice(v.as_slice())
    }
}

impl Drop for Aes256Key {
    fn drop(&mut self) {
        erase(&mut self.0)
    }
}

pub fn aes_128_seal(payload: &[u8], key: &Aes128Key, nonce: &Nonce) -> Result<Vec<u8>, AesError> {
    let sealing_key = ring_aead::SealingKey::new(&ring_aead::AES_128_GCM, &key.0).unwrap();
    let mut buffer: Vec<u8> = Vec::with_capacity(payload.len() + ring_aead::MAX_TAG_LEN);
    for byte in payload {
        buffer.push(*byte);
    }
    for _ in 0..ring_aead::MAX_TAG_LEN {
        buffer.push(0);
    }
    match ring_aead::seal_in_place(
        &sealing_key,
        &nonce.0,
        &[],
        &mut buffer,
        ring_aead::MAX_TAG_LEN,
    ) {
        Ok(size) => Ok(buffer[..size].to_vec()),
        Err(_) => Err(AesError::EncryptionError),
    }
}

pub fn aes_128_open(
    sealed_box: &[u8],
    key: &Aes128Key,
    nonce: &Nonce,
) -> Result<Vec<u8>, AesError> {
    let opening_key = ring_aead::OpeningKey::new(&ring_aead::AES_128_GCM, &key.0).unwrap();
    let mut buffer: Vec<u8> = Vec::with_capacity(sealed_box.len());
    for byte in sealed_box {
        buffer.push(*byte);
    }
    match ring_aead::open_in_place(&opening_key, &nonce.0, &[], 0, &mut buffer) {
        Ok(bytes) => Ok(bytes.to_vec()),
        Err(_) => Err(AesError::DecryptionError),
    }
}

pub fn aes_256_seal(payload: &[u8], key: &Aes256Key) -> Result<Vec<u8>, AesError> {
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

pub fn aes_256_open(sealed_box: &[u8], key: &Aes256Key) -> Result<Vec<u8>, AesError> {
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

    // AES128
    let key: Aes128Key = Aes128Key::from(randombytes::randombytes(AES128KEYBYTES));
    let nonce = Nonce::new_random();
    let encrypted = aes_128_seal(&payload, &key, &nonce).unwrap();
    let decrypted = aes_128_open(&encrypted, &key, &nonce).unwrap();
    assert_eq!(decrypted, payload);

    // AES256
    let key: Aes256Key = Aes256Key::from(randombytes::randombytes(AES256KEYBYTES));
    let encrypted = aes_256_seal(&payload, &key).unwrap();
    let decrypted = aes_256_open(&encrypted, &key).unwrap();
    assert_eq!(decrypted, payload);
}
