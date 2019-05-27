// Wire
// Copyright (C) 2019 Wire Swiss GmbH
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
use crypto::schedule::*;
use crypto::{aesgcm, hkdf};
use utils::*;

const APPLICATION_SECRET_SIZE: usize = 32;

pub struct ApplicationPlaintext {
    content: Vec<u8>,   // opaque content<0..2^32-1>;
    signature: Vec<u8>, // opaque signature<0..2^16-1>;
    zeros: Vec<u8>,     // uint8 zeros[length_of_padding];
}

pub struct ApplicationMessage {
    group: Vec<u8>,             // uint8  group[32];
    epoch: u32,                 // uint32 epoch;
    generation: u32,            // uint32 generation;
    sender: u32,                // uint32 sender;
    encrypted_content: Vec<u8>, // opaque encrypted_content<0..2^32-1>;
}

pub struct SignatureContent {
    group: Vec<u8>,   // uint8  group[32];
    epoch: u32,       // uint32 epoch;
    generation: u32,  // uint32 generation;
    sender: u32,      // uint32 sender;
    content: Vec<u8>, // opaque encrypted_content<0..2^32-1>;
}

impl ApplicationMessage {}

pub fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let mut prk_value = [0u8; APPLICATION_SECRET_SIZE];
    prk_value.clone_from_slice(&secret[..32]);
    let prk = hkdf::Prk(prk_value);

    let hkdf_label = HkdfLabel::new(context, label, 32);
    let state = &hkdf_label.serialize();

    println!("HKDFLabel for label '{}': {}", label, bytes_to_hex(&state));

    let info = hkdf::Info(state);
    hkdf::expand(prk, info, length)
}

#[derive(Clone)]
pub struct StageSecrets {
    pub nonce: [u8; aesgcm::NONCEBYTES],
    pub key: [u8; aesgcm::AES128KEYBYTES],
}

impl StageSecrets {
    pub fn new(nonce_bytes: &[u8], key_bytes: &[u8]) -> Self {
        let mut nonce = [0u8; aesgcm::NONCEBYTES];
        let mut key = [0u8; aesgcm::AES128KEYBYTES];
        nonce.clone_from_slice(&nonce_bytes[..aesgcm::NONCEBYTES]);
        key.clone_from_slice(&key_bytes[..aesgcm::AES128KEYBYTES]);
        Self { nonce, key }
    }
}

impl Codec for StageSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.nonce);
        encode_vec_u8(buffer, &self.key);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let mut nonce = <[u8; aesgcm::NONCEBYTES]>::default();
        let mut key = <[u8; aesgcm::AES128KEYBYTES]>::default();
        nonce.clone_from_slice(&decode_vec_u8(cursor)?);
        key.clone_from_slice(&decode_vec_u8(cursor)?);
        Ok(StageSecrets { nonce, key })
    }
}

#[derive(Debug)]
pub enum StageError {
    TooFarInThePast,
    TooFarInTheFuture,
}

pub struct SenderApplicationSecret {
    value: [u8; APPLICATION_SECRET_SIZE],
    sender: u32,
    stage: usize,
}

impl SenderApplicationSecret {
    pub fn from_bytes_for_sender(bytes: &[u8], sender: u32) -> Self {
        let mut init_value = [0u8; APPLICATION_SECRET_SIZE];
        init_value.clone_from_slice(&bytes[..APPLICATION_SECRET_SIZE]);
        let stage = 0;
        let mut context = Vec::new();
        (sender as u32).encode(&mut context);

        let new_value = hkdf_expand_label(bytes, "app sender", &context, APPLICATION_SECRET_SIZE);
        let mut value = [0u8; APPLICATION_SECRET_SIZE];
        value.clone_from_slice(&new_value[..APPLICATION_SECRET_SIZE]);
        Self {
            value,
            sender,
            stage,
        }
    }
    pub fn get_secret_for_stage(&mut self, stage: usize) -> Result<StageSecrets, StageError> {
        if stage <= self.stage {
            return Err(StageError::TooFarInThePast);
        }
        let steps = stage - self.stage;
        if steps > 1000 {
            return Err(StageError::TooFarInTheFuture);
        }

        let nonce_bytes = [0u8; aesgcm::NONCEBYTES];
        let key_bytes = [0u8; aesgcm::AES128KEYBYTES];
        let mut stage_secrets = StageSecrets::new(&nonce_bytes, &key_bytes);

        for _ in 0..steps {
            let mut context = Vec::new();
            (self.sender as u32).encode(&mut context);

            let nonce = hkdf_expand_label(&self.value, "nonce", &[], aesgcm::NONCEBYTES);
            let key = hkdf_expand_label(&self.value, "key", &[], aesgcm::AES128KEYBYTES);
            stage_secrets = StageSecrets::new(&nonce, &key);
            let next_value =
                hkdf_expand_label(&self.value, "app sender", &context, APPLICATION_SECRET_SIZE);
            self.value.copy_from_slice(&next_value);
            self.stage += 1;
        }

        Ok(stage_secrets)
    }
}
