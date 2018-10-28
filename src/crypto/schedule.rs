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
use crypto::hkdf;
use utils::*;

pub fn derive_secret(secret: hkdf::Prk, label: &str, group_state: &[u8]) -> Vec<u8> {
    let hkdf_label = HkdfLabel::new(group_state, label);
    let state = &hkdf_label.serialize();
    let info = hkdf::Info(state);
    hkdf::expand(secret, info, 32)
}

pub const INITSECRETBYTES: usize = 32;

#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct InitSecret([u8; INITSECRETBYTES]);

impl InitSecret {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut init_secret = InitSecret::default();
        init_secret.0.clone_from_slice(bytes);
        init_secret
    }
    pub fn update(&mut self, update_secret: &[u8], group_state: &[u8]) -> EpochSecrets {
        let current_init_secret = self.0;
        let salt = hkdf::Salt(&current_init_secret);
        let ikm = hkdf::Input(update_secret);
        let epoch_secret = hkdf::extract(salt, ikm);

        let application_secret = derive_secret(epoch_secret, "app", group_state);
        let confirmation_key = derive_secret(epoch_secret, "confirm", group_state);
        let init_secret = derive_secret(epoch_secret, "init", group_state);
        let epoch_secrets = EpochSecrets::new(&application_secret, &confirmation_key);
        self.0.copy_from_slice(&init_secret);

        epoch_secrets
    }
}

impl Codec for InitSecret {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.0);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes = decode_vec_u8(cursor)?;
        Ok(InitSecret::from_bytes(&bytes))
    }
}

impl Drop for InitSecret {
    fn drop(&mut self) {
        erase(&mut self.0)
    }
}

#[derive(Clone)]
pub struct EpochSecrets {
    pub app_secret: [u8; 32],
    pub confirmation_key: [u8; 32],
}

impl EpochSecrets {
    pub fn new(app_secret_bytes: &[u8], confirmation_key_bytes: &[u8]) -> Self {
        let mut app_secret = [0u8; 32];
        let mut confirmation_key = [0u8; 32];
        app_secret.clone_from_slice(&app_secret_bytes[..32]);
        confirmation_key.clone_from_slice(&confirmation_key_bytes[..32]);
        Self {
            app_secret,
            confirmation_key,
        }
    }
}

pub struct HkdfLabel {
    length: usize,
    label: String,
    group_state: Vec<u8>,
}

impl HkdfLabel {
    pub fn new(group_state: &[u8], label: &str) -> Self {
        let full_label = "mls10 ".to_owned() + label;

        HkdfLabel {
            length: 32,
            label: full_label,
            group_state: group_state.to_vec(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        (self.length as u32).encode(&mut buffer);
        encode_vec_u8(&mut buffer, self.label.as_bytes());
        encode_vec_u32(&mut buffer, &self.group_state);
        buffer
    }
}