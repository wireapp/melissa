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
use crypto::hpke::*;
use crypto::schedule::InitSecret;
use group::*;
use keys::*;
use std::convert::From;
use tree::*;

pub enum MessageError {
    UnknownOperation,
}

pub const HANDSHAKE_WELCOME: u8 = 1;
pub const HANDSHAKE_UPDATE: u8 = 2;
pub const HANDSHAKE_ADD: u8 = 3;
pub const HANDSHAKE_REMOVE: u8 = 4;

#[derive(Clone)]
pub enum GroupOperationValue {
    Welcome(Box<Welcome>),
    Update(Update),
    Add(Add),
    Remove(Remove),
}

impl Codec for GroupOperationValue {
    fn encode(&self, buffer: &mut Vec<u8>) {
        match self {
            GroupOperationValue::Welcome(welcome) => {
                HANDSHAKE_WELCOME.encode(buffer);
                welcome.encode(buffer);
            }
            GroupOperationValue::Update(update) => {
                HANDSHAKE_UPDATE.encode(buffer);
                update.encode(buffer);
            }
            GroupOperationValue::Add(add) => {
                HANDSHAKE_ADD.encode(buffer);
                add.encode(buffer);
            }
            GroupOperationValue::Remove(remove) => {
                HANDSHAKE_REMOVE.encode(buffer);
                remove.encode(buffer);
            }
        }
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let handshake_type = cursor.take(1)?[0];
        match handshake_type {
            HANDSHAKE_WELCOME => Ok(GroupOperationValue::Welcome(Box::new(Welcome::decode(
                cursor,
            )?))),
            HANDSHAKE_UPDATE => Ok(GroupOperationValue::Update(Update::decode(cursor)?)),
            HANDSHAKE_ADD => Ok(GroupOperationValue::Add(Add::decode(cursor)?)),
            HANDSHAKE_REMOVE => Ok(GroupOperationValue::Remove(Remove::decode(cursor)?)),
            _ => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum GroupOperationType {
    Init = 0,
    Add = 1,
    Update = 2,
    Remove = 3,
    Default = 255,
}

impl From<u8> for GroupOperationType {
    fn from(value: u8) -> Self {
        match value {
            0 => GroupOperationType::Init,
            1 => GroupOperationType::Add,
            2 => GroupOperationType::Update,
            3 => GroupOperationType::Remove,
            _ => GroupOperationType::Default,
        }
    }
}

impl Codec for GroupOperationType {
    fn encode(&self, buffer: &mut Vec<u8>) {
        (*self as u8).encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(GroupOperationType::from(cursor.take(1)?[0]))
    }
}

#[derive(Clone)]
pub struct GroupOperation {
    pub msg_type: GroupOperationType,
    pub group_operation: GroupOperationValue,
    pub confirmation: u8
}

impl Codec for GroupOperation {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.msg_type.encode(buffer);
        self.group_operation.encode(buffer);
        self.confirmation.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let msg_type = GroupOperationType::decode(cursor)?;
        let group_operation = GroupOperationValue::decode(cursor)?;
        let confirmation = u8::decode(cursor)?;
        Ok(GroupOperation {
            msg_type,
            group_operation,
            confirmation
        })
    }
}

#[derive(Clone)]
pub struct Handshake {
    pub prior_epoch: GroupEpoch,
    pub operation: GroupOperation,
    pub signer_index: u32,
    pub algorithm: SignatureScheme,
    pub signature: Option<Signature>,
}

impl Signable for Handshake {
    fn unsigned_payload(&self) -> Vec<u8> {
        let buffer = &mut Vec::new();
        self.prior_epoch.encode(buffer);
        self.operation.encode(buffer);
        self.signer_index.encode(buffer);
        self.algorithm.encode(buffer);
        buffer.to_vec()
    }
}

impl Codec for Handshake {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.prior_epoch.encode(buffer);
        self.operation.encode(buffer);
        self.signer_index.encode(buffer);
        self.algorithm.encode(buffer);
        self.signature.unwrap().encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let prior_epoch = GroupEpoch::decode(cursor)?;
        let operation = GroupOperation::decode(cursor)?;
        let signer_index = u32::decode(cursor)?;
        let algorithm = SignatureScheme::decode(cursor)?;
        let signature = Option::<Signature>::decode(cursor)?;
        Ok(Handshake {
            prior_epoch,
            operation,
            signer_index,
            algorithm,
            signature,
        })
    }
}

#[derive(Clone)]
pub struct RatchetNode {
    pub public_key: X25519PublicKey,
    pub credential: Option<BasicCredential>
}

impl Codec for RatchetNode {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.public_key.encode(buffer);
        self.credential.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let public_key = X25519PublicKey::decode(cursor)?;
        let credential = Option::<BasicCredential>::decode(cursor)?;
        Ok(RatchetNode {
            public_key,
            credential
        })
    }
}

#[derive(Clone)]
pub struct Welcome {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub tree: Vec<RatchetNode>,
    pub transcript: Vec<GroupOperationValue>,
    pub init_secret: InitSecret,
    pub leaf_secret: NodeSecret,
    pub version: ProtocolVersion,
}

impl Codec for Welcome {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.group_id.encode(buffer);
        self.epoch.encode(buffer);
        encode_vec_u16(buffer, &self.tree);
        encode_vec_u16(buffer, &self.transcript);
        self.init_secret.encode(buffer);
        self.leaf_secret.encode(buffer);
        self.version.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let tree_hash = decode_vec_u16(cursor)?;
        let transcript = decode_vec_u16(cursor)?;
        let init_secret = InitSecret::decode(cursor)?;
        let leaf_secret = NodeSecret::decode(cursor)?;
        let version = ProtocolVersion::decode(cursor)?;
        Ok(Welcome {
            group_id,
            epoch,
            tree_hash,
            transcript,
            init_secret,
            leaf_secret,
            version,
        })
    }
}

#[derive(Clone, Hash)]
pub struct Update {
    pub nodes: Vec<X25519PublicKey>,
    pub path: Vec<HpkeCiphertext>,
}

impl Codec for Update {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u16(buffer, &self.nodes);
        encode_vec_u16(buffer, &self.path);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let nodes = decode_vec_u16(cursor)?;
        let path = decode_vec_u16(cursor)?;
        Ok(Update { nodes, path })
    }
}

#[derive(Clone)]
pub struct Add {
    pub nodes: Vec<X25519PublicKey>,
    pub path: Vec<HpkeCiphertext>,
    pub init_key: UserInitKey,
    pub index: u32,
}

impl Codec for Add {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u16(buffer, &self.nodes);
        encode_vec_u16(buffer, &self.path);
        self.init_key.encode(buffer);
        self.index.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let nodes = decode_vec_u16(cursor)?;
        let path = decode_vec_u16(cursor)?;
        let init_key = UserInitKey::decode(cursor)?;
        let index = u32::decode(cursor)?;
        Ok(Add {
            nodes,
            path,
            init_key,
            index
        })
    }
}

#[derive(Clone)]
pub struct Remove {
    pub removed: usize,
    pub nodes: Vec<X25519PublicKey>,
    pub path: Vec<HpkeCiphertext>,
}

impl Codec for Remove {
    fn encode(&self, buffer: &mut Vec<u8>) {
        (self.removed as u32).encode(buffer);
        encode_vec_u16(buffer, &self.nodes);
        encode_vec_u16(buffer, &self.path);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let removed = u32::decode(cursor)? as usize;
        let nodes = decode_vec_u16(cursor)?;
        let path = decode_vec_u16(cursor)?;
        Ok(Remove {
            removed,
            nodes,
            path,
        })
    }
}


#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum ContentType {
    Invalid = 0,
    Handshake = 1,
    Application = 2,
    Default = 255
}

impl From<u8> for ContentType {
    fn from(value: u8) -> Self {
        match value {
            0 => ContentType::Invalid,
            1 => ContentType::Handshake,
            2 => ContentType::Application,
            _ => ContentType::Default,
        }
    }
}

impl Codec for ContentType {
    fn encode(&self, buffer: &mut Vec<u8>) {
        (*self as u8).encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(ContentType::from(cursor.take(1)?[0]))
    }
}

#[derive(Clone)]
pub struct MLSPlaintext {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub sender: u32, 
    pub content_type: ContentType,
    pub operation: Option<GroupOperation>, //Switch
    pub application_data: Vec<u8>, //Switch
    pub signature: Signature,
}

impl Codec for MLSPlaintext {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.group_id.encode(buffer);
        self.epoch.encode(buffer);
        (self.sender as u32).encode(buffer);
        self.content_type.encode(buffer);
        self.operation.unwrap().encode(buffer);
        encode_vec_u8(buffer, &self.application_data);
        self.signature.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let sender = u32::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let operation = Option::<GroupOperation>::decode(cursor)?;
        let application_data = decode_vec_u8(cursor)?;
        let signature = Signature::decode(cursor)?;

        Ok(MLSPlaintext {
            group_id,
            epoch,
            sender,
            content_type,
            operation,
            application_data,
            signature
        })
    }
}

#[derive(Clone)]
pub struct MLSCiphertext {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub content_type: ContentType,
    pub sender_data_nonce: Vec<u8>,
    pub encrypted_sender_data: Vec<u8>,
    pub ciphertext: Vec<u32>,
}

impl Codec for MLSCiphertext {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.group_id.encode(buffer);
        self.epoch.encode(buffer);
        self.content_type.encode(buffer);
        encode_vec_u8(buffer, &self.sender_data_nonce);
        encode_vec_u8(buffer, &self.encrypted_sender_data);
        encode_vec_u32(buffer, &self.ciphertext);
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let sender_data_nonce = decode_vec_u8(cursor)?;
        let encrypted_sender_data = decode_vec_u8(cursor)?;
        let ciphertext = decode_vec_u32(cursor)?;
        Ok(MLSCiphertext{
            group_id,
            epoch,
            content_type,
            sender_data_nonce,
            encrypted_sender_data,
            ciphertext
        })
    }
}

#[derive(Clone)]
pub struct MLSSenderData {
    pub sender: u32,
    pub generation: u32,
}

impl Codec for MLSSenderData {
    fn encode(&self, buffer: &mut Vec<u8>) {
        (self.sender as u32).encode(buffer);
        (self.generation as u32).encode(buffer);
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let sender = u32::decode(cursor)?;
        let generation = u32::decode(cursor)?;
        Ok(MLSSenderData{
            sender,
            generation
        })
    }
}

#[derive(Clone)]
pub struct MLSCiphertextSenderDataAAD {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub content_type: ContentType,
    pub sender_data_nonce: Vec<u8>,
}

impl Codec for MLSCiphertextSenderDataAAD {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.group_id.encode(buffer);
        self.epoch.encode(buffer);
        self.content_type.encode(buffer);
        encode_vec_u8(buffer, &sender_data_nonce);
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let sender_data_nonce = decode_vec_u8(cursor)?;
        Ok(MLSCiphertextSenderDataAAD{
            group_id,
            epoch,
            content_type,
            sender_data_nonce
        })
    }
}

#[derive(Clone)]
pub struct MLSCiphertextContent {
    pub content: Vec<u8>, //
    pub signature: Signature,
    pub sig_len: u16,
    pub marker: u8,
    pub zero_padding: u8, //
}

impl Codec for MLSCiphertextContent {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.content);
        self.signature.encode(buffer);
        (self.sig_len as u16).encode(buffer);
        (self.marker as u8).encode(buffer);
        (self.zero_padding as u8).encode(buffer);
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let content = decode_vec_u8(cursor)?;
        let signature = Signature::decode(cursor)?;
        let sig_len = u16::decode(cursor)?;
        let marker = u8::decode(cursor)?;
        let zero_padding = u8::decode(cursor)?;
        Ok(MLSCiphertextContent {
            content, 
            signature,
            sig_len,
            marker,
            zero_padding
        })
    }
}

#[derive(Clone)]
pub struct MLSCiphertextContentAAD {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub content_type: ContentType,
    pub sender_data_nonce: Vec<u8>, //
    pub encrypted_sender_data: Vec<u8>,
}

impl Codec for MLSCiphertextContentAAD {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.group_id.encode(buffer);
        self.epoch.encode(buffer);
        self.content_type.encode(buffer);
        encode_vec_u8(buffer, &self.sender_data_nonce);
        encode_vec_u8(buffer, &self.encrypted_sender_data);
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let sender_data_nonce = decode_vec_u8(cursor)?;
        let encrypted_sender_data = decode_vec_u8(cursor)?;
        Ok(MLSCiphertextContentAAD{
            group_id,
            epoch,
            content_type,
            sender_data_nonce,
            encrypted_sender_data
        })
    }
}
