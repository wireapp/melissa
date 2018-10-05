use codec::*;
use eckem::*;
use group::*;
use keys::*;
use tree::*;

pub const HANDSHAKE_WELCOME: u8 = 1;
pub const HANDSHAKE_UPDATE: u8 = 2;
pub const HANDSHAKE_ADD: u8 = 3;
pub const HANDSHAKE_REMOVE: u8 = 4;

#[derive(Clone)]
pub enum HandshakeMessage {
    Welcome(Welcome),
    Update(Update),
    Add(Add),
    Remove(Remove),
}

impl Codec for HandshakeMessage {
    fn encode(&self, buffer: &mut Vec<u8>) {
        match self {
            HandshakeMessage::Welcome(welcome) => {
                HANDSHAKE_WELCOME.encode(buffer);
                welcome.encode(buffer);
            }
            HandshakeMessage::Update(update) => {
                HANDSHAKE_UPDATE.encode(buffer);
                update.encode(buffer);
            }
            HandshakeMessage::Add(add) => {
                HANDSHAKE_ADD.encode(buffer);
                add.encode(buffer);
            }
            HandshakeMessage::Remove(remove) => {
                HANDSHAKE_REMOVE.encode(buffer);
                remove.encode(buffer);
            }
            _ => {}
        }
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let handshake_type = cursor.take(1)?[0];
        match handshake_type {
            HANDSHAKE_WELCOME => Ok(HandshakeMessage::Welcome(Welcome::decode(cursor)?)),
            HANDSHAKE_UPDATE => Ok(HandshakeMessage::Update(Update::decode(cursor)?)),
            HANDSHAKE_ADD => Ok(HandshakeMessage::Add(Add::decode(cursor)?)),
            HANDSHAKE_REMOVE => Ok(HandshakeMessage::Remove(Remove::decode(cursor)?)),
            _ => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Clone)]
pub struct Welcome {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub roster: Vec<BasicCredential>,
    pub tree: Vec<X25519PublicKey>,
    pub transcript: Vec<HandshakeMessage>,
    pub init_secret: GroupSecret,
    pub leaf_secret: NodeSecret,
}

impl Codec for Welcome {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.group_id.encode(buffer);
        self.epoch.encode(buffer);
        encode_vec_u16(buffer, &self.roster);
        encode_vec_u16(buffer, &self.tree);
        encode_vec_u16(buffer, &self.transcript);
        self.init_secret.encode(buffer);
        self.leaf_secret.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let roster = decode_vec_u16(cursor)?;
        let tree = decode_vec_u16(cursor)?;
        let transcript = decode_vec_u16(cursor)?;
        let init_secret = GroupSecret::decode(cursor)?;
        let leaf_secret = NodeSecret::decode(cursor)?;
        Ok(Welcome {
            group_id,
            epoch,
            roster,
            tree,
            transcript,
            init_secret,
            leaf_secret,
        })
    }
}

#[derive(Clone, Hash)]
pub struct Update {
    pub nodes: Vec<X25519PublicKey>,
    pub path: Vec<X25519AESCiphertext>,
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
    pub path: Vec<X25519AESCiphertext>,
    pub init_key: UserInitKey,
}

impl Codec for Add {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u16(buffer, &self.nodes);
        encode_vec_u16(buffer, &self.path);
        self.init_key.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let nodes = decode_vec_u16(cursor)?;
        let path = decode_vec_u16(cursor)?;
        let init_key = UserInitKey::decode(cursor)?;
        Ok(Add {
            nodes,
            path,
            init_key,
        })
    }
}

#[derive(Clone)]
pub struct Remove {
    pub removed: usize,
    pub nodes: Vec<X25519PublicKey>,
    pub path: Vec<X25519AESCiphertext>,
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
