use codec::*;
use eckem::*;
use group::*;
use keys::*;
use tree::*;

#[derive(Clone)]
pub enum HandshakeMessage {
    Welcome(Welcome),
    Add(Add),
    Update(Update),
    Remove(Remove),
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

#[derive(Clone)]
pub struct Add {
    pub nodes: Vec<X25519PublicKey>,
    pub path: Vec<X25519AESCiphertext>,
    pub init_key: UserInitKey,
}

#[derive(Clone, Hash)]
pub struct Update {
    pub nodes: Vec<X25519PublicKey>,
    pub path: Vec<X25519AESCiphertext>,
}

#[derive(Clone)]
pub struct Remove {
    pub removed: usize,
    pub nodes: Vec<X25519PublicKey>,
    pub path: Vec<X25519AESCiphertext>,
}
