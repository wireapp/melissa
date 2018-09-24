use eckem::*;
use group::*;
use keys::*;
use tree::*;

pub struct Welcome {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub roster: Vec<u8>, // FIXME
    pub tree: Vec<X25519PublicKey>,
    pub transcript: Vec<u8>, //FIXME
    pub init_secret: GroupSecret,
    pub leaf_secret: NodeSecret,
}

pub struct Add {
    pub nodes: Vec<X25519PublicKey>,
    pub path: Vec<X25519AESCiphertext>,
    pub init_key: UserInitKey,
}

pub struct Update {
    pub nodes: Vec<X25519PublicKey>,
    pub path: Vec<X25519AESCiphertext>,
}

pub struct Remove {
    pub removed: usize,
    pub nodes: Vec<X25519PublicKey>,
    pub path: Vec<X25519AESCiphertext>,
}
