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
use keys::*;
use messages::*;
use sodiumoxide::{randombytes, utils};
use std::collections::hash_map::DefaultHasher;
use std::hash::*;
use tree::*;
use treemath;

#[derive(Clone)]
pub struct Member {}

pub const GROUPSECRETBYTES: usize = 32;
pub const GROUPIDBYTES: usize = 255;

#[derive(Clone)]
pub struct GroupId(pub [u8; GROUPIDBYTES]);

impl GroupId {
    pub fn random() -> Self {
        Self::from_bytes(&randombytes::randombytes(GROUPIDBYTES))
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut group_id = [0u8; GROUPIDBYTES];
        group_id.clone_from_slice(bytes);
        GroupId(group_id)
    }
}

impl Codec for GroupId {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.0);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes = decode_vec_u8(cursor)?;
        Ok(GroupId::from_bytes(&bytes))
    }
}

#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct GroupSecret(pub [u8; GROUPSECRETBYTES]);

impl GroupSecret {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut group_secret = GroupSecret::default();
        group_secret.0.clone_from_slice(bytes);
        group_secret
    }
}

impl Codec for GroupSecret {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.0);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes = decode_vec_u8(cursor)?;
        Ok(GroupSecret::from_bytes(&bytes))
    }
}

impl Drop for GroupSecret {
    fn drop(&mut self) {
        utils::memzero(&mut self.0)
    }
}

pub type GroupEpoch = u32;

#[derive(Clone)]
pub struct Group {
    id: Identity,
    group_id: GroupId,
    group_epoch: GroupEpoch,
    group_secret: GroupSecret,
    roster: Vec<BasicCredential>,
    tree: Tree,
    update_secret: Option<(u64, NodeSecret)>,
    transcript: Vec<GroupOperationValue>,
}

impl Group {
    pub fn new(id: Identity, credential: BasicCredential, group_id: GroupId) -> Self {
        let secret = NodeSecret::new_random();
        let own_leaf = Node::from_secret(&secret);
        let group_secret = GroupSecret::from_bytes(&secret.0[..]);
        let tree = Tree::new_from_leaf(&own_leaf);
        Group {
            id,
            group_id,
            group_epoch: 0,
            group_secret, // FIXME
            roster: vec![credential],
            tree,
            update_secret: None,
            transcript: vec![],
        }
    }
    pub fn new_from_welcome(id: Identity, welcome: &Welcome) -> Self {
        let tree_size = welcome.tree.len();
        assert!(tree_size > 0);
        let roster = welcome.roster.clone();
        let own_slot = roster.iter().position(|k| k.public_key == id.public_key);
        assert!(own_slot.is_some());
        let tree =
            Tree::new_from_public_keys(&welcome.tree, own_slot.unwrap() * 2, &welcome.leaf_secret);
        Group {
            id,
            group_id: welcome.group_id.clone(),
            group_epoch: welcome.epoch,
            group_secret: welcome.init_secret.clone(),
            roster: welcome.roster.clone(),
            tree,
            update_secret: None,
            transcript: vec![],
        }
    }
    pub fn create_add(&mut self, id: BasicCredential, init_key: &UserInitKey) -> (Welcome, Add) {
        assert!(init_key.self_verify());
        let size = self.tree.get_leaf_count() + 1;
        let index = self.tree.get_leaf_count() * 2;

        let leaf_secret = NodeSecret::new_random();
        let (public_nodes, ciphertexts) = self.tree.encrypt(index, size, leaf_secret);
        let public_path = treemath::dirpath(index, size);
        assert_eq!(public_path.len(), public_nodes.len());

        let add = Add {
            nodes: public_nodes,
            path: ciphertexts,
            init_key: init_key.clone(),
        };

        let mut welcome_group = self.clone();
        welcome_group.process_add(&add);

        let mut welcome_roster = self.roster.clone();
        welcome_roster.push(id);

        let welcome = Welcome {
            group_id: self.group_id.clone(),
            epoch: self.group_epoch,
            roster: welcome_roster,
            tree: welcome_group.tree.get_public_key_tree(),
            transcript: Vec::new(), // FIXME
            init_secret: welcome_group.get_group_secret(),
            leaf_secret,
        };
        // FIXME sign the Add message
        (welcome, add)
    }
    pub fn process_add(&mut self, add: &Add) {
        // FIXME verify init key signature
        let size = self.tree.get_leaf_count() + 1;
        let index = self.tree.get_leaf_count() * 2;
        let kem_path = treemath::copath(index, size);
        assert_eq!(kem_path.len(), add.path.len());
        self.tree
            .apply_kem_path(index, size, &kem_path, &add.path, &add.nodes);
        self.rotate_group_secret();
        let bc = BasicCredential {
            identity: vec![],
            public_key: add.init_key.identity_key,
        };
        self.roster.push(bc);
        self.transcript.push(GroupOperationValue::Add(add.clone()));
    }
    pub fn create_update(&mut self) -> Update {
        let own_leaf_index = self.tree.get_own_leaf_index();
        let size = self.tree.get_leaf_count();
        let leaf_secret = NodeSecret::new_random();
        let (nodes, ciphertexts) = self.tree.encrypt(own_leaf_index, size, leaf_secret);
        let update = Update {
            nodes,
            path: ciphertexts,
        };
        // FIXME should be derived from roster
        let mut hasher = DefaultHasher::new();
        update.hash(&mut hasher);
        let hash = hasher.finish();
        self.update_secret = Some((hash, leaf_secret));
        // FIXME sign the Update message
        update
    }
    pub fn process_update(&mut self, participant: usize, update: &Update) {
        let size = self.tree.get_leaf_count();
        let index = participant * 2;
        // FIXME check if participant number matches the sender in the roster
        let kem_path = treemath::copath(index, size);
        if let Some((stored_hash, node_secret)) = self.update_secret {
            let mut hasher = DefaultHasher::new();
            update.hash(&mut hasher);
            let hash = hasher.finish();
            if stored_hash == hash {
                let nodes = Tree::hash_up(index, size, &node_secret);
                let mut merge_path = treemath::dirpath(index, size);
                merge_path.push(treemath::root(size));
                self.tree.merge(merge_path, &nodes);
            } else {
                self.tree
                    .apply_kem_path(index, size, &kem_path, &update.path, &update.nodes);
            }
        } else {
            self.tree
                .apply_kem_path(index, size, &kem_path, &update.path, &update.nodes);
        }
        self.update_secret = None;
        self.transcript
            .push(GroupOperationValue::Update(update.clone()));
        self.rotate_group_secret();
    }
    pub fn create_remove(&self, participant: usize) -> Remove {
        assert!(participant <= self.tree.get_leaf_count());
        let index = participant * 2;
        assert!(index != self.tree.get_own_leaf_index());
        let size = self.tree.get_leaf_count();
        let leaf_secret = NodeSecret::new_random();
        let (nodes, ciphertexts) = self.tree.encrypt(index, size, leaf_secret);
        // FIXME sign the Remove message
        Remove {
            removed: participant,
            nodes,
            path: ciphertexts,
        }
    }
    pub fn process_remove(&mut self, remove: &Remove) {
        let size = self.tree.get_leaf_count();
        let index = remove.removed * 2; // FIXME should be checked against the roster
        let kem_path = treemath::copath(index, size);
        assert_eq!(kem_path.len(), remove.path.len());
        self.tree
            .apply_kem_path(index, size, &kem_path, &remove.path, &remove.nodes);
        self.rotate_group_secret();
        self.transcript
            .push(GroupOperationValue::Remove(remove.clone()));
    }
    pub fn create_handshake(&self, group_operation: GroupOperation) -> Handshake {
        let signer_index = self.tree.get_own_leaf_index() as u32;
        let prior_epoch = self.group_epoch;
        let algorithm = ED25519;
        let mut hs = Handshake {
            prior_epoch,
            operation: group_operation,
            signer_index,
            algorithm,
            signature: None,
        };
        hs.signature = Some(hs.sign(&self.id));
        hs
    }
    pub fn process_handshake(&mut self, hs: Handshake) {
        let sender = hs.signer_index as usize;
        assert_eq!(hs.prior_epoch, self.group_epoch);
        assert_eq!(hs.algorithm, ED25519);
        assert!(sender < self.roster.len());
        {
            let signer = &self.roster[sender];
            assert!(signer.verify(&hs.unsigned_payload(), &hs.signature.unwrap()));
        }

        let group_operation_value = hs.operation.group_operation;
        match group_operation_value {
            GroupOperationValue::Add(add) => self.process_add(&add),
            GroupOperationValue::Update(update) => self.process_update(sender, &update),
            GroupOperationValue::Remove(remove) => self.process_remove(&remove),
            _ => (),
        }
    }
    pub fn get_members(&self) -> Vec<BasicCredential> {
        self.roster.clone()
    }
    pub fn get_group_secret(&self) -> GroupSecret {
        self.group_secret.clone()
    }
    pub fn rotate_group_secret(&mut self) {
        let root = self.tree.get_root();
        // FIXME: KDF is not yet applied
        self.group_secret = GroupSecret(root.secret.unwrap().0);
        self.group_epoch += 1;
    }
    pub fn encode_group_state(&self, buffer: &mut Vec<u8>) {
        self.group_id.encode(buffer);
        self.group_epoch.encode(buffer);
        encode_vec_u16(buffer, &self.roster);
        encode_vec_u16(buffer, &self.tree.get_public_key_tree());
        encode_vec_u16(buffer, &self.transcript); // FIXME
    }
}

#[test]
fn alice_bob_charlie_walk_into_a_group() {
    // Define identities
    let alice_identity = Identity::random();
    let bob_identity = Identity::random();
    let charlie_identity = Identity::random();

    let alice_credential = BasicCredential {
        identity: "Alice".as_bytes().to_vec(),
        public_key: alice_identity.public_key,
    };
    let bob_credential = BasicCredential {
        identity: "Bob".as_bytes().to_vec(),
        public_key: bob_identity.public_key,
    };
    let charlie_credential = BasicCredential {
        identity: "Charlie".as_bytes().to_vec(),
        public_key: charlie_identity.public_key,
    };

    // Generate UserInitKeys
    let bob_init_key_bundle = UserInitKeyBundle::new(1, &bob_identity);
    let bob_init_key = bob_init_key_bundle.init_key.clone();

    let charlie_init_key_bundle = UserInitKeyBundle::new(1, &charlie_identity);
    let charlie_init_key = charlie_init_key_bundle.init_key.clone();

    // Create a group with Alice
    let mut group_alice = Group::new(alice_identity, alice_credential, GroupId::random());

    // Alice adds Bob
    let (welcome_alice_bob, add_alice_bob) = group_alice.create_add(bob_credential, &bob_init_key);
    group_alice.process_add(&add_alice_bob);

    let mut group_bob = Group::new_from_welcome(bob_identity, &welcome_alice_bob);
    assert_eq!(group_alice.get_group_secret(), group_bob.get_group_secret());

    // Bob updates
    let update_bob = group_bob.create_update();
    group_bob.process_update(1, &update_bob);
    group_alice.process_update(1, &update_bob);
    assert_eq!(group_alice.get_group_secret(), group_bob.get_group_secret());

    // Alice updates
    let update_alice = group_alice.create_update();
    group_alice.process_update(0, &update_alice);
    group_bob.process_update(0, &update_alice);

    // Bob adds Charlie
    let (welcome_bob_charlie, add_bob_charlie) =
        group_bob.create_add(charlie_credential, &charlie_init_key);
    let mut group_charlie = Group::new_from_welcome(charlie_identity, &welcome_bob_charlie);

    group_alice.process_add(&add_bob_charlie);
    assert_eq!(
        group_alice.get_group_secret(),
        group_charlie.get_group_secret()
    );

    group_bob.process_add(&add_bob_charlie);
    assert_eq!(
        group_bob.get_group_secret(),
        group_charlie.get_group_secret()
    );
    assert_eq!(group_alice.get_group_secret(), group_bob.get_group_secret());

    // Charlie updates
    let update_charlie = group_charlie.create_update();
    group_alice.process_update(2, &update_charlie);
    group_bob.process_update(2, &update_charlie);
    group_charlie.process_update(2, &update_charlie);

    // Alice updates
    let update_alice = group_alice.create_update();
    group_alice.process_update(0, &update_alice);
    group_bob.process_update(0, &update_alice);
    group_charlie.process_update(0, &update_alice);
    assert_eq!(group_alice.get_group_secret(), group_bob.get_group_secret());
    assert_eq!(
        group_alice.get_group_secret(),
        group_charlie.get_group_secret()
    );

    // Charlie removes Bob
    let remove_charlie_bob = group_charlie.create_remove(1);
    group_alice.process_remove(&remove_charlie_bob);
    group_charlie.process_remove(&remove_charlie_bob);

    assert_eq!(
        group_alice.get_group_secret(),
        group_charlie.get_group_secret()
    );

    assert_ne!(group_alice.get_group_secret(), group_bob.get_group_secret());
}
