use keys::*;
use messages::*;
use tree::*;

pub struct Member {}

pub const GROUPSECRETBYTES: usize = 32;
pub type GroupId = u16;
pub type GroupEpoch = u32;

#[derive(Clone)]
pub struct GroupSecret(pub [u8; GROUPSECRETBYTES]);

pub struct Group {
    group_id: GroupId,
    group_epoch: GroupEpoch,
    group_secret: GroupSecret,
    members: Vec<Member>,
    tree: Tree,
    update_secret: Option<NodeSecret>, // FIXME needs to be set
}

impl Group {
    pub fn new(group_id: GroupId) -> Self {
        let secret = NodeSecret::new_random();
        let own_leaf = Node::from_secret(&secret);
        let mut bytes = [0u8; GROUPSECRETBYTES];
        bytes.clone_from_slice(&secret.0[..]);
        let group_secret = GroupSecret(bytes); // FIXME
        let tree = Tree::new_from_leaf(&own_leaf);
        Group {
            group_id,
            group_epoch: 0,
            group_secret, // FIXME
            members: vec![],
            tree,
            update_secret: None,
        }
    }
    pub fn new_from_welcome(welcome: &Welcome) -> Self {
        let tree_size = welcome.tree.len();
        assert!(tree_size > 0);
        let tree = Tree::new_from_public_keys(&welcome.tree, 0, &welcome.leaf_secret);
        Group {
            group_id: welcome.group_id,
            group_epoch: welcome.epoch,
            group_secret: welcome.init_secret.clone(),
            members: Vec::new(), // FIXME initialize from roster
            tree,
            update_secret: None,
        }
    }
    pub fn create_add(&mut self, init_key: UserInitKey) -> (Welcome, Add) {
        // FIXME verify init key signature
        let size = self.tree.get_leaf_count() + 1;
        let index = self.tree.get_leaf_count() * 2;

        let leaf_secret = NodeSecret::new_random();
        let (public_nodes, ciphertexts) = self.tree.encrypt(
            index,
            size,
            &self.tree.get_nodes_from_path(Tree::frontier(size - 1)),
            leaf_secret,
        );
        let public_path = Tree::dirpath(index, size);
        assert_eq!(public_path.len(), public_nodes.len());
        let welcome = Welcome {
            group_id: self.group_id,
            epoch: self.group_epoch,
            roster: Vec::new(), // FIXME
            tree: self.tree.get_public_key_tree(),
            transcript: Vec::new(), // FIXME
            init_secret: self.group_secret.clone(),
            leaf_secret,
        };
        let add = Add {
            nodes: public_nodes,
            path: ciphertexts,
            init_key,
        };
        // FIXME sign the Add message
        (welcome, add)
    }
    pub fn process_add(&mut self, add: &Add) {
        // FIXME verify init key signature
        let size = self.tree.get_leaf_count() + 1;
        let index = self.tree.get_leaf_count() * 2;
        self.tree.apply_kem_path(index, size, &add.path, &add.nodes);
        let _init_key = &add.init_key;
        // FIXME add new participant to roster
    }
    pub fn create_update(&mut self) -> Update {
        let own_leaf_index = self.tree.get_own_leaf_index();
        let size = self.tree.get_tree_size();
        let leaf_secret = NodeSecret::new_random();
        let mut path = Tree::hash_up(own_leaf_index, size, &leaf_secret);
        path.pop();
        let (nodes, ciphertexts) = self.tree.encrypt(own_leaf_index, size, &path, leaf_secret);
        // FIXME sign the Update message
        Update {
            nodes,
            path: ciphertexts,
        }
    }
    pub fn process_update(&mut self, update: &Update) {
        let size = self.tree.get_leaf_count();
        let index = self.tree.get_own_leaf_index(); // FIXME should be derived form roster
        self.tree
            .apply_kem_path(index, size, &update.path, &update.nodes);
    }
    pub fn create_remove(&self, participant: usize) -> Remove {
        assert!(participant <= self.tree.get_leaf_count());
        let index = participant * 2;
        assert!(index != self.tree.get_own_leaf_index());
        let size = self.tree.get_tree_size();
        let leaf_secret = NodeSecret::new_random();
        let mut path = Tree::hash_up(index, size, &leaf_secret);
        path.pop();
        let (nodes, ciphertexts) = self.tree.encrypt(index, size, &path, leaf_secret);
        // FIXME sign the Remove message
        Remove {
            removed: participant,
            nodes,
            path: ciphertexts,
        }
    }
    pub fn process_remove() {}
    pub fn get_members() {}
    pub fn get_group_secret(&self) -> GroupSecret {
        // FIXME: KDF is not yet applied
        let root = self.tree.get_root();
        GroupSecret(root.secret.unwrap().0)
    }
}

#[test]
fn create_group() {
    let mut group = Group::new(0);
    let secret = group.get_group_secret();

    assert_eq!(group.tree.get_own_leaf().secret.unwrap().0, secret.0);

    let init_key = UserInitKey {
        cipher_suite: vec![0],
        init_keys: vec![], /* [2^16-1] */
        identity_key: SignaturePublicKey {},
        algorithm: SignatureScheme {},
        signature: Signature {},
    };
    let (welcome, add) = group.create_add(init_key.clone());
    group.process_add(&add);
    let update = group.create_update();
    //group.process_update(&update);

    for _ in 0..10 {
        let (welcome2, add2) = group.create_add(init_key.clone());
        group.process_add(&add2);
    }

    let mut group2 = Group::new_from_welcome(&welcome);
    //group2.process_add(&add);
}
