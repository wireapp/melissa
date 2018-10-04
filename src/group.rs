use keys::*;
use messages::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::*;
use tree::*;

#[derive(Clone)]
pub struct Member {}

pub const GROUPSECRETBYTES: usize = 32;
pub type GroupId = u16;
pub type GroupEpoch = u32;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct GroupSecret(pub [u8; GROUPSECRETBYTES]);

impl GroupSecret {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut group_secret = GroupSecret::default();
        group_secret.0.clone_from_slice(bytes);
        group_secret
    }
}

#[derive(Clone)]
pub struct Group {
    group_id: GroupId,
    group_epoch: GroupEpoch,
    group_secret: GroupSecret,
    roster: Vec<BasicCredential>,
    tree: Tree,
    update_secret: Option<(u64, NodeSecret)>,
    transcript: Vec<HandshakeMessage>,
}

impl Group {
    pub fn new(group_id: GroupId) -> Self {
        let secret = NodeSecret::new_random();
        let own_leaf = Node::from_secret(&secret);
        let mut bytes = [0u8; GROUPSECRETBYTES];
        bytes.clone_from_slice(&secret.0[..]);
        let group_secret = GroupSecret::from_bytes(&secret.0[..]);
        let tree = Tree::new_from_leaf(&own_leaf);
        Group {
            group_id,
            group_epoch: 0,
            group_secret, // FIXME
            roster: vec![],
            tree,
            update_secret: None,
            transcript: vec![],
        }
    }
    pub fn new_from_welcome(welcome: &Welcome) -> Self {
        let tree_size = welcome.tree.len();
        assert!(tree_size > 0);
        let tree =
            Tree::new_from_public_keys(&welcome.tree, welcome.tree.len() - 1, &welcome.leaf_secret); // FIXME derive slot from roster
        Group {
            group_id: welcome.group_id,
            group_epoch: welcome.epoch,
            group_secret: welcome.init_secret,
            roster: Vec::new(), // FIXME initialize from roster
            tree,
            update_secret: None,
            transcript: vec![],
        }
    }
    pub fn create_add(&mut self, init_key: UserInitKey) -> (Welcome, Add) {
        // FIXME verify init key signature
        let size = self.tree.get_leaf_count() + 1;
        let index = self.tree.get_leaf_count() * 2;

        let leaf_secret = NodeSecret::new_random();
        let (public_nodes, ciphertexts) = self.tree.encrypt(index, size, leaf_secret);
        let public_path = Tree::dirpath(index, size);
        assert_eq!(public_path.len(), public_nodes.len());

        let add = Add {
            nodes: public_nodes,
            path: ciphertexts,
            init_key,
        };

        let mut welcome_group = self.clone();
        welcome_group.process_add(&add);

        let welcome = Welcome {
            group_id: self.group_id,
            epoch: self.group_epoch,
            roster: self.roster.clone(), // FIXME
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
        let kem_path = Tree::copath(index, size);
        assert_eq!(kem_path.len(), add.path.len());
        self.tree
            .apply_kem_path(index, size, &kem_path, &add.path, &add.nodes);
        self.rotate_group_secret();
        let bc = BasicCredential {
            identity: vec![],
            public_key: add.init_key.identity_key,
        };
        self.roster.push(bc);
        self.transcript.push(HandshakeMessage::Add(add.clone()));
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
        // save new node secret for later, as we can't process our own updates
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
        let kem_path = Tree::copath(index, size);
        if let Some((stored_hash, node_secret)) = self.update_secret {
            println!("process_update: node_secret found: {:?}", node_secret);
            let mut hasher = DefaultHasher::new();
            update.hash(&mut hasher);
            let hash = hasher.finish();
            if stored_hash == hash {
                println!("process_update: apply own update");
                let public_merge_path = Tree::dirpath(index, size);
                let mut public_nodes = Vec::new();
                for key in update.nodes.iter() {
                    public_nodes.push(Node::new_from_public_key(key));
                }
                println!("process_update: public_merge_path: {:?}", public_merge_path);
                self.tree.merge(public_merge_path, &public_nodes);
                let nodes = Tree::hash_up(index, size, &node_secret);
                let mut merge_path = Tree::dirpath(index, size);
                merge_path.push(Tree::root(size));
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
            .push(HandshakeMessage::Update(update.clone()));
        self.rotate_group_secret();
    }
    pub fn create_remove(&self, participant: usize) -> Remove {
        assert!(participant <= self.tree.get_leaf_count());
        let index = participant * 2;
        assert!(index != self.tree.get_own_leaf_index());
        let size = self.tree.get_leaf_count();
        let leaf_secret = NodeSecret::new_random();
        let (nodes, ciphertexts) = self.tree.encrypt(index, size, leaf_secret);
        println!("create_remove: ciphertexts length: {}", ciphertexts.len());
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
        let kem_path = Tree::copath(index, size);
        println!("process_remove: kem_path: {:?}", kem_path);
        assert_eq!(kem_path.len(), remove.path.len());
        self.tree
            .apply_kem_path(index, size, &kem_path, &remove.path, &remove.nodes);
        self.rotate_group_secret();
        self.transcript
            .push(HandshakeMessage::Remove(remove.clone()));
    }
    pub fn get_members() {}
    pub fn get_group_secret(&self) -> GroupSecret {
        self.group_secret
    }
    pub fn rotate_group_secret(&mut self) {
        let root = self.tree.get_root();
        // FIXME: KDF is not yet applied
        self.group_secret = GroupSecret(root.secret.unwrap().0);
        self.group_epoch += 1;
    }
}

#[test]
fn create_group() {
    let mut group = Group::new(0);
    let secret = group.get_group_secret();

    assert_eq!(group.tree.get_own_leaf().secret.unwrap().0, secret.0);

    let init_key = UserInitKey::new();
    let (welcome, add) = group.create_add(init_key.clone());
    group.process_add(&add);
    let remove = group.create_remove(1);
    group.process_remove(&remove);
    let update = group.create_update();
    group.process_update(0, &update);

    for _ in 0..100 {
        let (welcome2, add2) = group.create_add(init_key.clone());
        group.process_add(&add2);
    }

    let mut group2 = Group::new_from_welcome(&welcome);
    //group2.process_add(&add);
}

#[test]
fn alice_bob_charlie_walk_into_a_group() {
    let init_key = UserInitKey::new();

    // Create a group with Alice
    let mut group_alice = Group::new(1);
    println!(
        "test: alice group secret: {:?}",
        group_alice.get_group_secret()
    );

    // Alice addes Bob
    let (welcome_alice_bob, add_alice_bob) = group_alice.create_add(init_key.clone());
    group_alice.process_add(&add_alice_bob);
    println!(
        "test: alice group secret: {:?}",
        group_alice.get_group_secret()
    );

    let mut group_bob = Group::new_from_welcome(&welcome_alice_bob);
    println!("test: bob group secret: {:?}", group_bob.get_group_secret());
    assert_eq!(group_alice.get_group_secret(), group_bob.get_group_secret());

    // Bob updates
    let update_bob = group_bob.create_update();
    group_bob.process_update(1, &update_bob);
    println!("test: bob group secret: {:?}", group_bob.get_group_secret());
    group_alice.process_update(1, &update_bob);
    assert_eq!(group_alice.get_group_secret(), group_bob.get_group_secret());

    // Bob adds Charlie
    let (welcome_bob_charlie, add_bob_charlie) = group_bob.create_add(init_key.clone());
    let mut group_charlie = Group::new_from_welcome(&welcome_bob_charlie);

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
    println!("---------------------------- Charlie creates an update");
    let update_charlie = group_charlie.create_update();
    println!("---------------------------- Alice applies Charlie's update");
    group_alice.process_update(2, &update_charlie);
    println!("---------------------------- Bob applies Charlie's update");
    group_bob.process_update(2, &update_charlie);
    println!("---------------------------- Charlie applies Charlie's update");
    group_charlie.process_update(2, &update_charlie);

    println!(
        "test: alice group secret:   {:?}",
        group_alice.get_group_secret()
    );
    println!(
        "test: bob group secret:     {:?}",
        group_bob.get_group_secret()
    );
    println!(
        "test: charlie group secret: {:?}",
        group_bob.get_group_secret()
    );

    assert_eq!(group_alice.get_group_secret(), group_bob.get_group_secret());
    assert_eq!(
        group_alice.get_group_secret(),
        group_charlie.get_group_secret()
    );

    // Charlie removes Bob
    println!("---------------------------- Charlie removes Bob");
    let remove_charlie_bob = group_charlie.create_remove(1);
    println!("---------------------------- Alice applies Charlie's update");
    group_alice.process_remove(&remove_charlie_bob);
    println!("---------------------------- Charlie applies Charlie's update");
    group_charlie.process_remove(&remove_charlie_bob);

    println!(
        "test: alice group secret:   {:?}",
        group_alice.get_group_secret()
    );
    println!(
        "test: bob group secret:     {:?}",
        group_bob.get_group_secret()
    );
    println!(
        "test: charlie group secret: {:?}",
        group_charlie.get_group_secret()
    );

    assert_eq!(
        group_alice.get_group_secret(),
        group_charlie.get_group_secret()
    );

    assert_ne!(group_alice.get_group_secret(), group_bob.get_group_secret());
}
