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
use crypto::eckem::*;
use keys::*;
use sodiumoxide::crypto::hash::sha256::*;
use sodiumoxide::randombytes;
use treemath;

pub const NODESECRETBYTES: usize = 32;

#[derive(PartialEq, Clone, Copy, Debug)]
pub struct NodeSecret(pub [u8; NODESECRETBYTES]);

impl NodeSecret {
    pub fn new_random() -> Self {
        let mut bytes = [0u8; NODESECRETBYTES];
        bytes.clone_from_slice(randombytes::randombytes(NODESECRETBYTES).as_slice());
        NodeSecret(bytes)
    }

    pub fn hash(&mut self) {
        let digest = hash(&self.0[..]);
        self.0 = NodeSecret::from(digest).0;
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let hash = hash(bytes).0;
        let mut buffer = [0u8; NODESECRETBYTES];
        buffer.clone_from_slice(&hash[..NODESECRETBYTES]);
        NodeSecret(buffer)
    }
}

impl From<Digest> for NodeSecret {
    fn from(d: Digest) -> NodeSecret {
        let mut bytes = [0u8; DIGESTBYTES];
        bytes.clone_from_slice(&d.0[..DIGESTBYTES]);
        NodeSecret(bytes)
    }
}

impl From<NodeSecret> for Digest {
    fn from(n: NodeSecret) -> Digest {
        let mut bytes = [0u8; NODESECRETBYTES];
        bytes.clone_from_slice(&n.0[..NODESECRETBYTES]);
        Digest(bytes)
    }
}

impl Codec for NodeSecret {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u8(buffer, &self.0);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes = decode_vec_u8(cursor)?;
        Ok(NodeSecret::from_bytes(&bytes))
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct Node {
    pub secret: Option<NodeSecret>,
    pub dh_public_key: Option<X25519PublicKey>,
    pub dh_private_key: Option<X25519PrivateKey>,
}

impl Codec for Node {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.secret.encode(buffer);
        self.dh_public_key.encode(buffer);
        self.dh_private_key.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let secret = Option::<NodeSecret>::decode(cursor)?;
        let dh_public_key = Option::<X25519PublicKey>::decode(cursor)?;
        let dh_private_key = Option::<X25519PrivateKey>::decode(cursor)?;
        Ok(Node {
            secret,
            dh_public_key,
            dh_private_key,
        })
    }
}

impl Node {
    pub fn from_secret(secret: &NodeSecret) -> Node {
        let mut hashed_secret = secret.clone();
        hashed_secret.hash();
        let kp = X25519KeyPair::new_from_secret(&secret);
        Node {
            secret: Some(*secret),
            dh_public_key: Some(kp.public_key),
            dh_private_key: Some(kp.private_key),
        }
    }

    pub fn new_from_public_key(key: &X25519PublicKey) -> Node {
        Node {
            secret: None,
            dh_private_key: None,
            dh_public_key: Some(*key),
        }
    }

    pub fn new_blank() -> Node {
        Node {
            secret: None,
            dh_private_key: None,
            dh_public_key: None,
        }
    }

    pub fn get_public_key(&mut self) -> Option<X25519PublicKey> {
        match self.dh_public_key {
            Some(key) => Some(key),
            None => match self.secret {
                Some(secret) => {
                    let kp = X25519KeyPair::new_from_secret(&secret);
                    self.dh_private_key = Some(kp.private_key);
                    self.dh_public_key = Some(kp.public_key);
                    self.dh_public_key
                }
                None => None,
            },
        }
    }

    pub fn get_private_key(&mut self) -> Option<X25519PrivateKey> {
        match self.dh_private_key.clone() {
            Some(key) => Some(key),
            None => match self.secret {
                Some(secret) => {
                    let kp = X25519KeyPair::new_from_secret(&secret);
                    self.dh_private_key = Some(kp.private_key);
                    self.dh_public_key = Some(kp.public_key);
                    self.dh_private_key.clone()
                }
                None => None,
            },
        }
    }

    pub fn blank(&mut self) {
        self.secret = None;
        self.dh_private_key = None;
        self.dh_public_key = None;
    }

    pub fn is_blank(&self) -> bool {
        self.secret.is_none() && self.dh_private_key.is_none() && self.dh_public_key.is_none()
    }
}

#[derive(Clone)]
pub struct Tree {
    pub nodes: Vec<Node>,
    pub own_leaf_index: usize,
}

impl Codec for Tree {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u32(buffer, &self.nodes);
        (self.own_leaf_index as u32).encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let nodes = decode_vec_u32(cursor)?;
        let own_leaf_index = u32::decode(cursor)? as usize;
        Ok(Tree {
            nodes,
            own_leaf_index,
        })
    }
}

impl Tree {
    pub fn new_from_leaf(leaf: &Node) -> Tree {
        let mut tree = Tree {
            nodes: vec![leaf.clone()],
            own_leaf_index: 0,
        };
        let secret = leaf.secret.unwrap();
        let new_nodes = Tree::hash_up(0, 1, &secret);
        let copath = vec![0];
        tree.merge(copath, &new_nodes);
        tree
    }

    pub fn new_from_public_keys(
        keys: &[X25519PublicKey],
        own_leaf_index: usize,
        leaf_secret: &NodeSecret,
    ) -> Tree {
        let mut nodes: Vec<Node> = Vec::new();
        for key in keys {
            nodes.push(Node::new_from_public_key(key));
        }
        let own_node = Node::from_secret(leaf_secret);
        nodes[own_leaf_index] = own_node;
        Tree {
            nodes,
            own_leaf_index,
        }
    }

    pub fn get_tree_size(&self) -> usize {
        self.nodes.len()
    }

    pub fn get_root(&self) -> Node {
        let root_index = treemath::root(self.get_leaf_count());
        self.nodes[root_index].clone()
    }

    pub fn set_root(&mut self, node: Node) {
        let index = treemath::root(self.get_leaf_count());
        self.nodes[index] = node;
    }

    pub fn get_nodes_from_path(&self, path: Vec<usize>) -> Vec<Node> {
        let mut nodes: Vec<Node> = Vec::new();
        for i in path {
            nodes.push(self.nodes[i].clone());
        }
        nodes
    }

    pub fn get_public_keys_from_path(&self, path: Vec<usize>) -> Vec<X25519PublicKey> {
        let mut keys = Vec::new();
        for index in path {
            keys.push(self.nodes[index].clone().dh_public_key.unwrap());
        }
        keys
    }

    pub fn get_public_key_tree(&self) -> Vec<X25519PublicKey> {
        let mut tree = Vec::new();
        for node in self.nodes.iter() {
            tree.push(node.clone().dh_public_key.unwrap());
        }
        tree
    }

    pub fn get_own_leaf(&self) -> Node {
        self.nodes[self.own_leaf_index].clone()
    }

    pub fn get_own_leaf_index(&self) -> usize {
        self.own_leaf_index
    }

    pub fn get_leaf_count(&self) -> usize {
        self.get_tree_size() / 2 + 1
    }

    pub fn resolve(&self, x: usize) -> Vec<usize> {
        let n = self.get_leaf_count();
        if !self.nodes[x].is_blank() {
            return vec![x];
        }

        if treemath::level(x) == 0 {
            return vec![];
        }

        let mut left = self.resolve(treemath::left(x));
        let right = self.resolve(treemath::right(x, n));
        left.extend(right);
        left
    }

    pub fn blank_up(&mut self, x: usize) {
        let n = self.get_leaf_count();
        self.nodes[x].blank();
        if x != treemath::root(n) {
            self.blank_up(treemath::parent(x, n));
        }
    }

    pub fn merge(&mut self, path: Vec<usize>, nodes: &[Node]) {
        assert_eq!(path.len(), nodes.len());
        let mut max: usize = 0;
        for n in path.iter() {
            if *n > max {
                max = *n;
            }
        }
        if max >= self.nodes.len() {
            self.nodes.resize(max + 1, Node::new_blank());
        }
        for (node, index) in nodes.iter().zip(path) {
            self.nodes[index] = node.clone();
        }
    }

    pub fn hash_up(index: usize, size: usize, secret: &NodeSecret) -> Vec<Node> {
        // Compute hashes up the tree
        let mut nodes = Vec::new();
        let mut node_secret = *secret;
        let mut dirpath = treemath::dirpath(index, size);
        dirpath.push(treemath::root(size));
        for _ in dirpath {
            let node = Node::from_secret(&node_secret);
            nodes.push(node);
            node_secret.hash();
        }
        nodes
    }

    pub fn kem_to(
        dirpath_nodes: &mut [Node],
        copath_nodes: &mut [Node],
    ) -> Vec<X25519AESCiphertext> {
        let mut path: Vec<X25519AESCiphertext> = Vec::new();
        assert_eq!(dirpath_nodes.len(), copath_nodes.len());
        for node_pair in dirpath_nodes.iter_mut().zip(copath_nodes.iter_mut()) {
            let (mut dirpath_node, mut copath_node) = node_pair;
            let public_key = copath_node.dh_public_key.unwrap();
            let ciphertext =
                X25519AES::encrypt(&public_key, &dirpath_node.secret.unwrap().0[..]).unwrap();
            path.push(ciphertext);
        }
        path
    }

    pub fn encrypt(
        &self,
        index: usize,
        size: usize,
        secret: NodeSecret,
    ) -> (Vec<X25519PublicKey>, Vec<X25519AESCiphertext>) {
        let node_secret = secret;
        let mut nodes = Tree::hash_up(index, size, &node_secret);
        let mut copath_nodes = self.get_nodes_from_path(treemath::copath(index, size));
        // strip leaf
        let leaf_node = nodes.remove(0);
        assert_eq!(copath_nodes.len(), nodes.len());
        let ciphertexts = Tree::kem_to(&mut nodes, &mut copath_nodes);
        let mut public_keys: Vec<X25519PublicKey> = Vec::new();
        public_keys.push(leaf_node.dh_public_key.unwrap());
        for mut node in nodes {
            public_keys.push(node.dh_public_key.unwrap());
        }
        // strip root
        public_keys.pop();
        (public_keys, ciphertexts)
    }

    pub fn decrypt(
        &self,
        size: usize,
        kem_path: &[usize],
        ciphertexts: &[X25519AESCiphertext],
    ) -> (Vec<usize>, Vec<Node>) {
        let own_path = treemath::dirpath(self.own_leaf_index, size);
        let mut own_path_index = 0;
        let mut kem_path_index = 0;
        for (opi, op_element) in own_path.iter().enumerate() {
            for (kpi, kp_element) in kem_path.iter().enumerate() {
                if op_element == kp_element {
                    own_path_index = opi;
                    kem_path_index = kpi;
                }
            }
        }
        let mut merge_path = treemath::dirpath(treemath::parent(self.own_leaf_index, size), size);
        merge_path.push(treemath::root(size));
        merge_path.drain(0..own_path_index);
        let intersect_ciphertext = ciphertexts[kem_path_index].clone();
        let intersect_node = self.nodes[own_path[own_path_index]].clone();
        let private_key = intersect_node.dh_private_key.unwrap();
        let secret = X25519AES::decrypt(&private_key, &intersect_ciphertext).unwrap();
        let node_secret = NodeSecret::from_bytes(secret.as_slice());
        (
            merge_path,
            Tree::hash_up(
                treemath::parent(own_path[own_path_index], size),
                size,
                &node_secret,
            ),
        )
    }

    pub fn apply_kem_path(
        &mut self,
        index: usize,
        size: usize,
        kem_path: &[usize],
        ciphertext: &[X25519AESCiphertext],
        public_keys: &[X25519PublicKey],
    ) {
        let public_merge_path = treemath::dirpath(index, size);
        let mut public_nodes = Vec::new();
        for key in public_keys.iter() {
            public_nodes.push(Node::new_from_public_key(key));
        }
        self.merge(public_merge_path, &public_nodes);
        let (merge_path, nodes) = self.decrypt(size, &kem_path, ciphertext);
        self.merge(merge_path, &nodes);
    }
}

#[derive(Clone)]
pub struct LeafNodeInfo {
    pub public_key: X25519PublicKey,
    pub credential: BasicCredential
}

impl Codec for LeafNodeInfo {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.public_key.encode(buffer);
        self.credential.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let public_key = X25519PublicKey::decode(cursor)?;
        let credential = BasicCredential::decode(cursor)?;
        Ok(Welcome {
            public_key,
            credential,
        })
    }
}

#[derive(Clone)]
pub struct LeafNodeHashInput {
    pub hash_type: u8 = 0,
    pub info: Optional<LeafNodeInfo>
}

impl Codec for LeafNodeHashInput {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.hash_type.encode(buffer);
        self.info.encode(buffer);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let hash_type = u8::decode(cursor)?;
        let info = Some(LeafNodeInfo::decode(cursor)?);
        Ok(Welcome {
            hash_type,
            info,
        })
    }
}

#[derive(Clone)]
pub struct ParentNodeHashInput {
    pub hash_type: u8 = 1,
    pub public_key: Optional<X25519PublicKey>,
    pub left_hash: Vec<u8>,
    pub right_hash: Vec<u8>
}

impl Codec for Welcome {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.hash_type.encode(buffer);
        self.public_key.encode(buffer);
        encode_vec_u16(buffer, &self.left_hash);
        encode_vec_u16(buffer, &self.right_hash);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let hash_type = u8:decode(cursor)?;
        let public_key = Some(InitSecret::decode(cursor)?);
        let left_hash = decode_vec_u16(cursor)?;
        let right_hash = decode_vec_u16(cursor)?;
        Ok(Welcome {
            hash_type,
            public_key,
            left_hash,
            right_hash
        })
    }
}

#[derive(Clone)]
pub struct DirectPathNode {
    pub public_key: X25519PublicKey,
    pub encrypted_path_secrets: Vec<HpkeCiphertext>
}

impl Codec for DirectPathNode {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.public_key.encode(buffer);
        encode_vec_u16(buffer, &self.encrypted_path_secrets);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let public_key = X25519PublicKey::decode(cursor)?;
        let encrypted_path_secrets = decode_vec_u16(cursor)?;
        Ok(Welcome{ 
            public_key,
            encrypted_path_secrets
         });
    }
}

#[derive(Clone)]
pub struct DirectPath {
    pub nodes: Vec<DirectPathNode>
}

impl Codec for DirectPath {
    fn encode(&self, buffer: &mut Vec<u8>) {
        encode_vec_u16(buffer, &self.nodes);
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let nodes = decode_vec_u16(cursor)?;
        Ok(Welcome{ nodes });
    }
}

#[test]
fn verify_binary_test_vector_resolution() {
    use codec::*;
    use std::fs::File;
    use std::io::Read;
    use treemath;

    let mut file = File::open("test_vectors/resolution.bin").unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let mut cursor = Cursor::new(&buffer);

    let node_secret = NodeSecret::new_random();
    let blank_node = Node::new_blank();
    let full_node = Node::from_secret(&node_secret);

    let n_leaves = u32::decode(&mut cursor).unwrap() as usize;
    let cases: Vec<u8> = decode_vec_u32(&mut cursor).unwrap();
    let number_of_cases = treemath::pow2(2 * n_leaves - 1);
    let number_of_nodes = treemath::node_width(n_leaves);

    let mut cases_cursor = Cursor::new(&cases);
    for case_index in 0..number_of_cases {
        let resolution_case: Vec<u8> = decode_vec_u16(&mut cases_cursor).unwrap();

        let mut nodes: Vec<Node> = Vec::new();
        for node_index in 0..number_of_nodes {
            let is_blank = (case_index >> node_index) & 1 == 1;
            match is_blank {
                true => nodes.push(full_node.clone()),
                false => nodes.push(blank_node.clone()),
            }
        }

        let tree = Tree {
            nodes,
            own_leaf_index: 0,
        };

        let mut resolution_case_cursor = Cursor::new(&resolution_case);
        for node_index in 0..number_of_nodes {
            let test_resolution: Vec<u8> = decode_vec_u8(&mut resolution_case_cursor).unwrap();

            let actual_resolution = tree.resolve(node_index);

            assert_eq!(test_resolution.len(), actual_resolution.len());

            for resolution_index in 0..test_resolution.len() {
                assert_eq!(
                    test_resolution[resolution_index] as usize,
                    actual_resolution[resolution_index]
                );
            }
        }
        assert_eq!(resolution_case_cursor.has_more(), false);
    }
    assert_eq!(cases_cursor.has_more(), false);
    assert_eq!(cursor.has_more(), false);
}
