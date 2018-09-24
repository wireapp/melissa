use eckem::*;
use keys::*;
use sodiumoxide::crypto::hash::sha256::*;
use sodiumoxide::randombytes;
use std::ops::Range;

pub const NODESECRETBYTES: usize = 32;

#[derive(PartialEq, Clone, Copy)]
pub struct NodeSecret(pub [u8; NODESECRETBYTES]);

impl NodeSecret {
    pub fn new_random() -> Self {
        let mut bytes = [0u8; NODESECRETBYTES];
        bytes[..NODESECRETBYTES]
            .clone_from_slice(randombytes::randombytes(NODESECRETBYTES).as_slice());
        NodeSecret(bytes)
    }

    pub fn hash(&mut self) {
        let digest = hash(&self.0[..]);
        self.0 = NodeSecret::from(digest).0;
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut buffer = [0u8; NODESECRETBYTES];
        buffer[..NODESECRETBYTES].clone_from_slice(bytes);
        NodeSecret(buffer)
    }
}

impl From<Digest> for NodeSecret {
    fn from(d: Digest) -> NodeSecret {
        let mut bytes = [0u8; DIGESTBYTES];
        bytes[..DIGESTBYTES].clone_from_slice(&d.0[..DIGESTBYTES]);
        NodeSecret(bytes)
    }
}

impl From<NodeSecret> for Digest {
    fn from(n: NodeSecret) -> Digest {
        let mut bytes = [0u8; NODESECRETBYTES];
        bytes[..NODESECRETBYTES].clone_from_slice(&n.0[..NODESECRETBYTES]);
        Digest(bytes)
    }
}

#[derive(PartialEq, Clone)]
pub struct Node {
    pub secret: Option<NodeSecret>,
    pub dh_public_key: Option<X25519PublicKey>,
    pub dh_private_key: Option<X25519PrivateKey>,
}

impl Node {
    pub fn from_secret(secret: &NodeSecret) -> Node {
        // FIXME keypair should only be computed on demand
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
            dh_public_key: Some(key.clone()),
        }
    }

    pub fn new_blank() -> Node {
        Node {
            secret: None,
            dh_private_key: None,
            dh_public_key: None,
        }
    }
}

pub struct Tree {
    nodes: Vec<Option<Node>>,
    own_leaf_index: usize,
}

impl Tree {
    // -----BEGIN TREE MATH-----
    // FIXME check the math once more
    pub fn log2(n: usize) -> usize {
        let mut r = 0;
        let mut m = n;
        while m > 1 {
            m >>= 1;
            r += 1;
        }
        r
    }

    pub fn pow2(n: usize) -> usize {
        match n {
            0 => 1,
            _ => 2 << (n - 1),
        }
    }

    pub fn level(n: usize) -> usize {
        if (n & 0x01) == 0 {
            return 0;
        }
        let mut k = 0;
        while ((n >> k) & 0x01) == 1 {
            k += 1;
        }
        k
    }

    pub fn node_width(n: usize) -> usize {
        2 * (n - 1) + 1
    }

    pub fn assert_in_range(x: usize, n: usize) {
        if x > Tree::node_width(n) {
            panic!("node index out of range ({} > {})", x, n);
        }
    }

    pub fn root(n: usize) -> usize {
        let w = Tree::node_width(n);
        (1 << Tree::log2(w)) - 1
    }

    pub fn left(x: usize) -> usize {
        if Tree::level(x) == 0 {
            return x;
        }
        x ^ (0x01 << (Tree::level(x) - 1))
    }

    pub fn right(x: usize, n: usize) -> usize {
        Tree::assert_in_range(x, n);
        if Tree::level(x) == 0 {
            return x;
        }
        let mut r = x ^ (0x03 << (Tree::level(x) - 1));
        while r >= Tree::node_width(n) {
            r = Tree::left(r);
        }
        r
    }

    pub fn parent_step(x: usize) -> usize {
        let k = Tree::level(x);
        (x | (1 << k)) & !(1 << (k + 1))
    }

    pub fn parent(x: usize, n: usize) -> usize {
        Tree::assert_in_range(x, n);

        if x == Tree::root(n) {
            return x;
        }
        let mut p = Tree::parent_step(x);
        while p >= Tree::node_width(n) {
            p = Tree::parent_step(p);
        }
        p
    }

    pub fn sibling(x: usize, n: usize) -> usize {
        Tree::assert_in_range(x, n);

        let p = Tree::parent(x, n);
        if x < p {
            return Tree::right(p, n);
        } else if x > p {
            return Tree::left(p);
        }
        // root's sibling is itself
        p
    }

    // Ordered from leaf to root
    // Includes leaf, but not root
    pub fn dirpath(x: usize, n: usize) -> Vec<usize> {
        Tree::assert_in_range(x, n);
        if x == Tree::root(n) {
            return Vec::new();
        }
        let mut dirpath = vec![x];
        let mut parent = Tree::parent(x, n);
        let root = Tree::root(n);
        while parent != root {
            dirpath.push(parent);
            parent = Tree::parent(parent, n);
        }
        dirpath
    }

    // Ordered from leaf to root
    pub fn copath(x: usize, n: usize) -> Vec<usize> {
        Tree::dirpath(x, n)
            .iter()
            .map(|&x| Tree::sibling(x, n))
            .collect()
    }

    // Ordered from left to right
    pub fn frontier(n: usize) -> Vec<usize> {
        assert!(n > 0);

        let last = 2 * (n - 1);
        let mut frontier = Tree::copath(last, n);
        frontier.reverse();

        if !frontier.is_empty() {
            if frontier[frontier.len() - 1] != last {
                frontier.push(last);
            }
        } else {
            frontier.push(0);
        }

        while frontier.len() > 1 {
            let r = frontier[frontier.len() - 1];
            let parent = Tree::parent(r, n);
            if parent != Tree::parent_step(r) {
                break;
            }

            // Replace the last two nodes with their parent
            let length = frontier.len();
            frontier.truncate(length - 2);
            frontier.push(parent);
        }
        frontier
    }

    pub fn shadow(x: usize, n: usize) -> Vec<usize> {
        let mut height = Tree::level(x);
        let mut left = x;
        let mut right = x;
        while height > 0 {
            left = Tree::left(left);
            right = Tree::right(right, n);
            height -= 1;
        }

        // +1 for the end of the range?
        (0..=right - left).map(|x| x + left).collect()
    }

    pub fn leaves(n: usize) -> Vec<usize> {
        Range { start: 0, end: n }.map(|x| 2 * x).collect()
    }

    // -----END TREE MATH-----

    pub fn new_from_leaf(leaf: &Node) -> Tree {
        let mut tree = Tree {
            nodes: vec![Some(leaf.clone())],
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
        let mut nodes: Vec<Option<Node>> = Vec::new();
        for key in keys {
            nodes.push(Some(Node::new_from_public_key(key)));
        }
        let own_node = Node::from_secret(leaf_secret);
        nodes[own_leaf_index] = Some(own_node);
        Tree {
            nodes,
            own_leaf_index,
        }
    }

    pub fn get_tree_size(&self) -> usize {
        self.nodes.len()
    }

    pub fn get_root(&self) -> Node {
        let root_index = Tree::root(self.get_tree_size());
        self.nodes[root_index].clone().unwrap()
    }

    pub fn get_nodes_from_path(&self, path: Vec<usize>) -> Vec<Node> {
        let mut nodes: Vec<Node> = Vec::new();
        for i in path {
            nodes.push(self.nodes[i].clone().unwrap());
        }
        nodes
    }

    pub fn get_public_keys_from_path(&self, path: Vec<usize>) -> Vec<X25519PublicKey> {
        let mut keys = Vec::new();
        for index in path {
            keys.push(self.nodes[index].clone().unwrap().dh_public_key.unwrap());
        }
        keys
    }

    pub fn get_public_key_tree(&self) -> Vec<X25519PublicKey> {
        let mut tree = Vec::new();
        for node in self.nodes.iter() {
            tree.push(node.clone().unwrap().dh_public_key.unwrap());
        }
        tree
    }

    pub fn get_own_leaf(&self) -> Node {
        self.nodes[self.own_leaf_index].clone().unwrap()
    }

    pub fn get_own_leaf_index(&self) -> usize {
        self.own_leaf_index
    }

    pub fn get_leaf_count(&self) -> usize {
        self.get_tree_size() / 2 + 1
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
            self.nodes.resize(max + 1, Some(Node::new_blank()));
        }
        for (node, index) in nodes.iter().zip(path) {
            self.nodes[index] = Some(node.clone());
        }
    }

    pub fn hash_up(index: usize, size: usize, secret: &NodeSecret) -> Vec<Node> {
        // Compute hashes up the tree
        let mut nodes = Vec::new();
        let mut node_secret = *secret;
        let mut dirpath = Tree::dirpath(index, size);
        dirpath.push(Tree::root(size));
        for _ in dirpath {
            let node = Node::from_secret(&node_secret);
            nodes.push(node);
            node_secret.hash();
        }
        nodes
    }

    pub fn kem_to(dirpath_nodes: &[Node], copath_nodes: &[Node]) -> Vec<X25519AESCiphertext> {
        let mut path: Vec<X25519AESCiphertext> = Vec::new();
        assert_eq!(dirpath_nodes.len(), copath_nodes.len());
        for node_pair in dirpath_nodes.iter().zip(copath_nodes.iter()) {
            let (dirpath_node, copath_node) = node_pair;
            let ciphertext = X25519AES::encrypt(
                &copath_node.dh_public_key.clone().unwrap(),
                &dirpath_node.secret.unwrap().0[..],
            );
            path.push(ciphertext);
        }
        path
    }

    pub fn encrypt(
        &self,
        start: usize,
        size: usize,
        frontier_nodes: &[Node],
        secret: NodeSecret,
    ) -> (Vec<X25519PublicKey>, Vec<X25519AESCiphertext>) {
        let mut nodes = Tree::hash_up(start, size, &secret);
        // strip root
        nodes.pop();
        let ciphertexts = Tree::kem_to(&nodes, frontier_nodes);
        let mut public_keys: Vec<X25519PublicKey> = Vec::new();
        for node in nodes {
            public_keys.push(node.dh_public_key.unwrap());
        }
        (public_keys, ciphertexts)
    }

    pub fn decrypt(&self, ciphertexts: &[X25519AESCiphertext]) -> (Vec<usize>, Vec<Node>) {
        let size = self.get_leaf_count() + 1;
        let kem_path = Tree::frontier(size - 1);
        let own_path = Tree::dirpath(self.own_leaf_index, size);
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
        let mut merge_path = Tree::dirpath(self.own_leaf_index, size);
        merge_path.push(Tree::root(size));
        merge_path.drain(0..own_path_index);
        let intersect_ciphertext = ciphertexts[kem_path_index].clone();
        let intersect_node = self.nodes[own_path[own_path_index]].clone().unwrap();
        let private_key = intersect_node.dh_private_key.unwrap();
        let secret = X25519AES::decrypt(&private_key, &intersect_ciphertext);
        let node_secret = NodeSecret::from_bytes(secret.as_slice());
        (
            merge_path,
            Tree::hash_up(own_path[own_path_index], size, &node_secret),
        )
    }

    pub fn apply_kem_path(
        &mut self,
        index: usize,
        size: usize,
        ciphertext: &[X25519AESCiphertext],
        public_keys: &[X25519PublicKey],
    ) {
        let (merge_path, nodes) = self.decrypt(ciphertext);
        self.merge(merge_path, &nodes);
        let public_merge_path = Tree::dirpath(index, size);
        let mut public_nodes = Vec::new();
        for key in public_keys.iter() {
            public_nodes.push(Node::new_from_public_key(key));
        }
        self.merge(public_merge_path, &public_nodes);
    }
}

#[test]
fn test_root() {
    let n = 0x0b;
    let index = Range { start: 0, end: n };
    let a_root = vec![
        0x00, 0x01, 0x03, 0x03, 0x07, 0x07, 0x07, 0x07, 0x0f, 0x0f, 0x0f,
    ];

    let q: Vec<usize> = index.map(|x| Tree::root(x + 1)).collect();
    assert_eq!(q, a_root);
}

#[test]
fn test_relations() {
    let n = 0x0b;
    let e = 21;

    let index = Range { start: 0, end: e };

    let a_left = vec![
        0x00, 0x00, 0x02, 0x01, 0x04, 0x04, 0x06, 0x03, 0x08, 0x08, 0x0a, 0x09, 0x0c, 0x0c, 0x0e,
        0x07, 0x10, 0x10, 0x12, 0x11, 0x14,
    ];

    let a_right = vec![
        0x00, 0x02, 0x02, 0x05, 0x04, 0x06, 0x06, 0x0b, 0x08, 0x0a, 0x0a, 0x0d, 0x0c, 0x0e, 0x0e,
        0x13, 0x10, 0x12, 0x12, 0x14, 0x14,
    ];

    let a_parent = vec![
        0x01, 0x03, 0x01, 0x07, 0x05, 0x03, 0x05, 0x0f, 0x09, 0x0b, 0x09, 0x07, 0x0d, 0x0b, 0x0d,
        0x0f, 0x11, 0x13, 0x11, 0x0f, 0x13,
    ];

    let a_sibling = vec![
        0x02, 0x05, 0x00, 0x0b, 0x06, 0x01, 0x04, 0x13, 0x0a, 0x0d, 0x08, 0x03, 0x0e, 0x09, 0x0c,
        0x0f, 0x12, 0x14, 0x10, 0x07, 0x11,
    ];

    assert_eq!(
        index.clone().map(|x| Tree::left(x)).collect::<Vec<usize>>(),
        a_left
    );

    assert_eq!(
        index
            .clone()
            .map(|x| Tree::right(x, n))
            .collect::<Vec<usize>>(),
        a_right
    );
    assert_eq!(
        index
            .clone()
            .map(|x| Tree::parent(x, n))
            .collect::<Vec<usize>>(),
        a_parent
    );
    assert_eq!(
        index
            .clone()
            .map(|x| Tree::sibling(x, n))
            .collect::<Vec<usize>>(),
        a_sibling
    );
}

#[test]
fn test_frontier() {
    let n = 0x0b;

    let a_frontier = vec![
        vec![0x00],
        vec![0x01],
        vec![0x01, 0x04],
        vec![0x03],
        vec![0x03, 0x08],
        vec![0x03, 0x09],
        vec![0x03, 0x09, 0x0c],
        vec![0x07],
        vec![0x07, 0x10],
        vec![0x07, 0x11],
        vec![0x07, 0x11, 0x14],
    ];

    for x in 0..n {
        let f = Tree::frontier(x + 1);
        assert_eq!(f, a_frontier[x]);
    }
}

#[test]
fn test_paths() {
    let n = 0x0b;

    let a_dirpath = vec![
        vec![0, 1, 3, 7],
        vec![1, 3, 7],
        vec![2, 1, 3, 7],
        vec![3, 7],
        vec![4, 5, 3, 7],
        vec![5, 3, 7],
        vec![6, 5, 3, 7],
        vec![7],
        vec![8, 9, 11, 7],
        vec![9, 11, 7],
        vec![10, 9, 11, 7],
        vec![11, 7],
        vec![12, 13, 11, 7],
        vec![13, 11, 7],
        vec![14, 13, 11, 7],
        vec![],
        vec![16, 17, 19],
        vec![17, 19],
        vec![18, 17, 19],
        vec![19],
        vec![20, 19],
    ];

    let a_copath = vec![
        vec![2, 5, 11, 19],
        vec![5, 11, 19],
        vec![0, 5, 11, 19],
        vec![11, 19],
        vec![6, 1, 11, 19],
        vec![1, 11, 19],
        vec![4, 1, 11, 19],
        vec![19],
        vec![10, 13, 3, 19],
        vec![13, 3, 19],
        vec![8, 13, 3, 19],
        vec![3, 19],
        vec![14, 9, 3, 19],
        vec![9, 3, 19],
        vec![12, 9, 3, 19],
        vec![],
        vec![18, 20, 7],
        vec![20, 7],
        vec![16, 20, 7],
        vec![7],
        vec![17, 7],
    ];

    let a_shadow = vec![
        vec![0],
        vec![0, 1, 2],
        vec![2],
        vec![0, 1, 2, 3, 4, 5, 6],
        vec![4],
        vec![4, 5, 6],
        vec![6],
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
        vec![8],
        vec![8, 9, 10],
        vec![10],
        vec![8, 9, 10, 11, 12, 13, 14],
        vec![12],
        vec![12, 13, 14],
        vec![14],
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ],
        vec![16],
        vec![16, 17, 18],
        vec![18],
        vec![16, 17, 18, 19, 20],
        vec![20],
    ];

    for x in 0..Tree::node_width(n) {
        let d = Tree::dirpath(x, n);
        assert_eq!(d, a_dirpath[x]);

        let c = Tree::copath(x, n);
        assert_eq!(c, a_copath[x]);

        let s = Tree::shadow(x, n);
        assert_eq!(s, a_shadow[x]);
    }
}
