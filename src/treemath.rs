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
use std::ops::Range;

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
    if x > node_width(n) {
        panic!("node index out of range ({} > {})", x, n);
    }
}

pub fn root(n: usize) -> usize {
    let w = node_width(n);
    (1 << log2(w)) - 1
}

pub fn left(x: usize) -> usize {
    if level(x) == 0 {
        return x;
    }
    x ^ (0x01 << (level(x) - 1))
}

pub fn right(x: usize, n: usize) -> usize {
    assert_in_range(x, n);
    if level(x) == 0 {
        return x;
    }
    let mut r = x ^ (0x03 << (level(x) - 1));
    while r >= node_width(n) {
        r = left(r);
    }
    r
}

pub fn parent_step(x: usize) -> usize {
    let k = level(x);
    (x | (1 << k)) & !(1 << (k + 1))
}

pub fn parent(x: usize, n: usize) -> usize {
    if x == root(n) {
        return x;
    }

    let l0 = level(x);
    let l1 = level(x) + 1;
    let distance = pow2(l1);
    let left_offset = pow2(l0) - 1;

    let parity = (x - left_offset) / distance;
    let p = if parity & 0x01 == 1 {
        x - (distance / 2)
    } else {
        x + (distance / 2)
    };

    if p >= node_width(n) {
        parent(p, n)
    } else {
        p
    }
}

pub fn sibling(x: usize, n: usize) -> usize {
    assert_in_range(x, n);

    let p = parent(x, n);
    if x < p {
        return right(p, n);
    } else if x > p {
        return left(p);
    }
    // root's sibling is itself
    p
}

// Ordered from leaf to root
// Includes leaf, but not root
pub fn dirpath(x: usize, n: usize) -> Vec<usize> {
    assert_in_range(x, n);
    if x == root(n) {
        return Vec::new();
    }
    let mut dirpath = vec![x];
    let mut node_parent = parent(x, n);
    let root = root(n);
    while node_parent != root {
        dirpath.push(node_parent);
        node_parent = parent(node_parent, n);
    }
    dirpath
}

// Ordered from leaf to root
pub fn copath(x: usize, n: usize) -> Vec<usize> {
    dirpath(x, n).iter().map(|&x| sibling(x, n)).collect()
}

pub fn leaves(n: usize) -> Vec<usize> {
    Range { start: 0, end: n }.map(|x| 2 * x).collect()
}

#[derive(Clone, Copy)]
pub enum FunctionType {
    OneArg(fn(usize) -> usize),
    TwoArgs(fn(usize, usize) -> usize),
    TwoArgsPath(fn(usize, usize) -> Vec<usize>),
}

pub enum ReturnType {
    Primitive(Vec<usize>),
    Vector(Vec<Vec<usize>>),
}

pub fn gen_vector(range_start: usize, range_end: usize, size: usize, ft: FunctionType) -> Vec<u8> {
    let range = Range {
        start: range_start,
        end: range_end,
    };
    let mut test_vector: Vec<u32> = Vec::new();
    let mut test_vector_2d: Vec<Vec<u32>> = Vec::new();
    for i in range {
        match ft {
            FunctionType::OneArg(f) => {
                test_vector.push(f(i) as u32);
            }
            FunctionType::TwoArgs(f) => {
                test_vector.push(f(i, size) as u32);
            }
            FunctionType::TwoArgsPath(f) => {
                let sub_vector_usize = f(i, size);
                let mut sub_vector_u32 = Vec::new();
                sub_vector_usize
                    .iter()
                    .for_each(|&x| sub_vector_u32.push(x as u32));
                test_vector_2d.push(sub_vector_u32);
            }
        }
    }

    let mut buffer = Vec::new();

    match ft {
        FunctionType::OneArg(_) => {
            encode_vec_u32(&mut buffer, &test_vector);
        }
        FunctionType::TwoArgs(_) => {
            encode_vec_u32(&mut buffer, &test_vector);
        }
        FunctionType::TwoArgsPath(_) => {
            for e in test_vector_2d.iter_mut() {
                (e.len() as u32).encode(&mut buffer);
                encode_vec_u32(&mut buffer, e);
            }
        }
    }
    buffer
}

pub fn read_vector(rt: &ReturnType, buffer: &[u8]) -> ReturnType {
    let mut vector = Vec::new();
    let mut vector2d = Vec::new();
    let mut cursor = Cursor::new(buffer);

    match *rt {
        ReturnType::Primitive(_) => {
            let vector_usize: Vec<u32> = decode_vec_u32(&mut cursor).unwrap();
            vector_usize.iter().for_each(|&x| vector.push(x as usize));
            ReturnType::Primitive(vector)
        }
        ReturnType::Vector(_) => {
            let size = u32::decode(&mut cursor).unwrap();
            //let size = cursor.take(1).unwrap()[0];
            for _ in 0..size {
                let mut sub_vector = Vec::new();
                let sub_vector_usize: Vec<u32> = decode_vec_u32(&mut cursor).unwrap();
                sub_vector_usize
                    .iter()
                    .for_each(|&x| sub_vector.push(x as usize));
                vector2d.push(sub_vector);
            }
            ReturnType::Vector(vector2d)
        }
    }
}

#[test]
fn print_test_vectors() {
    use utils::*;

    let size = 255;
    println!(
        "Test vector for root() with size {}:\n{}",
        size,
        bytes_to_hex(&gen_vector(1, size, size, FunctionType::OneArg(root),))
    );
    println!(
        "Test vector for level() with size {}:\n{}",
        size,
        bytes_to_hex(&gen_vector(0, size - 1, size, FunctionType::OneArg(level),))
    );
    println!(
        "Test vector for node_width() with size {}:\n{}",
        size,
        bytes_to_hex(&gen_vector(1, size, size, FunctionType::OneArg(node_width),))
    );
    println!(
        "Test vector for left() with size {}:\n{}",
        size,
        bytes_to_hex(&gen_vector(0, size - 1, size, FunctionType::OneArg(left),))
    );
    println!(
        "Test vector for parent_step() with size {}:\n{}",
        size,
        bytes_to_hex(&gen_vector(
            0,
            size - 1,
            size,
            FunctionType::OneArg(parent_step),
        ))
    );
    println!(
        "Test vector for right() with size {}:\n{}",
        size,
        bytes_to_hex(&gen_vector(0, size - 1, size, FunctionType::TwoArgs(right),))
    );
    println!(
        "Test vector for parent() with size {}:\n{}",
        size,
        bytes_to_hex(&gen_vector(
            0,
            size - 1,
            size,
            FunctionType::TwoArgs(parent),
        ))
    );
    println!(
        "Test vector for sibling() with size {}:\n{}",
        size,
        bytes_to_hex(&gen_vector(
            0,
            size - 1,
            size,
            FunctionType::TwoArgs(sibling),
        ))
    );
    println!(
        "Test vector for dirpath() with size {}:\n{}",
        size,
        bytes_to_hex(&gen_vector(
            0,
            size - 1,
            size,
            FunctionType::TwoArgsPath(dirpath),
        ))
    );
    println!(
        "Test vector for copath() with size {}:\n{}",
        size,
        bytes_to_hex(&gen_vector(
            0,
            size - 1,
            size,
            FunctionType::TwoArgsPath(copath),
        ))
    );
}

#[test]
fn verify_binary_test_vector_treemath() {
    use codec::*;
    use std::fs::File;
    use std::io::Read;
    use treemath;

    let mut file = File::open("test_vectors/tree_math.bin").unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let mut cursor = Cursor::new(&buffer);

    let tree_size = u32::decode(&mut cursor).unwrap() as usize;

    let root: Vec<u32> = decode_vec_u32(&mut cursor).unwrap();
    let left: Vec<u32> = decode_vec_u32(&mut cursor).unwrap();
    let right: Vec<u32> = decode_vec_u32(&mut cursor).unwrap();
    let parent: Vec<u32> = decode_vec_u32(&mut cursor).unwrap();
    let sibling: Vec<u32> = decode_vec_u32(&mut cursor).unwrap();

    for i in 0..root.len() {
        assert_eq!(root[i] as usize, treemath::root(i + 1));
    }
    for i in 0..left.len() {
        assert_eq!(left[i] as usize, treemath::left(i));
    }
    for i in 0..right.len() {
        assert_eq!(right[i] as usize, treemath::right(i, tree_size));
    }
    for i in 0..parent.len() {
        assert_eq!(parent[i] as usize, treemath::parent(i, tree_size));
    }
    for i in 0..sibling.len() {
        assert_eq!(sibling[i] as usize, treemath::sibling(i, tree_size));
    }
    assert_eq!(cursor.has_more(), false);
}
