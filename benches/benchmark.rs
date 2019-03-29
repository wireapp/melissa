// Wire
// Copyright (C) 2019 Wire Swiss GmbH
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

#[macro_use]
extern crate criterion;
extern crate melissa;
extern crate sodiumoxide;

use criterion::Criterion;
use melissa::crypto::aesgcm::*;
use melissa::crypto::eckem::*;
use melissa::crypto::hkdf::*;
use melissa::group::*;
use melissa::keys::*;
use melissa::utils::*;
use sodiumoxide::randombytes;

const DATA: &'static [u8; 1 * 1024] = &[1u8; 1 * 1024];

// Crypto

fn hkdf() {
    let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_to_bytes("000102030405060708090a0b0c");
    let len = 32;

    let prk = extract(Salt(&salt), Input(&ikm));
    let _okm = expand(prk, Info(DATA), len);
}

fn aes128_seal() {
    let key: Aes128Key = Aes128Key::from(randombytes::randombytes(AES128KEYBYTES));
    let nonce = Nonce::new_random();
    let _encrypted = aes_128_seal(DATA, &key, &nonce).unwrap();
}

fn aes128_open(ciphertext: &[u8], key: &Aes128Key, nonce: &Nonce) {
    let _decrypted = aes_128_open(ciphertext, key, nonce).unwrap();
}

fn eckem_encrypt() {
    let kp = X25519KeyPair::new_random();
    let _encrypted = X25519AES::encrypt(&kp.public_key, DATA).unwrap();
}

fn eckem_decrypt(private_key: &X25519PrivateKey, ciphertext: &X25519AESCiphertext) {
    let _decrypted = X25519AES::decrypt(private_key, ciphertext).unwrap();
}

// UserInitKeys

fn create_uik_bundle(identity: &Identity) -> UserInitKeyBundle {
    UserInitKeyBundle::new(&identity)
}

fn large_group() {
    const GROUPSIZE: usize = 10;

    let mut identities: Vec<Identity> = Vec::new();
    let mut credentials: Vec<BasicCredential> = Vec::new();
    let mut uiks: Vec<UserInitKeyBundle> = Vec::new();
    let mut groups: Vec<Group> = Vec::new();

    for i in 0..GROUPSIZE {
        let identity = Identity::random();
        identities.push(identity.clone());
        let credential = BasicCredential {
            identity: format!("Member {}", i).as_bytes().to_vec(),
            public_key: identity.public_key,
        };
        credentials.push(credential.clone());
        uiks.push(UserInitKeyBundle::new(&identity));
        groups.push(Group::new(identity, credential, GroupId::random()));
    }

    for i in 0..GROUPSIZE {
        for j in 0..GROUPSIZE {
            if i != j {
                let (_welcome_alice_bob, add_alice_bob) =
                    groups[i].create_add(credentials[j].clone(), &uiks[j].init_key);
                groups[i].process_add(&add_alice_bob);
            }
        }
    }
}

// Groups

fn create_group() {
    // Define identities
    let alice_identity = Identity::random();
    let bob_identity = Identity::random();

    let alice_credential = BasicCredential {
        identity: "Alice".as_bytes().to_vec(),
        public_key: alice_identity.public_key,
    };
    let bob_credential = BasicCredential {
        identity: "Bob".as_bytes().to_vec(),
        public_key: bob_identity.public_key,
    };

    // Generate UserInitKeys
    let bob_init_key_bundle = UserInitKeyBundle::new(&bob_identity);
    let bob_init_key = bob_init_key_bundle.init_key.clone();

    // Create a group with Alice
    let mut group_alice = Group::new(alice_identity, alice_credential, GroupId::random());

    // Alice adds Bob
    let (welcome_alice_bob, add_alice_bob) = group_alice.create_add(bob_credential, &bob_init_key);
    group_alice.process_add(&add_alice_bob);

    let mut group_bob = Group::new_from_welcome(bob_identity, &welcome_alice_bob);
    assert_eq!(group_alice.get_init_secret(), group_bob.get_init_secret());

    // Bob updates
    let update_bob = group_bob.create_update();
    group_bob.process_update(1, &update_bob);
    group_alice.process_update(1, &update_bob);
    assert_eq!(group_alice.get_init_secret(), group_bob.get_init_secret());
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("HKDF extract & expand", |b| b.iter(|| hkdf()));
    c.bench_function("ECKEM encrypt", |b| b.iter(|| eckem_encrypt()));
    c.bench_function("ECKEM decrypt", |b| {
        b.iter_with_setup(
            || {
                let kp = X25519KeyPair::new_random();
                let encrypted = X25519AES::encrypt(&kp.public_key, DATA).unwrap();
                (kp.private_key, encrypted)
            },
            |(public_key, encrypted)| eckem_decrypt(&public_key, &encrypted),
        )
    });
    c.bench_function("AES128GCM encrypt", |b| b.iter(|| aes128_seal()));
    c.bench_function("AES128GCM decrypt", |b| {
        b.iter_with_setup(
            || {
                let key: Aes128Key = Aes128Key::from(randombytes::randombytes(AES128KEYBYTES));
                let nonce = Nonce::new_random();
                let ciphertext = aes_128_seal(DATA, &key, &nonce).unwrap();
                (ciphertext, key, nonce)
            },
            |(ciphertext, key, nonce)| aes128_open(&ciphertext, &key, &nonce),
        )
    });
    c.bench_function("UserInitKey create bundle", |b| {
        b.iter_with_setup(
            || {
                let identity = Identity::random();
                identity
            },
            |identity| create_uik_bundle(&identity),
        )
    });
    c.bench_function("Create group: Alice & Bob", |b| b.iter(|| create_group()));
    c.bench_function("Create large group", |b| b.iter(|| large_group()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
