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
    c.bench_function("Create group: Alice & Bob", |b| b.iter(|| create_group()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
