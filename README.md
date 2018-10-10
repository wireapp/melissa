# melissa

![build status](https://travis-ci.org/wireapp/melissa.svg?branch=master)

This is a PoC implementation of [Messaging Layer Security](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md) (using TreeKEM) in Rust.

## Dependencies

 - [libsodium](https://github.com/jedisct1/libsodium)

## Build

 - install libsodium (and make sure it can be found by using something like pkg-config)
 - run `cargo build`

## Test

`cargo test`
