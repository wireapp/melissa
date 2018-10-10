# melissa

This is a PoC implementation of [Messaging Layer Security](https://github.com/ekr/mls-protocol/blob/master/draft-barnes-mls-protocol.md) (using TreeKEM) in Rust.

## Dependencies

 - [libsodium](https://github.com/jedisct1/libsodium)

## Build

 - install libsodium (and make sure it can be found with something like pkg-config)
 - run `cargo build`

## Test

`cargo test`