# synchronized-stems-media

Shared audio-only implementation of the frozen synchronized-stems v1 media
contract.

The crate provides:

- semantic validation for the authoritative reliable source map/config;
- the exact 84-byte, network-big-endian `SST1` datagram header;
- closed generation, source, operation, media-class, FEC and MTU binding;
- a mandatory external AEAD opener, with no permissive implementation;
- authenticated-symbol grouping followed by an explicit FEC recovery boundary;
- immutable complete/deadline epoch release with explicit required/optional
  missing state and bounded pending/released windows.

It is additive to the existing numbered `MAE1` transport. Production ingress,
mesh and Nexus adapters still need to supply real capability facts, key-epoch
AEAD and the selected FEC implementation before this becomes a live path.

Validation:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```
