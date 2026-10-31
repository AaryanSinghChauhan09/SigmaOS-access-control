# SigmaOS Access Control

This repository is currently a minimal `no_std` component scaffold. Its library exposes a `Component` value with the fixed name `SigmaOS-access-control`.

It does not currently implement identity management, permission evaluation, policy enforcement, authentication, or authorization. Do not treat the crate as an access-control security boundary.

## Build

From this repository:

```sh
cargo check --lib
```

## License

Apache-2.0. See [`Cargo.toml`](Cargo.toml).
