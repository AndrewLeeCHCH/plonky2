# Plonky2

Plonky2 is a SNARK implementation based on techniques from PLONK and FRI. It is the successor of [Plonky](https://github.com/mir-protocol/plonky), which was based on PLONK and Halo.

Plonky2 is built for speed, and features a highly efficient recursive circuit. On a Macbook Pro, recursive proofs can be generated in about 170 ms.


## Documentation

For more details about the Plonky2 argument system, see this [writeup](plonky2.pdf).


## Building

Plonky2 requires a recent nightly toolchain, although we plan to transition to stable in the future.

To use a nightly toolchain for Plonky2 by default, you can run
```
rustup override set nightly
```
in the Plonky2 directory.


## Running

To see recursion performance, one can run this test, which generates a chain of three recursion proofs:

```sh
RUST_LOG=debug RUSTFLAGS=-Ctarget-cpu=native cargo test --release test_recursive_recursive_verifier -- --ignored
```

## Examples

Check out [`examples/src/lib.rs`](./examples/src/lib.rs) for example usage. You can run them all with the following cargo command:

```sh
RUST_LOG=debug RUSTFLAGS=-Ctarget-cpu=native cargo test --release -p plonky2_examples -- --ignored
```


## Copyright

Plonky2 was developed by Polygon Zero (formerly Mir). While we plan to adopt an open source license, we haven't selected one yet, so all rights are reserved for the time being. Please reach out to us if you have thoughts on licensing.


## Disclaimer

This code has not yet been audited, and should not be used in any production systems.

