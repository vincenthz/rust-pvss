# Rust PVSS (Publicly Verifiable Secret Sharing)

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![APACHE-2 licensed][apache2-badge]][apache2-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/pvss.svg
[crates-url]: https://crates.io/crates/pvss
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[apache2-badge]: https://img.shields.io/badge/license-APACHE--2-blue.svg
[mit-url]: https://github.com/vincenthz/rust-pvss/blob/master/LICENSE-MIT
[apache2-url]: https://github.com/vincenthz/rust-pvss/blob/master/LICENSE-APACHE
[actions-badge]: https://github.com/vincenthz/rust-pvss/workflows/CI/badge.svg
[actions-url]: https://github.com/vincenthz/rust-pvss/actions?query=workflow%3ACI+branch%3Amaster

[API Docs](https://docs.rs/pvss/latest/pvss)

This package provide secret sharing schemes which are publicly veriable and recoverable
using a simple `t` out of `n` `(t,n)` threshold system.

A secret value can be **escrow** to N encrypted shares.

This secret value can be recovered by decrypting at least `t` amount of shares,
and combining them.

Publicly Verifiable Secret Sharing (PVSS) scheme implemented:

* [Schoenmaker](http://www.win.tue.nl/~berry/papers/crypto99.pdf)
* [SCRAPE](https://eprint.iacr.org/2017/216.pdf)

Crypto
------

For now the implementation uses the P256R1 elliptic curve by default, through
the rust-openssl package.  In the future, the plan is to add support for all
curves that support the necessary operations.
