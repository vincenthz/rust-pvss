rust-pvss
=========

[![Build Status](https://img.shields.io/travis/vincenthz/rust-pvss.svg)](https://travis-ci.org/vincenthz/rust-pvss)

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
