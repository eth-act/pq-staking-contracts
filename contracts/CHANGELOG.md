# Changelog

## 1.0.0 (2026-10-17)


### ⚠ BREAKING CHANGES

* registration requests must carry a valid leanXMSS-K proof of possession.
* registration calldata and system-call output formats changed.
* registration calldata and system-call output formats changed.

### Features

* add EIP-8413 staking and registration contracts with release pipeline ([81545cc](https://github.com/eth-act/pq-staking-contracts/commit/81545cc8e242806aac6b126d52887361935aa229))
* EIP-7002-style system contracts for registration, consolidation and withdrawal ([49ce0c6](https://github.com/eth-act/pq-staking-contracts/commit/49ce0c6756084e4e5e5446dfead08d05f347d573))
* fix PQ key and signature sizes at 32 and 2400 bytes ([d54dd92](https://github.com/eth-act/pq-staking-contracts/commit/d54dd92aa44cb65e6b1dceb15184e062a8ae3eb1))
* PQ-only registration, no BLS key ([e2c8c93](https://github.com/eth-act/pq-staking-contracts/commit/e2c8c937c7fffd5b0321b758c20acb389fb99772))
* verify registration proofs of possession on the EL (leanXMSS-K) ([a9a7509](https://github.com/eth-act/pq-staking-contracts/commit/a9a7509661b6c05482db44bfe59bbb6c6e1d9258))
