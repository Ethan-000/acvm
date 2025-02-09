# Changelog

## [0.15.1](https://github.com/noir-lang/acvm/compare/brillig_vm-v0.15.0...brillig_vm-v0.15.1) (2023-06-20)


### Features

* **brillig:** Allow dynamic-size foreign calls ([#370](https://github.com/noir-lang/acvm/issues/370)) ([5ba0349](https://github.com/noir-lang/acvm/commit/5ba0349420cc1b20113cb5e96490a0808a769757))


### Bug Fixes

* **brillig:** remove register initialization check ([#392](https://github.com/noir-lang/acvm/issues/392)) ([1a53143](https://github.com/noir-lang/acvm/commit/1a531438b5c1ab7ce8c4bd599dda3515bdd5cfcd))

## [0.15.0](https://github.com/noir-lang/acvm/compare/brillig_vm-v0.14.2...brillig_vm-v0.15.0) (2023-06-15)


### ⚠ BREAKING CHANGES

* **brillig:** Accept multiple inputs/outputs for foreign calls ([#367](https://github.com/noir-lang/acvm/issues/367))

### Features

* Add method to generate updated `Brillig` opcode from `UnresolvedBrilligCall` ([#363](https://github.com/noir-lang/acvm/issues/363)) ([fda5dbe](https://github.com/noir-lang/acvm/commit/fda5dbe57c28dc4bc28dfd8fe0a4a8ba29635393))
* **brillig:** Accept multiple inputs/outputs for foreign calls ([#367](https://github.com/noir-lang/acvm/issues/367)) ([78d62b2](https://github.com/noir-lang/acvm/commit/78d62b2d7c1c8b884e1f3fe7983e6e5029700e70))
* **brillig:** Set `VMStatus` to `Failure` rather than panicking on invalid foreign call response ([#375](https://github.com/noir-lang/acvm/issues/375)) ([c49d82c](https://github.com/noir-lang/acvm/commit/c49d82c99c73c60e264585ed201af2b6a2b7ee0f))


### Bug Fixes

* **brillig:** Correct signed division implementation ([#356](https://github.com/noir-lang/acvm/issues/356)) ([4eefda0](https://github.com/noir-lang/acvm/commit/4eefda01e7b371035314f77631df4687608b4782))
* **brillig:** Explicitly wrap on arithmetic operations ([#365](https://github.com/noir-lang/acvm/issues/365)) ([c0544a9](https://github.com/noir-lang/acvm/commit/c0544a99930d3c8d534376c8f8a91645a39aecf8))

## [0.14.2](https://github.com/noir-lang/acvm/compare/brillig_vm-v0.14.1...brillig_vm-v0.14.2) (2023-06-08)


### Bug Fixes

* **brillig:** expand memory with zeroes on store ([#350](https://github.com/noir-lang/acvm/issues/350)) ([4d2dadd](https://github.com/noir-lang/acvm/commit/4d2dadd3acd9dc25f0feae865b74cbaea7250f3d))

## [0.14.1](https://github.com/noir-lang/acvm/compare/brillig_vm-v0.14.0...brillig_vm-v0.14.1) (2023-06-07)


### Miscellaneous Chores

* **brillig_vm:** Synchronize acvm versions

## [0.14.0](https://github.com/noir-lang/acvm/compare/brillig_vm-v0.13.3...brillig_vm-v0.14.0) (2023-06-06)


### Miscellaneous Chores

* **brillig_vm:** Synchronize acvm versions

## [0.13.3](https://github.com/noir-lang/acvm/compare/brillig_vm-v0.13.2...brillig_vm-v0.13.3) (2023-06-05)


### Bug Fixes

* Empty commit to trigger release-please ([e8f0748](https://github.com/noir-lang/acvm/commit/e8f0748042ef505d59ab63266d3c36c5358ee30d))

## [0.13.2](https://github.com/noir-lang/acvm/compare/brillig_vm-v0.13.1...brillig_vm-v0.13.2) (2023-06-02)


### Miscellaneous Chores

* **brillig_vm:** Synchronize acvm versions

## [0.13.1](https://github.com/noir-lang/acvm/compare/brillig_vm-v0.1.1...brillig_vm-v0.13.1) (2023-06-01)


### Bug Fixes

* **brillig:** Proper error handling for Brillig failures ([#329](https://github.com/noir-lang/acvm/issues/329)) ([cffa110](https://github.com/noir-lang/acvm/commit/cffa110c8df30ee3dd8b635d38b17b1fcd54b03e))
