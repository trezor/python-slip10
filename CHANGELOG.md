# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] - 2026-02-02

### Added

- A new method `get_fingerprint()` was added.

### Changed

- Drop base58 dependency. Port base58 code directly in-tree as a `base58` module.
- Drop ecdsa dependency. Replace with own implementation of point addition.

## [1.0.1] - 2024-09-03

- Support Python 3.8

## [1.0.0] - 2024-08-20

- First release forked from Antoine Poinsot's python-bip32.
