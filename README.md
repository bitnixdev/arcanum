# Arcanum

A Rust-based file encryption tool that provides secure file management with support for multiple recipients and seamless integration with Nix-based projects.

## Overview

Arcanum is a command-line utility for encrypting and managing sensitive files using the [age](https://github.com/FiloSottile/age) encryption format. It's designed to work well in development environments, particularly those using Nix, by providing a simple interface for encrypting secrets and configuration files.

## Features

- **File Encryption/Decryption**: Encrypt and decrypt files using age encryption
- **Multiple Recipients**: Support for encrypting files to multiple recipients
- **In-place Editing**: Edit encrypted files directly without manual decrypt/encrypt cycles
- **Re-keying**: Update encryption keys for existing files
- **Merge Conflict Resolution**: Handle merge conflicts in encrypted files
- **Nix Integration**: Generate cache files for Nix-based projects
- **SSH Key Support**: Use SSH keys for encryption and decryption

## Installation

### Using Cargo

```bash
cargo install --path .
```

## Usage

### Basic Commands

#### Encrypt a file

```bash
arcanum encrypt <plaintext-file> <encrypted-file>
```

#### Decrypt a file

```bash
arcanum decrypt <encrypted-file> <plaintext-file>
```

#### Edit an encrypted file

```bash
arcanum edit <encrypted-file>
```

Opens the decrypted content in your default editor, then re-encrypts after editing.

#### Re-encrypt files

```bash
arcanum rekey <encrypted-file>
```

Re-encrypts a file to all configured recipients. Useful when adding new recipients or rotating keys.

#### Resolve merge conflicts

```bash
arcanum merge <encrypted-file>
```

Helps resolve merge conflicts in encrypted files by providing a clean merge interface.

#### Generate cache file

```bash
arcanum cache
```

Regenerates cache files for the current project. This is needed when adding new files or changing recipients.

### Identity Management

Use the `--identity` flag to specify which identity file to use for encryption/decryption:

```bash
arcanum --identity ~/.ssh/id_ed25519 decrypt secrets.age secrets.txt
```

## Configuration

Arcanum uses a configuration system that defines:

- **Files**: Which files should be encrypted and their destination paths
- **Recipients**: Who can decrypt the files (SSH public keys or age public keys)
- **Permissions**: File and directory permissions for decrypted files
- **Ownership**: User and group ownership settings

The configuration is typically managed through Nix expressions when used in Nix-based projects.

## Project Structure

When used in a project, Arcanum expects:

- Configuration defining files and recipients
- Encrypted files stored in a designated directory (commonly `secrets/`)
- Cache files for performance optimization
