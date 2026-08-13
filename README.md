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

### Nix / NixOS

The flake exposes `packages.<system>.arcanum`, `overlays.default`, and integration
modules for NixOS, nix-darwin, Home Manager, and nix-chips development shells.
Use either the overlay:

```nix
{
  inputs.arcanum.url = "github:bitnixdev/arcanum";

  outputs = {nixpkgs, arcanum, ...}: {
    nixosConfigurations.example = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        arcanum.nixosModules.default
        ({pkgs, ...}: {
          nixpkgs.overlays = [arcanum.overlays.default];
          environment.systemPackages = [pkgs.arcanum];
        })
      ];
    };
  };
}
```

Or reference the package without an overlay:

```nix
environment.systemPackages = [
  inputs.arcanum.packages.${pkgs.system}.arcanum
];
```

The other module outputs are:

```nix
arcanum.darwinModules.default
arcanum.homeManagerModules.default
arcanum.chipsModules.default
```

Pass `chipsModules.default` through `modules.chips` when using nix-chips:

```nix
chips.lib.mkFlake {
  inherit inputs;
  modules.chips = [arcanum.chipsModules.default];
  nixpkgs.overlays = [arcanum.overlays.default];
}
```

Build or run from the flake directly:

```bash
nix build github:bitnixdev/arcanum
nix run github:bitnixdev/arcanum -- --help
```

### Using Cargo

```bash
cargo install --path .
```

## Versioning and releases

Pushes to `master` publish the SemVer declared in `Cargo.toml` as a GitHub
release, with binaries for Linux, macOS, and Windows. Bump the package version
before pushing; the release fails rather than overwrite an existing tag.

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

#### Decrypt to stdout (for Git textconv)

```bash
arcanum textconv <encrypted-file>
```

Example Git setup:

```bash
git config diff.arcanum.textconv "arcanum textconv %f"
```

```gitattributes
secrets/*.age diff=arcanum
```

#### Edit an encrypted file

```bash
arcanum edit <encrypted-file>
```

Opens the decrypted content in your default editor, then re-encrypts after editing. When run
inside a nix-chips dev shell, it also updates the configured decrypted destination for that
secret without requiring `direnv reload`. Relative encrypted-file paths are resolved from the
project root, so the command behaves the same way from any directory in the project.

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

#### Show plaintext diffs for changed secrets

```bash
arcanum diff [--from <rev>] [--vcs auto|jj|git] [encrypted-file ...]
```

Shows unified plaintext diffs for changed age-encrypted files. By default this uses the current jj
working copy when available, or git staged/working-tree changes otherwise. Use `--from` to compare
the current files with an arbitrary jj revset, bookmark, git commit, or branch.

#### Generate cache file

```bash
arcanum cache
```

Regenerates the cache file for the current project. This is needed when adding new files or changing recipients.

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
