# Secure Vault Manager

A Bash script to set up and manage a secure, encrypted environment using LUKS, GPG, and SSH configurations.  
This tool is designed to simplify the creation of a 5GB encrypted container that allows you to safely store SSH and GPG keys, use custom SSH client configs, and securely transfer cryptographic assets between machines.

## Features

- 🔐 Create a 5GB LUKS-encrypted EXT4 file container
- 🧠 Automate GPG key pair creation and export
- 📦 Store SSH keys and configurations in a secured vault
- 🧩 Custom SSH client config template (`ssh -F`) support
- ♻️ Import and export SSH and GPG keys
- 🔄 CLI interface for install, open, close, and manage operations
- 🧾 Safe permissions and symbolic link for shell aliases

## Requirements

Ensure the following dependencies are installed:

- `cryptsetup`
- `gpg`
- `ssh`
- `losetup`
- `mkfs.ext4`

## Installation

Run the script to install and initialize the vault:

```bash
./secure-vault.sh install
```

# Usage
Basic commands:

```bash
./secure-vault.sh open           # Mount and open the secure vault
./secure-vault.sh close          # Unmount and close the vault
./secure-vault.sh gpg-generate   # Generate new GPG keypair
./secure-vault.sh gpg-import     # Import existing GPG keys into the vault
./secure-vault.sh gpg-export     # Export GPG keys from vault to system
./secure-vault.sh ssh-import     # Import SSH host config and key into vault
./secure-vault.sh ssh-config     # Generate SSH client config template
./secure-vault.sh aliases        # Create alias file and symlink
./secure-vault.sh status         # Show current vault status
```

To load the aliases in your shell:

source ~/.secure_vault_aliases

# Security Notes

- GPG private keys are sensitive — exporting them is optional and will prompt a warning.
- The LUKS container is protected with strong encryption and requires manual unlocking.
- Alias and configuration files use strict permissions.
