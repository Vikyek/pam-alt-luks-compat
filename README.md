# PAM Alternative Password & LUKS Compatibility Toolset

This project provides a robust, permanent solution for integrating alternative password authentication on Arch Linux, ensuring complete compatibility with `su`/`sudo`, screen locking, and automated GNOME Keyring decryption. Additionally, it automates in-place LUKS encryption for secondary partitions with a themed, formatted terminal progress bar.

---

## Features

1.  **Keyring Compatibility (`pam_keyring_compat.so`):**
    Allows GNOME Keyring to unlock automatically when logging in with an alternative password. Stores the main password encrypted via AES-256-GCM in `/etc/pam_keyring_compat.vault` (keys derived using PBKDF2), decrypting it at login to populate the PAM authentication token.
2.  **Persistent Systemd Watcher:**
    Monitors core PAM files (`system-auth`, `su`, `su-l`, `vlock`, and quickshell `passwd`) for modifications or package overrides (such as `pambase` updates or manual `.pacnew` merges). Re-applies configuration patches automatically.
3.  **Unified Password Tool (`pam_keyring_compat_tool`):**
    Enrolls your main and alternative passwords into the Keyring Vault, and handles automatic/queued registration of passwords into the LUKS slots on your partition.
4.  **CLI Progress Monitor (`crypt-progress`):**
    A themed, rounded-corner terminal progress card monitor designed to mirror the color layouts and ASCII logo of your desktop's Caelestia fetch configuration. Includes an interactive arrow-key theme selector (`-t`/`--theme-menu`).

---

## Directory Structure

```text
pam-alt-luks-compat/
├── hooks/
│   └── patch-pam-alternative-passwords.hook       # Pacman hook
├── src/
│   ├── crypt_progress.py                          # Themed CLI monitor
│   ├── pam_keyring_compat.c                       # PAM module & tool C source
│   └── patch_pam_alternative_passwords.py         # PAM configuration patch script
├── systemd/
│   ├── patch-pam-alternative-passwords.path       # Watcher path unit
│   └── patch-pam-alternative-passwords.service    # Watcher service unit
├── Makefile                                       # Automation script
├── README.md                                      # Documentation
└── .gitignore                                     # Git ignore patterns
```

---

## Installation

To compile the binaries, install scripts and modules, register systemd watchers, and apply the PAM patches in one command, run:

```bash
sudo make install
```

To clean up all system configurations, disable the systemd services, and cleanly restore original PAM files from backup, run:

```bash
sudo make uninstall
```

To clear local build artifacts:

```bash
make clean
```

---

## Post-Install Usage

### 1. Unified Password Registration (Keyring + LUKS)
To configure the secure keyring compatibility vault and register/queue your passwords for the LUKS partition (`/dev/sdc1`), run:

```bash
sudo pam_keyring_compat_tool --set v
```
*   *Note:* If the partition is not yet encrypted, the tool will offer to automatically shrink your filesystem (supporting online shrinking for Btrfs and offline for Ext2/3/4) by 32MB, generate cryptographic keys, initialize LUKS2, and launch background in-place encryption. If the partition is already encrypting, passwords are queued securely at `/run/luks_keys_to_add.tmp` and enrolled once done.

### 2. Monitoring Encryption progress
You can watch the in-place encryption using the themed visual monitor card:

```bash
sudo crypt-progress
```

To select a theme (like **Caelestia**, **Midnight Cyber**, **Minimalist**, **Forest**, or **Oceanic**):

```bash
sudo crypt-progress --theme-menu
```
*   *Note:* Themes are saved locally in the user config folder at `~/.config/crypt-progress/config.json`.
