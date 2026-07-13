# PAM Alternative Password & LUKS Compatibility Toolset

This project provides a robust, permanent solution for integrating alternative password authentication on Arch Linux, ensuring complete compatibility with `su`/`sudo`, screen locking, and automated GNOME Keyring decryption. Additionally, it automates in-place LUKS encryption for secondary partitions with a themed, formatted terminal progress bar.

---

## Features

1.  **Keyring Compatibility (`pam_keyring_compat.so`):**
    Allows GNOME Keyring to unlock automatically when logging in with an alternative password. Stores the main password encrypted via AES-256-GCM in `/etc/pam_keyring_compat.vault` (keys derived using PBKDF2), decrypting it at login to populate the PAM authentication token.
2.  **Persistent Systemd Watcher:**
    Monitors core PAM files (`system-auth`, `su`, `su-l`, `vlock`, and quickshell `passwd`) for modifications or package overrides (such as `pambase` updates or manual `.pacnew` merges). Re-applies configuration patches automatically.
3.  **Dynamic Partition & Passphrase Tool (`pam_keyring_compat_tool`):**
    Enrolls your passwords into the Keyring Vault, dynamically scans all system partitions, and automatically enrolls them into LUKS slots.
    *   **Self-Healing Keyfile Restoration:** If auto-unlock keyfiles (`data.key`/`data.key.backup`) are missing/deleted, it automatically regenerates them and prompts for your existing LUKS passphrase to authorize enrollment.
    *   **Passphrase Fallback:** Falls back to direct passphrase authorization if keyfiles fail validation.
    *   **Offline Root Encryption Script:** If an unencrypted root partition is found, it offers to generate a custom, ready-to-run chrooted script (`~/encrypt-root-offline.sh`) to perform offline in-place Btrfs/Ext4 root partition encryption from a Live USB.
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
To configure the secure keyring compatibility vault and enroll your passwords for all candidate partitions, run:

```bash
sudo pam_keyring_compat_tool --set v
```
*   *Note on Dynamic Partition Scanning:* The tool automatically detects all partitions on the system, excluding boot/EFI and the active root partition. It will enroll keys into any LUKS-encrypted partitions, and offer online in-place encryption for other unencrypted partitions.
*   *Note on Offline Root Encryption:* Since an active root partition cannot be encrypted online, if the root partition is unencrypted, the tool will offer to generate a custom, automated offline root encryption script (`~/encrypt-root-offline.sh`). You can run this script after booting from a Live USB to securely perform in-place encryption on your root partition.

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
