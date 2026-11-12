# PAM Alternative Password & LUKS Compatibility Toolset

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This project provides a robust, permanent solution for integrating alternative password authentication on Arch Linux, ensuring complete compatibility with `su`/`sudo`, screen locking, and automated GNOME Keyring decryption. Additionally, it automates progress monitoring and verification for root partition LUKS encryption.

---

## 📋 Requirements & Dependencies

- **Operating System:** Arch Linux or Arch-based distributions
- **Build Tools & Libraries:**
  - `gcc` / `clang` (C compiler)
  - `make`
  - `pam` (Linux-PAM development headers)
  - `openssl` (libcrypto)
  - `python3`
- **System Utilities:**
  - `systemd`
  - `cryptsetup`
  - `pacman`

Install build dependencies on Arch Linux:
```bash
sudo pacman -S base-devel pam openssl python cryptsetup
```

---

## 🌟 Key Features

1. **PAM Alternative Password Integration (`pam_keyring_compat`):**
   - Seamlessly unlocks GNOME Keyring and handles alternative authentication hashes across `system-auth`, `su`, `su-l`, and `vlock`.
   - Protects against pam stack breakage across system updates.

2. **Automated Pacman & Systemd Watcher:**
   - Systemd path watcher (`patch-pam-alternative-passwords.path`) monitors `/etc/pam.d/` changes.
   - Pacman post-transaction hook automatically reapplies compatibility patches after PAM package upgrades.

3. **LUKS Encryption Verification & Progress:**
   - Background encryption health checker (`check-root-encryption.service`).
   - Terminal encryption progress visualization utility (`crypt-progress`).

---

## 🚀 Installation & Setup

### Automated Installation
```bash
git clone https://github.com/Vikyek/pam-alt-luks-compat.git
cd pam-alt-luks-compat
chmod +x install.sh
./install.sh
```

### Manual Installation (Makefile)
```bash
cd pam-alt-luks-compat
make
sudo make install
```

---

## 💻 Usage & Verification

### Verify PAM Configuration
Check that alternative password patches and keyring compat modules are active:
```bash
sudo /usr/local/bin/patch-pam-alternative-passwords.py
```

### Check LUKS Encryption Progress
Run the progress monitor to observe active disk encryption re-encryption sessions:
```bash
crypt-progress
```

### Check Systemd Watcher Status
```bash
systemctl status patch-pam-alternative-passwords.path
```

---

## 🗑️ Uninstallation
To completely remove the modules and restore original PAM configurations:
```bash
sudo make uninstall
```


---

## Support & Sponsorship

`pam-alt-luks-compat` is authored and maintained by **[Vikyek](https://github.com/Vikyek)** as an independent open-source project. Everything is 100% open-source, telemetry-free, and public.

<div align="center">


[![Sponsor Vikyek](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github&style=for-the-badge)](https://github.com/sponsors/Vikyek)
[![Donate on Liberapay](https://img.shields.io/badge/Donate-Liberapay-f6c915?style=for-the-badge&logo=liberapay&logoColor=black)](https://liberapay.com/Vikyek)
[![Donate with Stripe](https://img.shields.io/badge/Donate-Stripe-635BFF?style=for-the-badge&logo=stripe&logoColor=white)](https://profile.stripe.com/@vikyek)

</div>

> ### 🎯 Active Sponsorship Goal: Monthly Living Essentials
> **Target:** **2,710 PLN / ~$680 USD per month** (`630 PLN / week`) — Rent & Essential Utilities  
> Covering basic living essentials directly unlocks dedicated, sustainable full-time independent open-source engineering across Arch Linux utilities, developer tools, and AI middleware free from corporate telemetry, ads, or paywalls.

If this project saves you time, optimizes your setup, or accelerates your workflow, consider supporting ongoing work:

- **GitHub Sponsors**: [github.com/sponsors/Vikyek](https://github.com/sponsors/Vikyek) *(Monthly tiers and one-time tips)*
- **Liberapay**: [liberapay.com/Vikyek](https://liberapay.com/Vikyek) *(0% platform fee recurrent patronage in EUR/USD/PLN)*
- **Direct Stripe Profile**: [profile.stripe.com/@vikyek](https://profile.stripe.com/@vikyek) *(Direct one-time tips & sponsorship)*

Every contribution—monthly or one-time—directly supports active maintenance, hardware testbeds, and new feature development!

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
