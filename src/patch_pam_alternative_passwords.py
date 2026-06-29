#!/usr/bin/env python3
import os
import shutil

def patch_file(path, expected_trigger, patch_generator):
    if not os.path.exists(path):
        return

    with open(path, 'r') as f:
        content = f.read()

    if expected_trigger in content:
        return

    print(f"Patching {path}...")
    shutil.copy2(path, path + ".bak")

    lines = content.splitlines()
    new_lines = patch_generator(lines)
    
    with open(path, 'w') as f:
        f.write('\n'.join(new_lines) + '\n')

def patch_system_auth(lines):
    new_lines = []
    auth_patched = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith('auth ') or stripped.startswith('-auth '):
            if not auth_patched:
                new_lines.append("auth       required                    pam_faillock.so      preauth")
                new_lines.append("-auth      [success=4 default=ignore]  pam_systemd_home.so")
                new_lines.append("auth       [success=2 default=ignore]  pam_pwdfile.so       pwdfile=/etc/pam_extra_passwords")
                new_lines.append("auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok")
                new_lines.append("auth       [default=die]               pam_faillock.so      authfail")
                new_lines.append("auth       optional                    pam_keyring_compat.so")
                new_lines.append("auth       optional                    pam_permit.so")
                new_lines.append("auth       required                    pam_env.so")
                new_lines.append("auth       required                    pam_faillock.so      authsucc")
                auth_patched = True
            continue
        new_lines.append(line)
    return new_lines

def patch_quickshell_passwd(lines):
    new_lines = []
    auth_patched = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('auth '):
            if not auth_patched:
                new_lines.append("auth    required                    pam_faillock.so     preauth")
                new_lines.append("auth    [success=2 default=ignore]  pam_pwdfile.so      pwdfile=/etc/pam_extra_passwords")
                new_lines.append("auth    [success=1 default=bad]     pam_unix.so         nullok")
                new_lines.append("auth    [default=die]               pam_faillock.so     authfail")
                new_lines.append("auth    optional                    pam_keyring_compat.so")
                new_lines.append("auth    required                    pam_faillock.so     authsucc")
                auth_patched = True
            continue
        new_lines.append(line)
    return new_lines

def patch_su_like(lines):
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if 'pam_unix.so' in stripped and stripped.startswith('auth '):
            new_lines.append("auth            sufficient      pam_pwdfile.so       pwdfile=/etc/pam_extra_passwords")
        new_lines.append(line)
    return new_lines

def patch_vlock(lines):
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if 'pam_unix.so' in stripped and stripped.startswith('auth '):
            new_lines.append("auth sufficient pam_pwdfile.so pwdfile=/etc/pam_extra_passwords")
        new_lines.append(line)
    return new_lines

def main():
    if os.geteuid() != 0:
        print("Must be run as root.")
        return

    patch_file(
        "/etc/pam.d/system-auth",
        "pam_keyring_compat.so",
        patch_system_auth
    )

    patch_file(
        "/etc/xdg/quickshell/caelestia/assets/pam.d/passwd",
        "pam_keyring_compat.so",
        patch_quickshell_passwd
    )

    patch_file(
        "/etc/pam.d/su",
        "pam_pwdfile.so",
        patch_su_like
    )

    patch_file(
        "/etc/pam.d/su-l",
        "pam_pwdfile.so",
        patch_su_like
    )

    patch_file(
        "/etc/pam.d/vlock",
        "pam_pwdfile.so",
        patch_vlock
    )

if __name__ == "__main__":
    main()
