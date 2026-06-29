CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lcrypto
PAM_LDFLAGS = -lpam -lcrypto

all: pam_keyring_compat.so pam_keyring_compat_tool

pam_keyring_compat.so: src/pam_keyring_compat.c
	$(CC) $(CFLAGS) -fPIC -shared -DPAM_MODULE -o $@ $< $(PAM_LDFLAGS)

pam_keyring_compat_tool: src/pam_keyring_compat.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f pam_keyring_compat.so pam_keyring_compat_tool

install: all
	install -Dm755 pam_keyring_compat_tool /usr/local/bin/pam_keyring_compat_tool
	install -Dm755 src/patch_pam_alternative_passwords.py /usr/local/bin/patch-pam-alternative-passwords.py
	install -Dm755 src/crypt_progress.py /usr/local/bin/crypt-progress
	
	# Install shared library cleanly by unlinking first (prevents segmentation fault)
	rm -f /usr/lib/security/pam_keyring_compat.so
	install -Dm644 pam_keyring_compat.so /usr/lib/security/pam_keyring_compat.so
	
	# Install systemd configs
	install -Dm644 systemd/patch-pam-alternative-passwords.path /etc/systemd/system/patch-pam-alternative-passwords.path
	install -Dm644 systemd/patch-pam-alternative-passwords.service /etc/systemd/system/patch-pam-alternative-passwords.service
	
	# Install pacman hook
	install -Dm644 hooks/patch-pam-alternative-passwords.hook /etc/pacman.d/hooks/patch-pam-alternative-passwords.hook
	
	# Reload and activate systemd watcher
	systemctl daemon-reload
	systemctl enable --now patch-pam-alternative-passwords.path
	
	# Run initial patch
	/usr/local/bin/patch-pam-alternative-passwords.py

uninstall:
	systemctl disable --now patch-pam-alternative-passwords.path || true
	rm -f /etc/systemd/system/patch-pam-alternative-passwords.path
	rm -f /etc/systemd/system/patch-pam-alternative-passwords.service
	systemctl daemon-reload
	
	rm -f /etc/pacman.d/hooks/patch-pam-alternative-passwords.hook
	rm -f /usr/lib/security/pam_keyring_compat.so
	rm -f /usr/local/bin/pam_keyring_compat_tool
	rm -f /usr/local/bin/patch-pam-alternative-passwords.py
	rm -f /usr/local/bin/crypt-progress
	
	# Revert PAM backups if they exist
	[ -f /etc/pam.d/system-auth.bak ] && mv /etc/pam.d/system-auth.bak /etc/pam.d/system-auth || true
	[ -f /etc/pam.d/su.bak ] && mv /etc/pam.d/su.bak /etc/pam.d/su || true
	[ -f /etc/pam.d/su-l.bak ] && mv /etc/pam.d/su-l.bak /etc/pam.d/su-l || true
	[ -f /etc/pam.d/vlock.bak ] && mv /etc/pam.d/vlock.bak /etc/pam.d/vlock || true
	[ -f /etc/xdg/quickshell/caelestia/assets/pam.d/passwd.bak ] && mv /etc/xdg/quickshell/caelestia/assets/pam.d/passwd.bak /etc/xdg/quickshell/caelestia/assets/pam.d/passwd || true
