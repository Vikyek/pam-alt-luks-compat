#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <termios.h>

#define VAULT_PATH "/etc/pam_keyring_compat.vault"
#define TEMP_KEYS_PATH "/run/luks_keys_to_add.tmp"
#define LUKS_DEV "/dev/sdc1"
#define KEY_FILE "/etc/cryptsetup-keys.d/data.key"
#define BACKUP_KEY_FILE "/etc/cryptsetup-keys.d/data.key.backup"

struct vault_record {
    char username[32];
    unsigned char salt[16];
    unsigned char iv[12];
    unsigned char tag[16];
    int ciphertext_len;
    unsigned char ciphertext[128];
};

int derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 16, 10000, EVP_sha256(), 32, key);
}

int encrypt_gcm(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_gcm(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                const unsigned char *tag, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        plaintext[plaintext_len] = '\0';
        return plaintext_len;
    } else {
        return -1;
    }
}

int enroll_luks_key_with_keyfile(const char *dev, const char *key_file, const char *new_pass) {
    char new_temp[] = "/tmp/luks_new_XXXXXX";
    int new_fd = mkstemp(new_temp);
    if (new_fd < 0) return -1;
    
    if (write(new_fd, new_pass, strlen(new_pass)) < 0 || write(new_fd, "\n", 1) < 0) {
        close(new_fd);
        unlink(new_temp);
        return -1;
    }
    close(new_fd);
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cryptsetup luksAddKey --batch-mode --key-file %s %s %s 2>/dev/null", key_file, dev, new_temp);
    int res = system(cmd);
    
    unlink(new_temp);
    return res;
}

int enroll_luks_key_with_passphrase(const char *dev, const char *existing_pass, const char *new_pass) {
    char old_temp[] = "/tmp/luks_old_XXXXXX";
    char new_temp[] = "/tmp/luks_new_XXXXXX";
    
    int old_fd = mkstemp(old_temp);
    int new_fd = mkstemp(new_temp);
    
    if (old_fd < 0 || new_fd < 0) {
        if (old_fd >= 0) { close(old_fd); unlink(old_temp); }
        if (new_fd >= 0) { close(new_fd); unlink(new_temp); }
        return -1;
    }
    
    if (write(old_fd, existing_pass, strlen(existing_pass)) < 0 || write(old_fd, "\n", 1) < 0 ||
        write(new_fd, new_pass, strlen(new_pass)) < 0 || write(new_fd, "\n", 1) < 0) {
        close(old_fd); close(new_fd);
        unlink(old_temp); unlink(new_temp);
        return -1;
    }
    close(old_fd);
    close(new_fd);
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cryptsetup luksAddKey --batch-mode --key-file %s %s %s 2>/dev/null", old_temp, dev, new_temp);
    int res = system(cmd);
    
    unlink(old_temp);
    unlink(new_temp);
    return res;
}

int enroll_luks_keyfile_with_passphrase(const char *dev, const char *existing_pass, const char *keyfile_path) {
    char old_temp[] = "/tmp/luks_old_XXXXXX";
    int old_fd = mkstemp(old_temp);
    if (old_fd < 0) return -1;
    
    if (write(old_fd, existing_pass, strlen(existing_pass)) < 0 || write(old_fd, "\n", 1) < 0) {
        close(old_fd);
        unlink(old_temp);
        return -1;
    }
    close(old_fd);
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cryptsetup luksAddKey --batch-mode --key-file %s %s %s 2>/dev/null", old_temp, dev, keyfile_path);
    int res = system(cmd);
    
    unlink(old_temp);
    return res;
}

#ifdef PAM_MODULE
#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;
    const char *authtok = NULL;
    int r;

    r = pam_get_user(pamh, &username, NULL);
    if (r != PAM_SUCCESS || !username) {
        return PAM_IGNORE;
    }

    r = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
    if (r != PAM_SUCCESS || !authtok) {
        return PAM_IGNORE;
    }

    FILE *f = fopen(VAULT_PATH, "rb");
    if (!f) {
        return PAM_IGNORE;
    }

    struct vault_record rec;
    int found = 0;
    while (fread(&rec, sizeof(rec), 1, f) == 1) {
        if (strcmp(rec.username, username) == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);

    if (!found) {
        return PAM_IGNORE;
    }

    unsigned char key[32];
    if (derive_key(authtok, rec.salt, key) != 1) {
        return PAM_IGNORE;
    }

    unsigned char decrypted[128];
    int dec_len = decrypt_gcm(rec.ciphertext, rec.ciphertext_len, key, rec.iv, rec.tag, decrypted);
    if (dec_len > 0) {
        pam_set_item(pamh, PAM_AUTHTOK, decrypted);
        memset(decrypted, 0, sizeof(decrypted));
    }

    memset(key, 0, sizeof(key));
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

#else

// CLI Tool implementation
int is_luks_device(const char *dev) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cryptsetup isLuks %s 2>/dev/null", dev);
    return system(cmd) == 0;
}

int is_luks_reencrypting(const char *dev) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cryptsetup luksDump %s 2>/dev/null", dev);
    FILE *dp = popen(cmd, "r");
    if (!dp) return 0;
    char line[256];
    int reencrypting = 0;
    while (fgets(line, sizeof(line), dp)) {
        if (strstr(line, "reencrypt")) {
            reencrypting = 1;
            break;
        }
    }
    pclose(dp);
    return reencrypting;
}

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --set <username>\n", prog);
    fprintf(stderr, "       %s --delete <username>\n", prog);
    fprintf(stderr, "       %s --status\n", prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];

    if (strcmp(action, "--status") == 0 || strcmp(action, "-s") == 0) {
        printf("\n\033[1mPAM & LUKS Alternative Passwords Status\033[0m\n");
        printf("----------------------------------------\n");
        
        // 1. Vault status
        FILE *f = fopen(VAULT_PATH, "rb");
        if (f) {
            printf("\033[92m✔\033[0m Keyring Compatibility Vault: PRESENT\n");
            struct vault_record rec;
            printf("  Configured users:\n");
            while (fread(&rec, sizeof(rec), 1, f) == 1) {
                printf("    - %s\n", rec.username);
            }
            fclose(f);
        } else {
            printf("\033[93m⚠\033[0m Keyring Compatibility Vault: NOT PRESENT / EMPTY\n");
        }
        
        // 2. Queue status
        if (access(TEMP_KEYS_PATH, F_OK) == 0) {
            printf("\033[93m⚠\033[0m LUKS Password Queue: PENDING (credentials cached in memory, waiting for encryption)\n");
        } else {
            printf("\033[92m✔\033[0m LUKS Password Queue: COMPLETED (no cached credentials in memory)\n");
        }
        
        // 3. LUKS device status
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "cryptsetup isLuks %s 2>/dev/null", LUKS_DEV);
        int is_luks = system(cmd);
        if (is_luks == 0) {
            printf("\033[92m✔\033[0m LUKS Partition: PRESENT (%s)\n", LUKS_DEV);
            
            // Count active keyslots
            snprintf(cmd, sizeof(cmd), "cryptsetup luksDump %s 2>/dev/null", LUKS_DEV);
            FILE *dp = popen(cmd, "r");
            if (dp) {
                char line[256];
                int slots = 0;
                while (fgets(line, sizeof(line), dp)) {
                    if (strstr(line, "luks2") && strstr(line, ":")) {
                        if (!strstr(line, "reencrypt")) {
                            slots++;
                        }
                    }
                }
                pclose(dp);
                printf("  Active password/key slots: %d\n", slots);
            }
        } else {
            printf("\033[91m✘\033[0m LUKS Partition: NOT FOUND or NOT LUKS format (%s)\n", LUKS_DEV);
        }
        printf("\n");
        return 0;
    }

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *username = argv[2];

    if (strcmp(action, "--set") != 0 && strcmp(action, "--delete") != 0) {
        usage(argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: This tool must be run as root (sudo).\n");
        return 1;
    }

    if (strcmp(action, "--delete") == 0) {
        FILE *f = fopen(VAULT_PATH, "rb");
        if (!f) {
            printf("No vault file found at %s.\n", VAULT_PATH);
            return 0;
        }

        struct vault_record records[100];
        int count = 0;
        struct vault_record rec;
        while (fread(&rec, sizeof(rec), 1, f) == 1 && count < 100) {
            if (strcmp(rec.username, username) != 0) {
                records[count++] = rec;
            }
        }
        fclose(f);

        f = fopen(VAULT_PATH, "wb");
        if (!f) {
            perror("Failed to open vault for writing");
            return 1;
        }
        chmod(VAULT_PATH, 0600);
        for (int i = 0; i < count; i++) {
            fwrite(&records[i], sizeof(struct vault_record), 1, f);
        }
        fclose(f);
        printf("Successfully deleted vault entry for user '%s'.\n", username);
        return 0;
    }

    char alt_pass[128] = {0};
    char main_pass[128] = {0};

    printf("Enter alternative password for '%s': ", username);
    fflush(stdout);
    if (!fgets(alt_pass, sizeof(alt_pass), stdin)) return 1;
    alt_pass[strcspn(alt_pass, "\n")] = '\0';

    printf("Enter main (keyring/unix) password for '%s': ", username);
    fflush(stdout);
    struct stat st;
    int is_tty = isatty(STDIN_FILENO);
    #include <termios.h>
    struct termios oldt, newt;
    if (is_tty) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    if (!fgets(main_pass, sizeof(main_pass), stdin)) return 1;
    if (is_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        printf("\n");
    }
    main_pass[strcspn(main_pass, "\n")] = '\0';

    struct vault_record new_rec;
    memset(&new_rec, 0, sizeof(new_rec));
    strncpy(new_rec.username, username, sizeof(new_rec.username) - 1);

    if (RAND_bytes(new_rec.salt, sizeof(new_rec.salt)) != 1 ||
        RAND_bytes(new_rec.iv, sizeof(new_rec.iv)) != 1) {
        fprintf(stderr, "Failed to generate random salt/IV\n");
        return 1;
    }

    unsigned char key[32];
    if (derive_key(alt_pass, new_rec.salt, key) != 1) {
        fprintf(stderr, "Key derivation failed\n");
        return 1;
    }

    new_rec.ciphertext_len = encrypt_gcm((unsigned char *)main_pass, strlen(main_pass),
                                         key, new_rec.iv, new_rec.ciphertext, new_rec.tag);
    if (new_rec.ciphertext_len <= 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    memset(key, 0, sizeof(key));

    FILE *f = fopen(VAULT_PATH, "rb");
    struct vault_record records[100];
    int count = 0;
    int replaced = 0;
    if (f) {
        struct vault_record rec;
        while (fread(&rec, sizeof(rec), 1, f) == 1 && count < 100) {
            if (strcmp(rec.username, username) == 0) {
                records[count++] = new_rec;
                replaced = 1;
            } else {
                records[count++] = rec;
            }
        }
        fclose(f);
    }

    if (!replaced && count < 100) {
        records[count++] = new_rec;
    }

    f = fopen(VAULT_PATH, "wb");
    if (!f) {
        perror("Failed to open vault for writing");
        return 1;
    }
    chmod(VAULT_PATH, 0600);
    for (int i = 0; i < count; i++) {
        fwrite(&records[i], sizeof(struct vault_record), 1, f);
    }
    fclose(f);

    printf("Successfully updated keyring compatibility vault entry for user '%s'.\n", username);

    if (!is_luks_device(LUKS_DEV)) {
        printf("Note: Device '%s' is not a LUKS partition.\n", LUKS_DEV);
        printf("Would you like to initialize and start in-place LUKS encryption? (y/N): ");
        fflush(stdout);
        char ans[10] = {0};
        if (fgets(ans, sizeof(ans), stdin) && (ans[0] == 'y' || ans[0] == 'Y')) {
            printf("Starting in-place LUKS encryption initialization...\n");
            
            char cmd[1024];
            system("mkdir -p /etc/cryptsetup-keys.d");
            if (access(BACKUP_KEY_FILE, F_OK) != 0) {
                printf("Generating a new random backup keyfile at '%s'...\n", BACKUP_KEY_FILE);
                snprintf(cmd, sizeof(cmd), "dd if=/dev/urandom of=%s bs=512 count=1 status=none && chmod 400 %s", BACKUP_KEY_FILE, BACKUP_KEY_FILE);
                if (system(cmd) != 0) {
                    fprintf(stderr, "Failed to generate backup key file.\n");
                    memset(alt_pass, 0, sizeof(alt_pass));
                    memset(main_pass, 0, sizeof(main_pass));
                    return 1;
                }
            }
            snprintf(cmd, sizeof(cmd), "cp %s %s && chmod 400 %s", BACKUP_KEY_FILE, KEY_FILE, KEY_FILE);
            system(cmd);

            FILE *fp = popen("blkid -o value -s TYPE " LUKS_DEV " 2>/dev/null", "r");
            char fstype[64] = {0};
            if (fp) {
                if (fgets(fstype, sizeof(fstype), fp)) {
                    fstype[strcspn(fstype, "\n")] = '\0';
                }
                pclose(fp);
            }

            char mountpoint[512] = {0};
            fp = popen("findmnt -n -o TARGET " LUKS_DEV " 2>/dev/null", "r");
            if (fp) {
                if (fgets(mountpoint, sizeof(mountpoint), fp)) {
                    mountpoint[strcspn(mountpoint, "\n")] = '\0';
                }
                pclose(fp);
            }

            if (strlen(fstype) > 0) {
                printf("Detected filesystem: %s on '%s'\n", fstype, LUKS_DEV);
                if (strcmp(fstype, "btrfs") == 0) {
                    if (strlen(mountpoint) > 0) {
                        printf("Shrinking Btrfs filesystem online at '%s'...\n", mountpoint);
                        snprintf(cmd, sizeof(cmd), "btrfs filesystem resize -32M %s", mountpoint);
                        system(cmd);
                    } else {
                        printf("Btrfs filesystem is not mounted. Mounting temporarily to shrink...\n");
                        system("mkdir -p /tmp/mnt_shrink");
                        snprintf(cmd, sizeof(cmd), "mount " LUKS_DEV " /tmp/mnt_shrink && btrfs filesystem resize -32M /tmp/mnt_shrink && umount /tmp/mnt_shrink");
                        system(cmd);
                    }
                } else if (strcmp(fstype, "ext4") == 0 || strcmp(fstype, "ext3") == 0 || strcmp(fstype, "ext2") == 0) {
                    if (strlen(mountpoint) > 0) {
                        printf("Unmounting '%s' to shrink ext4 filesystem...\n", mountpoint);
                        snprintf(cmd, sizeof(cmd), "umount %s", mountpoint);
                        system(cmd);
                    }
                    printf("Running filesystem check on '%s'...\n", LUKS_DEV);
                    snprintf(cmd, sizeof(cmd), "e2fsck -f -y %s", LUKS_DEV);
                    system(cmd);

                    fp = popen("blockdev --getsize64 " LUKS_DEV " 2>/dev/null", "r");
                    long long bytes = 0;
                    if (fp) {
                        if (fscanf(fp, "%lld", &bytes) != 1) bytes = 0;
                        pclose(fp);
                    }
                    if (bytes > 0) {
                        long long new_kb = (bytes / 1024) - 32768;
                        printf("Shrinking ext4 filesystem to %lld KB...\n", new_kb);
                        snprintf(cmd, sizeof(cmd), "resize2fs %s %lldK", LUKS_DEV, new_kb);
                        system(cmd);
                    } else {
                        fprintf(stderr, "Failed to determine device size for shrinking.\n");
                        memset(alt_pass, 0, sizeof(alt_pass));
                        memset(main_pass, 0, sizeof(main_pass));
                        return 1;
                    }
                } else {
                    printf("Unsupported filesystem type '%s' for automatic shrinking. You must shrink it manually.\n", fstype);
                }
            }

            snprintf(cmd, sizeof(cmd), "umount %s 2>/dev/null || true", LUKS_DEV);
            system(cmd);

            printf("Initializing in-place LUKS encryption on '%s'...\n", LUKS_DEV);
            snprintf(cmd, sizeof(cmd), "cryptsetup reencrypt --new --encrypt --type luks2 --reduce-device-size 32m --init-only --key-file %s %s", KEY_FILE, LUKS_DEV);
            if (system(cmd) != 0) {
                fprintf(stderr, "Failed to initialize LUKS encryption on '%s'.\n", LUKS_DEV);
                memset(alt_pass, 0, sizeof(alt_pass));
                memset(main_pass, 0, sizeof(main_pass));
                return 1;
            }

            printf("Saving passwords to secure in-memory cache at '%s'...\n", TEMP_KEYS_PATH);
            FILE *tf = fopen(TEMP_KEYS_PATH, "w");
            if (tf) {
                chmod(TEMP_KEYS_PATH, 0600);
                fprintf(tf, "%s\n%s\n", alt_pass, main_pass);
                fclose(tf);
            }

            printf("Starting background encryption process...\n");
            snprintf(cmd, sizeof(cmd), "nohup cryptsetup reencrypt %s >/dev/null 2>&1 &", LUKS_DEV);
            system(cmd);

            printf("\n🎉 Encryption successfully initialized and started in the background!\n");
            printf("You can monitor the progress by running: sudo crypt-progress\n");
            
            memset(alt_pass, 0, sizeof(alt_pass));
            memset(main_pass, 0, sizeof(main_pass));
            return 0;
        } else {
            printf("Skipping LUKS encryption initialization. Keyring Compatibility Vault updated.\n");
            memset(alt_pass, 0, sizeof(alt_pass));
            memset(main_pass, 0, sizeof(main_pass));
            return 0;
        }
    }

    int keyfiles_exist = (access(BACKUP_KEY_FILE, F_OK) == 0 || access(KEY_FILE, F_OK) == 0);
    if (!keyfiles_exist) {
        printf("\033[93m⚠\033[0m Key files for auto-unlock do not exist.\n");
        printf("Generating new random keyfile at '%s'...\n", BACKUP_KEY_FILE);
        
        system("mkdir -p /etc/cryptsetup-keys.d");
        
        char key_gen_cmd[1024];
        snprintf(key_gen_cmd, sizeof(key_gen_cmd), "dd if=/dev/urandom of=%s bs=512 count=1 status=none && chmod 400 %s", BACKUP_KEY_FILE, BACKUP_KEY_FILE);
        if (system(key_gen_cmd) != 0) {
            fprintf(stderr, "Error: Failed to generate backup key file.\n");
            memset(alt_pass, 0, sizeof(alt_pass));
            memset(main_pass, 0, sizeof(main_pass));
            return 1;
        }
        
        char existing_pass[128] = {0};
        printf("Enter existing LUKS passphrase for '%s' to authorize the keyfile: ", LUKS_DEV);
        fflush(stdout);
        
        struct termios oldt, newt;
        int is_tty = isatty(STDIN_FILENO);
        if (is_tty) {
            tcgetattr(STDIN_FILENO, &oldt);
            newt = oldt;
            newt.c_lflag &= ~(ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        }
        if (fgets(existing_pass, sizeof(existing_pass), stdin)) {
            existing_pass[strcspn(existing_pass, "\n")] = '\0';
        }
        if (is_tty) {
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            printf("\n");
        }
        
        int res = enroll_luks_keyfile_with_passphrase(LUKS_DEV, existing_pass, BACKUP_KEY_FILE);
        if (res == 0) {
            printf("Successfully enrolled auto-unlock keyfile into LUKS.\n");
            snprintf(key_gen_cmd, sizeof(key_gen_cmd), "cp %s %s && chmod 400 %s", BACKUP_KEY_FILE, KEY_FILE, KEY_FILE);
            system(key_gen_cmd);
        } else {
            fprintf(stderr, "\033[91mError: Failed to authorize keyfile (incorrect passphrase).\033[0m\n");
            unlink(BACKUP_KEY_FILE);
            memset(existing_pass, 0, sizeof(existing_pass));
            memset(alt_pass, 0, sizeof(alt_pass));
            memset(main_pass, 0, sizeof(main_pass));
            return 1;
        }
        memset(existing_pass, 0, sizeof(existing_pass));
    }

    printf("Enrolling alternative and main passwords to LUKS partition '%s'...\n", LUKS_DEV);
    const char *auth_key = BACKUP_KEY_FILE;
    if (access(BACKUP_KEY_FILE, F_OK) != 0) {
        auth_key = KEY_FILE;
    }

    int alt_res = -1;
    int main_res = -1;
    if (auth_key && access(auth_key, F_OK) == 0) {
        alt_res = enroll_luks_key_with_keyfile(LUKS_DEV, auth_key, alt_pass);
        main_res = enroll_luks_key_with_keyfile(LUKS_DEV, auth_key, main_pass);
    }

    if (alt_res != 0 || main_res != 0) {
        if (is_luks_reencrypting(LUKS_DEV)) {
            printf("LUKS device is currently busy/locked (encryption in progress).\n");
            printf("Saving passwords to secure in-memory cache at '%s'...\n", TEMP_KEYS_PATH);
            FILE *tf = fopen(TEMP_KEYS_PATH, "w");
            if (tf) {
                chmod(TEMP_KEYS_PATH, 0600);
                fprintf(tf, "%s\n%s\n", alt_pass, main_pass);
                fclose(tf);
                printf("Passwords successfully queued. They will be automatically enrolled once background encryption finishes.\n");
            } else {
                perror("Failed to save passwords to temporary cache");
            }
        } else {
            printf("\033[93m⚠\033[0m Keyfile authorization failed. Fallback to manual LUKS passphrase.\n");
            char existing_pass[128] = {0};
            printf("Enter existing LUKS passphrase for '%s': ", LUKS_DEV);
            fflush(stdout);
            
            struct termios oldt, newt;
            int is_tty = isatty(STDIN_FILENO);
            if (is_tty) {
                tcgetattr(STDIN_FILENO, &oldt);
                newt = oldt;
                newt.c_lflag &= ~(ECHO);
                tcsetattr(STDIN_FILENO, TCSANOW, &newt);
            }
            if (fgets(existing_pass, sizeof(existing_pass), stdin)) {
                existing_pass[strcspn(existing_pass, "\n")] = '\0';
            }
            if (is_tty) {
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
                printf("\n");
            }
            
            alt_res = enroll_luks_key_with_passphrase(LUKS_DEV, existing_pass, alt_pass);
            main_res = enroll_luks_key_with_passphrase(LUKS_DEV, existing_pass, main_pass);
            
            if (alt_res == 0 && main_res == 0) {
                printf("Successfully enrolled alternative and main passwords using passphrase.\n");
                
                printf("Re-creating auto-unlock keyfiles...\n");
                system("mkdir -p /etc/cryptsetup-keys.d");
                char gen_cmd[1024];
                snprintf(gen_cmd, sizeof(gen_cmd), "dd if=/dev/urandom of=%s bs=512 count=1 status=none && chmod 400 %s", BACKUP_KEY_FILE, BACKUP_KEY_FILE);
                if (system(gen_cmd) == 0) {
                    int enroll_kf_res = enroll_luks_keyfile_with_passphrase(LUKS_DEV, existing_pass, BACKUP_KEY_FILE);
                    if (enroll_kf_res == 0) {
                        snprintf(gen_cmd, sizeof(gen_cmd), "cp %s %s && chmod 400 %s", BACKUP_KEY_FILE, KEY_FILE, KEY_FILE);
                        system(gen_cmd);
                        printf("Successfully re-created and enrolled auto-unlock keyfile.\n");
                    } else {
                        fprintf(stderr, "Warning: Failed to enroll the newly generated keyfile into LUKS.\n");
                        unlink(BACKUP_KEY_FILE);
                    }
                }
            } else {
                fprintf(stderr, "\033[91mError: Failed to enroll passwords (incorrect passphrase or system error).\033[0m\n");
            }
            memset(existing_pass, 0, sizeof(existing_pass));
        }
    } else {
        printf("Successfully enrolled alternative and main passwords into LUKS slots.\n");
    }

    memset(alt_pass, 0, sizeof(alt_pass));
    memset(main_pass, 0, sizeof(main_pass));

    return 0;
}
#endif
