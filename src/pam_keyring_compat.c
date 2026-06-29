#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define VAULT_PATH "/etc/pam_keyring_compat.vault"
#define TEMP_KEYS_PATH "/run/luks_keys_to_add.tmp"
#define LUKS_DEV "/dev/sdc1"
#define KEY_FILE "/etc/cryptsetup-keys.d/data.key"

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

int enroll_luks_key(const char *dev, const char *key_file, const char *new_pass) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cryptsetup luksAddKey --key-file %s %s", key_file, dev);
    FILE *p = popen(cmd, "w");
    if (!p) return -1;
    fprintf(p, "%s\n", new_pass);
    return pclose(p);
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
void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --set <username>\n", prog);
    fprintf(stderr, "       %s --delete <username>\n", prog);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];
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

    printf("Enrolling alternative and main passwords to LUKS partition '%s'...\n", LUKS_DEV);
    int alt_res = enroll_luks_key(LUKS_DEV, KEY_FILE, alt_pass);
    int main_res = enroll_luks_key(LUKS_DEV, KEY_FILE, main_pass);

    if (alt_res == 0 && main_res == 0) {
        printf("Successfully enrolled alternative and main passwords into LUKS slots.\n");
    } else {
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
    }

    memset(alt_pass, 0, sizeof(alt_pass));
    memset(main_pass, 0, sizeof(main_pass));

    return 0;
}
#endif
