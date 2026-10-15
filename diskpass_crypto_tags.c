static const char *map_encode(const char *part_name, const char *value) {
    const map_entry_t *tbl = NULL; int n = 0;
    if (strcmp(part_name, "type") == 0) { tbl = TYPE_MAP; n = TYPE_MAP_N; }
    else if (strcmp(part_name, "size") == 0) { tbl = SIZE_MAP; n = SIZE_MAP_N; }
    else if (strcmp(part_name, "cipher") == 0) { tbl = CIPHER_MAP; n = CIPHER_MAP_N; }
    if (!tbl) return value;
    for (int i = 0; i < n; i++)
        if (strcmp(tbl[i].name, value) == 0) return tbl[i].code;
    return value;
}

static const char *map_decode(const char *part_name, const char *code) {
    const map_entry_t *tbl = NULL; int n = 0;
    if (strcmp(part_name, "type") == 0) { tbl = TYPE_MAP; n = TYPE_MAP_N; }
    else if (strcmp(part_name, "size") == 0) { tbl = SIZE_MAP; n = SIZE_MAP_N; }
    else if (strcmp(part_name, "cipher") == 0) { tbl = CIPHER_MAP; n = CIPHER_MAP_N; }
    if (!tbl) return code;
    for (int i = 0; i < n; i++)
        if (strcmp(tbl[i].code, code) == 0) return tbl[i].name;
    return code;
}

static gboolean map_has_name(const map_entry_t *tbl, int n, const char *value) {
    if (!tbl || !value) return FALSE;
    for (int i = 0; i < n; i++)
        if (strcmp(tbl[i].name, value) == 0) return TRUE;
    return FALSE;
}

static gboolean map_has_code(const map_entry_t *tbl, int n, const char *value) {
    if (!tbl || !value) return FALSE;
    for (int i = 0; i < n; i++)
        if (strcmp(tbl[i].code, value) == 0) return TRUE;
    return FALSE;
}

static gboolean valid_ascii_tag_char(unsigned char c) {
    return c < 0x80 && g_ascii_isalnum((gchar)c);
}

static gboolean valid_alphabet_string(const char *s, size_t expected_len) {
    if (!s || strlen(s) != expected_len) return FALSE;
    for (size_t i = 0; i < expected_len; i++)
        if (!strchr(ALPHABET, s[i])) return FALSE;
    return TRUE;
}

static char *generate_salt(int length) {
    char *buf = malloc(length + 1);
    if (!buf) return NULL;
    for (int i = 0; i < length; i++)
        buf[i] = ALPHABET[randombytes_uniform(ALPHABET_LEN)];
    buf[length] = '\0';
    return buf;
}

static char calculate_block_salt(const uint8_t *noise_key, size_t key_len,
    const uint8_t *salt, size_t salt_len,
    int part_index, const char *val_str)
{
    if (!noise_key || !salt || !val_str || salt_len > 32 || key_len > 32)
        return ALPHABET[0];
    size_t vlen = strlen(val_str);
    if (vlen > 64) return ALPHABET[0];
    uint8_t msg[32 + 1 + 64];
    size_t msg_len = salt_len + 1 + vlen;
    memcpy(msg, salt, salt_len);
    msg[salt_len] = (uint8_t)part_index;
    memcpy(msg + salt_len + 1, val_str, vlen);
    uint8_t hash[8] = {0};
    if (crypto_generichash(hash, sizeof(hash), msg, msg_len, noise_key, key_len) != 0) {
        sodium_memzero(msg, sizeof(msg));
        sodium_memzero(hash, sizeof(hash));
        return ALPHABET[0];
    }
    sodium_memzero(msg, sizeof(msg));
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) val = (val << 8) | hash[i];
    sodium_memzero(hash, sizeof(hash));
    return ALPHABET[val % ALPHABET_LEN];
}

static void secure_shuffle(const char **arr, int n) {
    for (int i = n - 1; i > 0; i--) {
        uint32_t j = randombytes_uniform((uint32_t)(i + 1));
        const char *tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
}

static int ensure_db_gpg(db_manager_t *m) {
    if (!m) return -1;
    gpgme_error_t gerr = gpgme_new(&m->gpg_ctx);
    if (gerr != GPG_ERR_NO_ERROR) return -1;
    gpgme_set_protocol(m->gpg_ctx, GPGME_PROTOCOL_OpenPGP);
    return 0;
}

static int db_init_gpg(db_manager_t *m, char *err_msg, size_t err_msg_sz) {
    gpgme_error_t gerr = gpgme_new(&m->gpg_ctx);
    GPG_CHECK(gerr, "gpgme_new");
    gpgme_set_protocol(m->gpg_ctx, GPGME_PROTOCOL_OpenPGP);
    gpgme_set_armor(m->gpg_ctx, 1);
    gerr = gpgme_set_pinentry_mode(m->gpg_ctx, GPGME_PINENTRY_MODE_ASK);
    GPG_CHECK(gerr, "gpgme_set_pinentry_mode");
    return 0;
cleanup:
    return -1;
}

static int db_read_file(const char *path, char **out_recipient, char **out_enc_data,
    char *err_msg, size_t err_msg_sz)
{
    if (!path || !out_recipient || !out_enc_data) {
        snprintf(err_msg, err_msg_sz, "Invalid database path");
        return -1;
    }
    *out_recipient = NULL;
    *out_enc_data = NULL;

    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        snprintf(err_msg, err_msg_sz, "Cannot open file safely: %s", strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > (uint64_t)DB_MAX_FILE_BYTES) {
        snprintf(err_msg, err_msg_sz, "Invalid database file type or size limit exceeded");
        close(fd);
        return -1;
    }
    FILE *f = fdopen(fd, "rb");
    if (!f) {
        snprintf(err_msg, err_msg_sz, "Cannot read database: %s", strerror(errno));
        close(fd);
        return -1;
    }

    char recipient_buf[256];
    if (!fgets(recipient_buf, sizeof(recipient_buf), f)) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("file_corrupted"));
        fclose(f);
        return -1;
    }
    char *nl = strchr(recipient_buf, '\n');
    if (!nl) {
        snprintf(err_msg, err_msg_sz, "Invalid or oversized recipient fingerprint");
        fclose(f);
        return -1;
    }
    *nl = '\0';
    size_t fp_len = strlen(recipient_buf);
    if (fp_len > 0 && recipient_buf[fp_len - 1] == '\r') recipient_buf[--fp_len] = '\0';
    gboolean fp_valid_len = (fp_len == 32 || fp_len == 40 || fp_len == 64);
    if (!fp_valid_len) {
        snprintf(err_msg, err_msg_sz, "Invalid recipient fingerprint");
        fclose(f);
        return -1;
    }
    for (size_t i = 0; i < fp_len; i++) {
        if (!g_ascii_isxdigit((guchar)recipient_buf[i])) {
            snprintf(err_msg, err_msg_sz, "Invalid recipient fingerprint");
            fclose(f);
            return -1;
        }
    }

    size_t file_cap = (size_t)st.st_size + 1;
    char *enc_data = malloc(file_cap);
    if (!enc_data) {
        snprintf(err_msg, err_msg_sz, "Out of memory while reading database");
        fclose(f);
        return -1;
    }
    size_t enc_len = 0;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (enc_len > (size_t)DB_MAX_FILE_BYTES - n || enc_len + n >= file_cap) {
            snprintf(err_msg, err_msg_sz, "Encrypted database exceeds size limit");
            free(enc_data);
            fclose(f);
            return -1;
        }
        if (memchr(buf, '\0', n) != NULL) {
            snprintf(err_msg, err_msg_sz, "Invalid binary data in armored database");
            free(enc_data);
            fclose(f);
            return -1;
        }
        memcpy(enc_data + enc_len, buf, n);
        enc_len += n;
    }
    int read_error = ferror(f);
    int close_error = fclose(f);
    if (read_error || close_error != 0) {
        snprintf(err_msg, err_msg_sz, "Error while reading database");
        free(enc_data);
        return -1;
    }
    if (!enc_data || enc_len == 0) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("file_corrupted"));
        free(enc_data);
        return -1;
    }
    enc_data[enc_len] = '\0';
    *out_recipient = xstrdup(recipient_buf);
    *out_enc_data = enc_data;
    return 0;
}

typedef struct {
    unsigned char *data;
    size_t used;
} secure_gpg_chunk_t;

typedef struct {
    GPtrArray *chunks;
    size_t len;
    size_t limit;
    gboolean overflow;
} bounded_gpg_output_t;

#define GPG_DECRYPT_CHUNK_SIZE (64U * 1024U)

static void secure_gpg_chunk_free(gpointer p) {
    secure_gpg_chunk_t *chunk = p;
    if (!chunk) return;
    if (chunk->data) sec_free(chunk->data, GPG_DECRYPT_CHUNK_SIZE);
    sodium_memzero(chunk, sizeof(*chunk));
    g_free(chunk);
}

static ssize_t bounded_gpg_write(void *handle, const void *buffer, size_t size) {
    bounded_gpg_output_t *out = handle;
    const unsigned char *src = buffer;
    if (!out || !out->chunks || (!buffer && size != 0)) { errno = EINVAL; return -1; }
    if (size > out->limit - out->len) {
        out->overflow = TRUE;
        errno = EFBIG;
        return -1;
    }
    size_t remaining = size;
    while (remaining > 0) {
        secure_gpg_chunk_t *chunk = out->chunks->len
            ? g_ptr_array_index(out->chunks, out->chunks->len - 1)
            : NULL;
        if (!chunk || chunk->used == GPG_DECRYPT_CHUNK_SIZE) {
            chunk = g_new0(secure_gpg_chunk_t, 1);
            if (!chunk) { errno = ENOMEM; return -1; }
            chunk->data = sodium_malloc(GPG_DECRYPT_CHUNK_SIZE);
            if (!chunk->data) {
                g_free(chunk);
                errno = ENOMEM;
                return -1;
            }
            g_ptr_array_add(out->chunks, chunk);
        }
        size_t room = GPG_DECRYPT_CHUNK_SIZE - chunk->used;
        size_t take = remaining < room ? remaining : room;
        memcpy(chunk->data + chunk->used, src, take);
        chunk->used += take;
        out->len += take;
        src += take;
        remaining -= take;
    }
    return (ssize_t)size;
}

static gboolean bounded_gpg_has_nul(const bounded_gpg_output_t *out) {
    if (!out || !out->chunks) return FALSE;
    for (guint i = 0; i < out->chunks->len; i++) {
        secure_gpg_chunk_t *chunk = g_ptr_array_index(out->chunks, i);
        if (chunk && chunk->used && memchr(chunk->data, '\0', chunk->used)) return TRUE;
    }
    return FALSE;
}

static gboolean bounded_gpg_copy(const bounded_gpg_output_t *out, char *dst, size_t dst_len) {
    if (!out || !out->chunks || !dst || dst_len < out->len + 1) return FALSE;
    size_t off = 0;
    for (guint i = 0; i < out->chunks->len; i++) {
        secure_gpg_chunk_t *chunk = g_ptr_array_index(out->chunks, i);
        if (!chunk || chunk->used == 0) continue;
        memcpy(dst + off, chunk->data, chunk->used);
        off += chunk->used;
    }
    if (off != out->len) return FALSE;
    dst[off] = '\0';
    return TRUE;
}

static char *db_gpg_decrypt(db_manager_t *m, const char *enc_data, size_t enc_len,
    char *err_msg, size_t err_msg_sz)
{
    gpgme_error_t gerr;
    gpgme_data_t in = NULL, out = NULL;
    char *result = NULL;
    bounded_gpg_output_t bounded = {0};
    struct gpgme_data_cbs cbs = {0};
    gpgme_key_t recipient_pub = NULL;

    if (!m || !enc_data || enc_len == 0 || enc_len > DB_MAX_FILE_BYTES) {
        snprintf(err_msg, err_msg_sz, "Invalid encrypted database size");
        return NULL;
    }

    bounded.chunks = g_ptr_array_new_with_free_func(secure_gpg_chunk_free);
    bounded.limit = DB_MAX_JSON_BYTES;
    if (!bounded.chunks) {
        snprintf(err_msg, err_msg_sz, "Cannot allocate bounded decryption buffer");
        return NULL;
    }
    cbs.write = bounded_gpg_write;

    gerr = gpgme_data_new_from_mem(&in, enc_data, enc_len, 0);
    GPG_CHECK(gerr, "gpgme_data_new_from_mem");
    gerr = gpgme_data_new_from_cbs(&out, &cbs, &bounded);
    GPG_CHECK(gerr, "gpgme_data_new_from_cbs");
    gerr = gpgme_op_decrypt_verify(m->gpg_ctx, in, out);
    if (gerr != GPG_ERR_NO_ERROR) {
        if (bounded.overflow)
            snprintf(err_msg, err_msg_sz, "Decrypted database exceeds size limit");
        else
            snprintf(err_msg, err_msg_sz, "%s%s", i18n("gpg_err"), gpgme_strerror(gerr));
        goto cleanup;
    }

    m->is_signed = FALSE;
    gpgme_verify_result_t vres = gpgme_op_verify_result(m->gpg_ctx);
    gpgme_signature_t sig = vres ? vres->signatures : NULL;
    if (!sig) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("unsigned_err"));
        goto cleanup;
    }
    if (sig->next || sig->status != GPG_ERR_NO_ERROR || !sig->fpr || !m->recipient) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("sig_mismatch"));
        goto cleanup;
    }
    if (gpgme_get_key(m->gpg_ctx, m->recipient, &recipient_pub, 0) != GPG_ERR_NO_ERROR ||
        !recipient_pub) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("key_mismatch"));
        goto cleanup;
    }

    gboolean signer_matches = g_ascii_strcasecmp(sig->fpr, m->recipient) == 0;
    if (!signer_matches) {
        for (gpgme_subkey_t sub = recipient_pub->subkeys; sub; sub = sub->next) {
            if (sub->fpr && g_ascii_strcasecmp(sub->fpr, sig->fpr) == 0) {
                signer_matches = TRUE;
                break;
            }
        }
    }
    if (!signer_matches) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("sig_mismatch"));
        goto cleanup;
    }

    gboolean recipient_matches = FALSE;
    gboolean recipient_pqc = FALSE;
    gpgme_decrypt_result_t dres = gpgme_op_decrypt_result(m->gpg_ctx);
    for (gpgme_recipient_t rec = dres ? dres->recipients : NULL; rec; rec = rec->next) {
        if (!rec->keyid || rec->status != GPG_ERR_NO_ERROR) continue;
        for (gpgme_subkey_t sub = recipient_pub->subkeys; sub; sub = sub->next) {
            if (!sub->keyid) continue;
            if (g_ascii_strcasecmp(sub->keyid, rec->keyid) == 0) {
                recipient_matches = TRUE;
                recipient_pqc =
                    rec->pubkey_algo == GPGME_PK_KYBER ||
                    sub->pubkey_algo == GPGME_PK_KYBER;
                break;
            }
        }
        if (recipient_matches) break;
    }
    if (!recipient_matches) {
        snprintf(err_msg, err_msg_sz,
            "Encrypted database recipient does not match the pinned OpenPGP key");
        goto cleanup;
    }

    m->is_pqc_encrypted = recipient_pqc;
    m->is_signed = TRUE;

    size_t rlen = bounded.len;
    if (rlen == 0 || rlen > DB_MAX_JSON_BYTES) {
        snprintf(err_msg, err_msg_sz, "Decrypted database is empty or exceeds size limit");
        goto cleanup;
    }
    if (bounded_gpg_has_nul(&bounded)) {
        snprintf(err_msg, err_msg_sz, "Decrypted content contains an embedded NUL byte");
        goto cleanup;
    }
    result = sodium_malloc(rlen + 1);
    if (!result) {
        snprintf(err_msg, err_msg_sz, "Cannot allocate protected memory for decrypted database");
        goto cleanup;
    }
    if (!bounded_gpg_copy(&bounded, result, rlen + 1)) {
        sec_free(result, rlen + 1);
        result = NULL;
        snprintf(err_msg, err_msg_sz, "Cannot assemble decrypted database");
        goto cleanup;
    }

cleanup:
    if (recipient_pub) gpgme_key_release(recipient_pub);
    if (in) gpgme_data_release(in);
    if (out) gpgme_data_release(out);
    if (bounded.chunks) g_ptr_array_free(bounded.chunks, TRUE);
    return result;
}

static gboolean gpg_key_has_pqc_encryption(gpgme_key_t key) {
    if (!key) return FALSE;
    for (gpgme_subkey_t sub = key->subkeys; sub; sub = sub->next) {
        if (sub->revoked || sub->expired || sub->disabled || sub->invalid || !sub->can_encrypt)
            continue;
        if (sub->pubkey_algo == GPGME_PK_KYBER) return TRUE;
    }
    return FALSE;
}

static gboolean db_recipient_has_pqc(db_manager_t *m) {
    if (!m || !m->gpg_ctx || !m->recipient) return FALSE;
    gpgme_key_t key = NULL;
    gpgme_error_t gerr = gpgme_get_key(m->gpg_ctx, m->recipient, &key, 0);
    if (gerr != GPG_ERR_NO_ERROR || !key) {
        if (key) gpgme_key_release(key);
        return FALSE;
    }
    gboolean ok = !key->revoked && !key->expired && !key->disabled &&
        !key->invalid && key->can_encrypt && gpg_key_has_pqc_encryption(key);
    gpgme_key_release(key);
    return ok;
}

static const char *gpg_openpgp_engine_path(void) {
    gpgme_engine_info_t info = NULL;
    if (gpgme_get_engine_info(&info) != GPG_ERR_NO_ERROR) return NULL;
    for (gpgme_engine_info_t cur = info; cur; cur = cur->next)
        if (cur->protocol == GPGME_PROTOCOL_OpenPGP && cur->file_name && cur->file_name[0])
            return cur->file_name;
    return NULL;
}

static char *db_gpg_encrypt(db_manager_t *m, const char *plaintext, size_t pt_len,
    char *err_msg, size_t err_msg_sz)
{
    gpgme_key_t recipient_key = NULL;
    gpgme_key_t signer = NULL;
    GError *spawn_err = NULL;
    GSubprocess *proc = NULL;
    GBytes *input = NULL, *out_bytes = NULL, *err_bytes = NULL;
    char *result = NULL;

    if (!m || !m->recipient || !plaintext || pt_len == 0 || pt_len > DB_MAX_JSON_BYTES) {
        snprintf(err_msg, err_msg_sz, "Invalid data or missing recipient key");
        return NULL;
    }

    gpgme_error_t gerr = gpgme_get_key(m->gpg_ctx, m->recipient, &recipient_key, 0);
    if (gerr != GPG_ERR_NO_ERROR || !recipient_key) {
        snprintf(err_msg, err_msg_sz, "Cannot load OpenPGP recipient key: %s", gpgme_strerror(gerr));
        goto cleanup;
    }
    if (recipient_key->revoked || recipient_key->expired || recipient_key->disabled ||
        recipient_key->invalid || !recipient_key->can_encrypt ||
        !gpg_key_has_pqc_encryption(recipient_key)) {
        snprintf(err_msg, err_msg_sz,
            "Selected OpenPGP key does not have a valid ML-KEM/Kyber encryption subkey");
        goto cleanup;
    }

    gerr = gpgme_get_key(m->gpg_ctx, m->recipient, &signer, 1);
    if (gerr != GPG_ERR_NO_ERROR || !signer || signer->revoked || signer->expired ||
        signer->disabled || signer->invalid || !signer->can_sign) {
        snprintf(err_msg, err_msg_sz,
            "The selected key must have a valid private signing key; unsigned databases are disabled");
        goto cleanup;
    }

    const char *gpg_path = gpg_openpgp_engine_path();
    if (!gpg_path) {
        snprintf(err_msg, err_msg_sz, "Cannot locate the GnuPG OpenPGP engine");
        goto cleanup;
    }

    const gchar *argv[] = {
        gpg_path,
        "--no-options",
        "--batch",
        "--yes",
        "--pinentry-mode", "ask",
        "--armor",
        "--always-trust",
        "--require-pqc-encryption",
        "--cipher-algo", "AES256",
        "--compress-algo", "none",
        "--local-user", m->recipient,
        "--recipient", m->recipient,
        "--sign",
        "--encrypt",
        NULL
    };

    proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDIN_PIPE | G_SUBPROCESS_FLAGS_STDOUT_PIPE |
        G_SUBPROCESS_FLAGS_STDERR_PIPE, &spawn_err);
    if (!proc) {
        snprintf(err_msg, err_msg_sz, "Cannot start GnuPG: %s",
            spawn_err ? spawn_err->message : "unknown error");
        goto cleanup;
    }

    input = g_bytes_new_static(plaintext, pt_len);
    if (!g_subprocess_communicate(proc, input, NULL, &out_bytes, &err_bytes, &spawn_err)) {
        snprintf(err_msg, err_msg_sz, "GnuPG communication failed: %s",
            spawn_err ? spawn_err->message : "unknown error");
        goto cleanup;
    }
    if (!g_subprocess_get_successful(proc)) {
        gsize elen = 0;
        const char *edata = err_bytes ? g_bytes_get_data(err_bytes, &elen) : NULL;
        if (edata && elen) {
            size_t n = elen < 180 ? (size_t)elen : 180;
            char tmp[181];
            memcpy(tmp, edata, n);
            tmp[n] = '\0';
            for (size_t i = 0; i < n; i++)
                if ((unsigned char)tmp[i] < 0x20 && tmp[i] != '\n' && tmp[i] != '\t') tmp[i] = ' ';
            snprintf(err_msg, err_msg_sz, "PQC encryption failed: %s", tmp);
        } else {
            snprintf(err_msg, err_msg_sz, "PQC encryption failed");
        }
        goto cleanup;
    }

    gsize out_len = 0;
    const unsigned char *out_data = out_bytes ? g_bytes_get_data(out_bytes, &out_len) : NULL;
    if (!out_data || out_len == 0 || (uint64_t)out_len > (uint64_t)DB_MAX_FILE_BYTES) {
        snprintf(err_msg, err_msg_sz, "Invalid or oversized PQC ciphertext");
        goto cleanup;
    }
    result = malloc((size_t)out_len + 1);
    if (!result) {
        snprintf(err_msg, err_msg_sz, "Out of memory while encrypting database");
        goto cleanup;
    }
    memcpy(result, out_data, (size_t)out_len);
    result[out_len] = '\0';

cleanup:
    if (spawn_err) g_error_free(spawn_err);
    if (input) g_bytes_unref(input);
    if (out_bytes) g_bytes_unref(out_bytes);
    if (err_bytes) g_bytes_unref(err_bytes);
    if (proc) g_object_unref(proc);
    if (signer) gpgme_key_release(signer);
    if (recipient_key) gpgme_key_release(recipient_key);
    return result;
}

static char *db_gpg_encrypt_legacy(db_manager_t *m, const char *plaintext, size_t pt_len,
    char *err_msg, size_t err_msg_sz)
{
    gpgme_error_t gerr;
    gpgme_data_t in = NULL, out = NULL;
    gpgme_key_t recipient_key = NULL;
    gpgme_key_t signer = NULL;
    char *result = NULL;

    if (!m || !m->recipient || !plaintext || pt_len == 0 || pt_len > DB_MAX_JSON_BYTES) {
        snprintf(err_msg, err_msg_sz, "Invalid data or missing recipient key");
        return NULL;
    }

    gerr = gpgme_data_new_from_mem(&in, plaintext, pt_len, 0);
    GPG_CHECK(gerr, "gpgme_data_new_from_mem");
    gerr = gpgme_data_new(&out);
    GPG_CHECK(gerr, "gpgme_data_new");
    gerr = gpgme_get_key(m->gpg_ctx, m->recipient, &recipient_key, 0);
    GPG_CHECK(gerr, "gpgme_get_key (recipient)");
    if (!recipient_key || recipient_key->revoked || recipient_key->expired ||
        recipient_key->disabled || recipient_key->invalid || !recipient_key->can_encrypt) {
        snprintf(err_msg, err_msg_sz, "Selected OpenPGP certificate is not valid for encryption");
        goto cleanup;
    }

    gerr = gpgme_get_key(m->gpg_ctx, m->recipient, &signer, 1);
    if (gerr != GPG_ERR_NO_ERROR || !signer || signer->revoked || signer->expired ||
        signer->disabled || signer->invalid || !signer->can_sign) {
        snprintf(err_msg, err_msg_sz,
            "The selected key must have a valid private signing key; unsigned databases are disabled");
        goto cleanup;
    }

    gpgme_signers_clear(m->gpg_ctx);
    gerr = gpgme_signers_add(m->gpg_ctx, signer);
    if (gerr != GPG_ERR_NO_ERROR) {
        snprintf(err_msg, err_msg_sz, "Cannot configure database signer: %s", gpgme_strerror(gerr));
        goto cleanup;
    }

    gpgme_key_t recips[] = { recipient_key, NULL };
    gerr = gpgme_op_encrypt_sign(m->gpg_ctx, recips, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    if (gerr != GPG_ERR_NO_ERROR) {
        snprintf(err_msg, err_msg_sz, "%s%s", i18n("gpg_err"), gpgme_strerror(gerr));
        goto cleanup;
    }

    size_t rlen = 0;
    char *raw = gpgme_data_release_and_get_mem(out, &rlen);
    out = NULL;
    if (!raw) {
        snprintf(err_msg, err_msg_sz, "GnuPG returned no encrypted data");
        goto cleanup;
    }
    if (rlen == 0 || (uint64_t)rlen > (uint64_t)DB_MAX_FILE_BYTES) {
        sodium_memzero(raw, rlen);
        gpgme_free(raw);
        snprintf(err_msg, err_msg_sz, "Invalid or oversized encrypted database");
        goto cleanup;
    }

    result = malloc(rlen + 1);
    if (!result) {
        sodium_memzero(raw, rlen);
        gpgme_free(raw);
        snprintf(err_msg, err_msg_sz, "Out of memory while encrypting database");
        goto cleanup;
    }
    memcpy(result, raw, rlen);
    result[rlen] = '\0';
    sodium_memzero(raw, rlen);
    gpgme_free(raw);

cleanup:
    if (signer) gpgme_key_release(signer);
    if (recipient_key) gpgme_key_release(recipient_key);
    if (in) gpgme_data_release(in);
    if (out) {
        size_t wipe_len = 0;
        char *wipe_buf = gpgme_data_release_and_get_mem(out, &wipe_len);
        if (wipe_buf) {
            sodium_memzero(wipe_buf, wipe_len);
            gpgme_free(wipe_buf);
        }
    }
    return result;
}

static char *hex_encode(const uint8_t *data, size_t len) {
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) snprintf(out + i*2, 3, "%02x", data[i]);
    out[len*2] = '\0';
    return out;
}

static int hex_nibble(unsigned char c) {
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return (int)(c - 'a') + 10;
    if (c >= 'A' && c <= 'F') return (int)(c - 'A') + 10;
    return -1;
}

static uint8_t *hex_decode(const char *hex, size_t *out_len) {
    if (!hex || !out_len) return NULL;
    *out_len = 0;
    size_t slen = strlen(hex);
    if ((slen % 2) != 0) return NULL;
    size_t dlen = slen / 2;
    uint8_t *out = malloc(dlen ? dlen : 1);
    if (!out) return NULL;
    for (size_t i = 0; i < dlen; i++) {
        int hi = hex_nibble((unsigned char)hex[i * 2]);
        int lo = hex_nibble((unsigned char)hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            sodium_memzero(out, dlen ? dlen : 1);
            free(out);
            return NULL;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = dlen;
    return out;
}

static char *db_encode_label(db_manager_t *m, const char *type, const char *size,
    const char *content_tag, const char *cipher, const char *dsalt) {
    if (!m || !m->salt || m->salt_len != 32 || !m->noise_key || m->noise_key_len != 32 ||
        !map_has_name(TYPE_MAP, TYPE_MAP_N, type) ||
        !map_has_name(SIZE_MAP, SIZE_MAP_N, size) ||
        !map_has_name(CIPHER_MAP, CIPHER_MAP_N, cipher) ||
        !content_tag || strlen(content_tag) != 2 ||
        !valid_ascii_tag_char((unsigned char)content_tag[0]) ||
        !valid_ascii_tag_char((unsigned char)content_tag[1]) ||
        !valid_alphabet_string(dsalt, 2))
        return NULL;

    const char *values[SCHEMA_COUNT];
    const char *raw_names[SCHEMA_COUNT];
    gboolean seen_names[SCHEMA_COUNT] = { FALSE, FALSE, FALSE, FALSE, FALSE };
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        if (!m->schema_order[i]) return NULL;
        if (strcmp(m->schema_order[i], "type") == 0)        { values[i] = type;        raw_names[i] = "type"; }
        else if (strcmp(m->schema_order[i], "size") == 0)   { values[i] = size;        raw_names[i] = "size"; }
        else if (strcmp(m->schema_order[i], "content_tag")==0){ values[i] = content_tag; raw_names[i] = "content_tag"; }
        else if (strcmp(m->schema_order[i], "cipher") == 0) { values[i] = cipher;      raw_names[i] = "cipher"; }
        else if (strcmp(m->schema_order[i], "dsalt") == 0)  { values[i] = dsalt;       raw_names[i] = "dsalt"; }
        else return NULL;
        int name_index = -1;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (strcmp(SCHEMA_PARTS[j], raw_names[i]) == 0) { name_index = j; break; }
        if (name_index < 0 || seen_names[name_index]) return NULL;
        seen_names[name_index] = TRUE;
    }
    char blocks[SCHEMA_COUNT][8];
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        const char *encoded = map_encode(raw_names[i], values[i]);
        int part_index = -1;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (strcmp(SCHEMA_PARTS[j], raw_names[i]) == 0) { part_index = j; break; }
        if (!encoded || part_index < 0 || strlen(encoded) != (size_t)PART_LENGTHS[part_index])
            return NULL;
        char schar = calculate_block_salt(m->noise_key, m->noise_key_len,
            m->salt, m->salt_len, part_index, encoded);
        int written = snprintf(blocks[i], sizeof(blocks[i]), "%s%c", encoded, schar);
        if (written < 0 || (size_t)written >= sizeof(blocks[i])) return NULL;
    }
    char label[128] = "";
    size_t pos = 0;
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        if (i > 0) label[pos++] = '-';
        size_t blen = strlen(blocks[i]);
        if (pos + blen >= sizeof(label)) return NULL;
        memcpy(label + pos, blocks[i], blen);
        pos += blen;
        label[pos] = '\0';
    }
    return xstrdup(label);
}

static int db_parse_label(db_manager_t *m, const char *label,
    parsed_block_t *out_blocks, int *out_count,
    char *err_msg, size_t err_msg_sz) {
    if (!m || !label || !out_blocks || !out_count || !m->salt || !m->noise_key ||
        strlen(label) >= 128) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("invalid_label"));
        return -1;
    }
    char buf[128];
    memcpy(buf, label, strlen(label) + 1);
    for (char *p = buf; *p; p++) *p = (char)toupper((unsigned char)*p);
    char *parts[SCHEMA_COUNT]; int cnt = 0;
    char *save = NULL;
    if (strlen(label) != 17 || label[0] == '-' || label[16] == '-' || strstr(label, "--")) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("label_err")); return -1;
    }
    char *tok = strtok_r(buf, "-", &save);
    while (tok && cnt < SCHEMA_COUNT) { parts[cnt++] = tok; tok = strtok_r(NULL, "-", &save); }
    if (cnt != SCHEMA_COUNT || tok != NULL) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("label_err")); return -1;
    }
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        const char *part_name = m->schema_order[i];
        if (!part_name) {
            snprintf(err_msg, err_msg_sz, "%s", i18n("invalid_label")); return -1;
        }
        int expected_len = 0;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (strcmp(SCHEMA_PARTS[j], part_name) == 0) { expected_len = FULL_PART_LENGTHS[j]; break; }
        if ((int)strlen(parts[i]) != expected_len) {
            snprintf(err_msg, err_msg_sz, "%s %d", i18n("block_len_err"), i+1); return -1;
        }
        strncpy(out_blocks[i].part_name, part_name, sizeof(out_blocks[i].part_name)-1);
        strncpy(out_blocks[i].block, parts[i], sizeof(out_blocks[i].block)-1);
        int val_len = expected_len - 1;
        memcpy(out_blocks[i].val, parts[i], val_len);
        out_blocks[i].val[val_len] = '\0';
        out_blocks[i].schar = parts[i][val_len];
        int part_index = -1;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (strcmp(SCHEMA_PARTS[j], part_name) == 0) { part_index = j; break; }
        if (part_index < 0) {
            snprintf(err_msg, err_msg_sz, "%s", i18n("invalid_label")); return -1;
        }
        if ((strcmp(part_name, "type") == 0 && !map_has_code(TYPE_MAP, TYPE_MAP_N, out_blocks[i].val)) ||
            (strcmp(part_name, "size") == 0 && !map_has_code(SIZE_MAP, SIZE_MAP_N, out_blocks[i].val)) ||
            (strcmp(part_name, "cipher") == 0 && !map_has_code(CIPHER_MAP, CIPHER_MAP_N, out_blocks[i].val)) ||
            (strcmp(part_name, "content_tag") == 0 &&
             (!valid_ascii_tag_char((unsigned char)out_blocks[i].val[0]) ||
              !valid_ascii_tag_char((unsigned char)out_blocks[i].val[1]))) ||
            (strcmp(part_name, "dsalt") == 0 && !valid_alphabet_string(out_blocks[i].val, 2))) {
            snprintf(err_msg, err_msg_sz, "%s", i18n("invalid_label")); return -1;
        }
        out_blocks[i].expected_schar = calculate_block_salt(m->noise_key, m->noise_key_len, m->salt, m->salt_len, part_index, out_blocks[i].val);
        if (out_blocks[i].schar != out_blocks[i].expected_schar) {
            snprintf(err_msg, err_msg_sz, "%s %d (%s)", i18n("block_err"), i+1, i18n(part_name)); return -1;
        }
        const char *decoded = map_decode(part_name, out_blocks[i].val);
        strncpy(out_blocks[i].decoded, decoded, sizeof(out_blocks[i].decoded)-1);
    }
    *out_count = cnt;
    return 0;
}

static char *build_label_tooltip(db_manager_t *m, const char *label) {
    parsed_block_t blocks[SCHEMA_COUNT];
    int block_count = 0;
    char err_buf[256] = "";
    if (!label || !label[0]) return g_strdup(i18n("invalid_label"));
    if (db_parse_label(m, label, blocks, &block_count, err_buf, sizeof(err_buf)) != 0)
        return g_strdup(err_buf);
    GString *s = g_string_new(NULL);
    for (int i = 0; i < block_count; i++) {
        if (i > 0) g_string_append_c(s, '\n');
        if (strcmp(blocks[i].part_name, "type") == 0 || strcmp(blocks[i].part_name, "size") == 0 ||
            strcmp(blocks[i].part_name, "cipher") == 0)
            g_string_append_printf(s, "%s: %s (%s)", i18n(blocks[i].part_name), blocks[i].val, blocks[i].decoded);
        else
            g_string_append_printf(s, "%s: %s", i18n(blocks[i].part_name), blocks[i].decoded);
    }
    return g_string_free(s, FALSE);
}

static GtkWidget *make_visual_label(db_manager_t *m, const char *label) {
    parsed_block_t blocks[SCHEMA_COUNT];
    int block_count = 0;
    char err_buf[256] = "";
    if (!m || !label || !label[0])
        return NULL;
    if (db_parse_label(m, label, blocks, &block_count, err_buf, sizeof(err_buf)) != 0)
        return NULL;

    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    for (int i = 0; i < block_count; i++) {
        GtkWidget *vl = gtk_label_new(blocks[i].val);
        gtk_style_context_add_class(gtk_widget_get_style_context(vl), "vlabel-val");
        gtk_box_pack_start(GTK_BOX(hbox), vl, FALSE, FALSE, 0);

        char sc[4] = { blocks[i].schar, '\0' };
        GtkWidget *sl = gtk_label_new(sc);
        gtk_style_context_add_class(gtk_widget_get_style_context(sl), "vlabel-salt");
        gtk_box_pack_start(GTK_BOX(hbox), sl, FALSE, FALSE, 0);
    }
    return hbox;
}

static gpg_key_info_t *gpg_list_keys(gpgme_ctx_t ctx, int secret_only, int *out_count) {
    gpgme_error_t gerr;
    gpgme_key_t key;
    gpg_key_info_t *result = NULL;
    int count = 0, cap = 0;
    gerr = gpgme_op_keylist_start(ctx, NULL, secret_only);
    if (gerr != GPG_ERR_NO_ERROR) { *out_count = 0; return NULL; }
    while (1) {
        gerr = gpgme_op_keylist_next(ctx, &key);
        if (gerr == GPG_ERR_EOF) break;
        if (gerr != GPG_ERR_NO_ERROR) break;
        if (key->revoked || key->expired || key->disabled || key->invalid ||
            !key->can_encrypt) {
            gpgme_key_release(key);
            continue;
        }
        if (count >= cap) {
            int new_cap = cap ? cap * 2 : 32;
            gpg_key_info_t *tmp = realloc(result, (size_t)new_cap * sizeof(gpg_key_info_t));
            if (!tmp) { gpgme_key_release(key); break; }
            result = tmp;
            cap = new_cap;
        }
        result[count].fingerprint = xstrdup(key->fpr ? key->fpr : "");
        result[count].uid = xstrdup((key->uids && key->uids->uid) ? key->uids->uid : "No Name");
        result[count].has_pqc = gpg_key_has_pqc_encryption(key);
        count++;
        gpgme_key_release(key);
    }
    gpgme_op_keylist_end(ctx);
    *out_count = count;
    return result;
}

static void gpg_free_key_list(gpg_key_info_t *list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) { free(list[i].fingerprint); free(list[i].uid); }
    free(list);
}
