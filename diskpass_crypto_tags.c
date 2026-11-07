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
    if (length <= 0 || (size_t)length > SIZE_MAX - 1U) return NULL;
    char *buf = malloc((size_t)length + 1U);
    if (!buf) return NULL;
    for (int i = 0; i < length; i++)
        buf[i] = ALPHABET[randombytes_uniform((uint32_t)ALPHABET_LEN)];
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


static char calculate_block_salt_v2(const uint8_t *noise_key, size_t key_len,
    const uint8_t *salt, size_t salt_len,
    int part_index, const char *val_str)
{
    if (!noise_key || !salt || !val_str || salt_len > 32 || key_len > 32)
        return ALPHABET[0];
    size_t vlen = strlen(val_str);
    if (vlen > 64) return ALPHABET[0];

    static const unsigned char domain[] = "DP-block-salt-v2";


    size_t msg_len = (sizeof(domain) - 1) + 4 + salt_len + vlen;
    unsigned char *msg = malloc(msg_len);
    if (!msg) return ALPHABET[0];
    size_t off = 0;
    memcpy(msg + off, domain, sizeof(domain) - 1); off += sizeof(domain) - 1;
    uint32_t pi = (uint32_t)part_index;
    msg[off++] = (unsigned char)pi;
    msg[off++] = (unsigned char)(pi >> 8);
    msg[off++] = (unsigned char)(pi >> 16);
    msg[off++] = (unsigned char)(pi >> 24);
    memcpy(msg + off, salt, salt_len); off += salt_len;
    memcpy(msg + off, val_str, vlen);

    uint8_t hash[8] = {0};
    if (crypto_generichash(hash, sizeof(hash), msg, msg_len, noise_key, key_len) != 0) {
        sodium_memzero(msg, msg_len); free(msg);
        sodium_memzero(hash, sizeof(hash));
        return ALPHABET[0];
    }
    sodium_memzero(msg, msg_len); free(msg);
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


    if (m->gpg_ctx) { gpgme_release(m->gpg_ctx); m->gpg_ctx = NULL; }
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


    if (st.st_nlink != 1) {
        snprintf(err_msg, err_msg_sz,
            "Database file has multiple hard links; refusing to open (potential attack). "
            "Copy the file to a private location and retry.");
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
    gboolean private_header = strcmp(recipient_buf, DB_CONTAINER_MAGIC) == 0;
    if (!private_header) {
        gboolean fp_valid_len = (fp_len == 32 || fp_len == 40 || fp_len == 64);
        if (!fp_valid_len) {
            snprintf(err_msg, err_msg_sz, "Invalid recipient fingerprint or container header");
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
    *out_recipient = private_header ? NULL : xstrdup(recipient_buf);
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

static char *db_make_selected_key_gpg_wrapper(gpgme_ctx_t base_ctx, const char *recipient,
    const char **out_home_dir, char *err_msg, size_t err_msg_sz)
{
    if (out_home_dir) *out_home_dir = NULL;
    if (!base_ctx || !recipient || !recipient[0]) return NULL;
    size_t rlen = strlen(recipient);
    if (rlen < 16 || rlen > 64) return NULL;
    for (size_t i = 0; i < rlen; i++)
        if (!g_ascii_isxdigit((guchar)recipient[i])) return NULL;

    gpgme_engine_info_t engine = gpgme_ctx_get_engine_info(base_ctx);
    while (engine && engine->protocol != GPGME_PROTOCOL_OpenPGP) engine = engine->next;
    if (!engine || !engine->file_name || !engine->file_name[0]) return NULL;
    if (out_home_dir) *out_home_dir = engine->home_dir;

    const char *base = g_get_user_runtime_dir();
    if (!base || !base[0]) base = g_get_user_cache_dir();
    if (!base || !base[0]) return NULL;
    char *dir = g_build_filename(base, "diskpass", "gpg-select", NULL);
    if (!dir) return NULL;
    if (g_mkdir_with_parents(dir, 0700) != 0 || chmod(dir, 0700) != 0) {
        if (err_msg && err_msg_sz)
            snprintf(err_msg, err_msg_sz, "Cannot create private GnuPG helper directory: %s", strerror(errno));
        g_free(dir);
        return NULL;
    }

    char *path = g_build_filename(dir, "selected-key-XXXXXX", NULL);
    g_free(dir);
    if (!path) return NULL;
    int fd = g_mkstemp_full(path, O_WRONLY | O_CLOEXEC, 0700);
    if (fd < 0) {
        if (err_msg && err_msg_sz)
            snprintf(err_msg, err_msg_sz, "Cannot create private GnuPG helper: %s", strerror(errno));
        g_free(path);
        return NULL;
    }

    char *qgpg = g_shell_quote(engine->file_name);
    char *qkey = g_shell_quote(recipient);
    char *script = (qgpg && qkey) ? g_strdup_printf(
        "#!/bin/sh\nexec %s --default-key %s --try-secret-key %s \"$@\"\n",
        qgpg, qkey, qkey) : NULL;
    g_free(qgpg); g_free(qkey);
    /* Keep generated helper non-executable and private while its contents are
     * written; grant execute permission only after the complete write. */
    gboolean ok = script && fchmod(fd, 0600) == 0;
    if (ok) ok = write_all_fd(fd, script, strlen(script)) == 0;
    if (ok) ok = fchmod(fd, 0700) == 0;
    if (ok) ok = fsync(fd) == 0;
    if (script) { sodium_memzero(script, strlen(script)); g_free(script); }
    if (close(fd) != 0) ok = FALSE;
    if (!ok) {
        if (err_msg && err_msg_sz && !err_msg[0])
            snprintf(err_msg, err_msg_sz, "Cannot write private GnuPG helper");
        unlink(path); g_free(path); return NULL;
    }
    return path;
}


static gboolean db_keygrip_is_valid(const char *grip) {
    if (!grip || strlen(grip) != 40) return FALSE;
    for (const char *p = grip; *p; p++)
        if (!g_ascii_isxdigit((guchar)*p)) return FALSE;
    return TRUE;
}

static gboolean db_keygrip_array_has(GPtrArray *grips, const char *grip) {
    if (!grips || !grip) return FALSE;
    for (guint i = 0; i < grips->len; i++) {
        const char *cur = g_ptr_array_index(grips, i);
        if (cur && g_ascii_strcasecmp(cur, grip) == 0) return TRUE;
    }
    return FALSE;
}

static void db_add_keygrip_field(GPtrArray *grips, const char *field) {
    if (!grips || !field || !field[0]) return;
    gchar **parts = g_strsplit(field, ",", -1);
    if (!parts) return;
    for (gchar **p = parts; *p; p++) {
        g_strstrip(*p);
        if (!db_keygrip_is_valid(*p) || db_keygrip_array_has(grips, *p)) continue;
        g_ptr_array_add(grips, g_ascii_strup(*p, -1));
    }
    g_strfreev(parts);
}


static gboolean db_collect_selected_keygrips(db_manager_t *m, GPtrArray *grips,
    char *err_msg, size_t err_msg_sz)
{
    if (!m || !m->gpg_ctx || !m->recipient || !m->recipient[0] || !grips) {
        snprintf(err_msg, err_msg_sz, "Cannot clear GnuPG cache: no OpenPGP key selected");
        return FALSE;
    }

    gpgme_key_t sec = NULL;
    gpgme_error_t gerr = gpgme_get_key(m->gpg_ctx, m->recipient, &sec, 1);
    if (gerr == GPG_ERR_NO_ERROR && sec) {
        for (gpgme_subkey_t sub = sec->subkeys; sub; sub = sub->next) {


            if (!sub->secret || !sub->can_encrypt || sub->revoked || sub->expired ||
                sub->disabled || sub->invalid)
                continue;
            db_add_keygrip_field(grips, sub->keygrip);
        }
    }
    if (sec) gpgme_key_release(sec);
    if (grips->len > 0) return TRUE;

    gpgme_engine_info_t engine = gpgme_ctx_get_engine_info(m->gpg_ctx);
    while (engine && engine->protocol != GPGME_PROTOCOL_OpenPGP) engine = engine->next;
    if (!engine || !engine->file_name || !engine->file_name[0]) {
        snprintf(err_msg, err_msg_sz, "Cannot clear GnuPG cache: OpenPGP engine unavailable");
        return FALSE;
    }

    gchar *argv[9] = {0};
    int ai = 0;
    argv[ai++] = engine->file_name;
    if (engine->home_dir && engine->home_dir[0]) {
        argv[ai++] = "--homedir";
        argv[ai++] = engine->home_dir;
    }
    argv[ai++] = "--batch";
    argv[ai++] = "--with-colons";
    argv[ai++] = "--with-keygrip";
    argv[ai++] = "--list-secret-keys";
    argv[ai++] = m->recipient;
    argv[ai] = NULL;

    gchar *out = NULL;
    gchar *err = NULL;
    gint status = 0;
    GError *spawn_err = NULL;
    gboolean spawned = g_spawn_sync(NULL, argv, NULL, 0, NULL, NULL,
        &out, &err, &status, &spawn_err);
    if (!spawned || status != 0 || !out) {
        if (spawn_err) {
            snprintf(err_msg, err_msg_sz, "Cannot list selected keygrips: %s", spawn_err->message);
            g_error_free(spawn_err);
        } else {
            snprintf(err_msg, err_msg_sz, "Cannot list selected keygrips with GnuPG");
        }
        if (out) { sodium_memzero(out, strlen(out)); g_free(out); }
        if (err) { sodium_memzero(err, strlen(err)); g_free(err); }
        return FALSE;
    }
    if (spawn_err) g_error_free(spawn_err);

    gchar **lines = g_strsplit(out, "\n", -1);
    if (lines) {
        gboolean want_grip = FALSE;
        for (gchar **line = lines; *line; line++) {
            gchar **fields = g_strsplit(*line, ":", -1);
            if (!fields) continue;
            gsize nf = g_strv_length(fields);
            if (nf > 0 && (strcmp(fields[0], "sec") == 0 || strcmp(fields[0], "ssb") == 0)) {


                want_grip = nf > 11 && fields[11] && strchr(fields[11], 'e') != NULL;
            } else if (nf > 9 && strcmp(fields[0], "grp") == 0) {
                if (want_grip) db_add_keygrip_field(grips, fields[9]);
                want_grip = FALSE;
            }
            g_strfreev(fields);
        }
        g_strfreev(lines);
    }
    sodium_memzero(out, strlen(out));
    g_free(out);
    if (err) { sodium_memzero(err, strlen(err)); g_free(err); }

    if (grips->len == 0) {
        snprintf(err_msg, err_msg_sz,
            "Cannot clear GnuPG cache: selected private key has no usable keygrip");
        return FALSE;
    }
    return TRUE;
}

static char *db_find_gpg_connect_agent(gpgme_ctx_t ctx) {
    char *agent = g_find_program_in_path("gpg-connect-agent");
    if (agent) return agent;

    gpgme_engine_info_t engine = gpgme_ctx_get_engine_info(ctx);
    while (engine && engine->protocol != GPGME_PROTOCOL_OpenPGP) engine = engine->next;
    if (!engine || !engine->file_name || !engine->file_name[0]) return NULL;
    char *dir = g_path_get_dirname(engine->file_name);
    if (!dir) return NULL;
    char *candidate = g_build_filename(dir, "gpg-connect-agent", NULL);
    g_free(dir);
    if (!candidate) return NULL;
    if (!g_file_test(candidate, G_FILE_TEST_IS_EXECUTABLE)) {
        g_free(candidate);
        return NULL;
    }
    return candidate;
}

static gboolean db_clear_selected_key_passphrase_cache(db_manager_t *m,
    char *err_msg, size_t err_msg_sz)
{
    GPtrArray *grips = g_ptr_array_new_with_free_func(g_free);
    if (!grips) {
        snprintf(err_msg, err_msg_sz, "Cannot allocate GnuPG cache-clear state");
        return FALSE;
    }
    if (!db_collect_selected_keygrips(m, grips, err_msg, err_msg_sz)) {
        g_ptr_array_free(grips, TRUE);
        return FALSE;
    }

    char *agent = db_find_gpg_connect_agent(m->gpg_ctx);
    if (!agent) {
        snprintf(err_msg, err_msg_sz,
            "Cannot clear GnuPG cache: gpg-connect-agent was not found");
        g_ptr_array_free(grips, TRUE);
        return FALSE;
    }

    gpgme_engine_info_t engine = gpgme_ctx_get_engine_info(m->gpg_ctx);
    while (engine && engine->protocol != GPGME_PROTOCOL_OpenPGP) engine = engine->next;
    const char *home = engine ? engine->home_dir : NULL;

    for (guint i = 0; i < grips->len; i++) {
        const char *grip = g_ptr_array_index(grips, i);
        char *command = g_strdup_printf("CLEAR_PASSPHRASE --mode=normal %s", grip);
        if (!command) {
            snprintf(err_msg, err_msg_sz, "Cannot build GnuPG cache-clear command");
            g_free(agent);
            g_ptr_array_free(grips, TRUE);
            return FALSE;
        }

        gchar *argv[7] = {0};
        int ai = 0;
        argv[ai++] = agent;
        argv[ai++] = "--quiet";
        if (home && home[0]) {
            argv[ai++] = "--homedir";
            argv[ai++] = (gchar *)home;
        }
        argv[ai++] = command;
        argv[ai++] = "/bye";
        argv[ai] = NULL;

        gchar *agent_out = NULL;
        gchar *agent_err = NULL;
        gint status = 0;
        GError *spawn_err = NULL;
        gboolean spawned = g_spawn_sync(NULL, argv, NULL, 0, NULL, NULL,
            &agent_out, &agent_err, &status, &spawn_err);
        gboolean ok = spawned && status == 0 &&
            (!agent_out || strstr(agent_out, "ERR ") == NULL);
        if (!ok) {
            if (spawn_err) {
                snprintf(err_msg, err_msg_sz, "Cannot clear GnuPG passphrase cache: %s",
                    spawn_err->message);
            } else if (agent_err && agent_err[0]) {
                snprintf(err_msg, err_msg_sz, "Cannot clear GnuPG passphrase cache: %.160s",
                    agent_err);
            } else {
                snprintf(err_msg, err_msg_sz, "GnuPG agent refused to clear passphrase cache");
            }
        }
        if (spawn_err) g_error_free(spawn_err);
        if (agent_out) { sodium_memzero(agent_out, strlen(agent_out)); g_free(agent_out); }
        if (agent_err) { sodium_memzero(agent_err, strlen(agent_err)); g_free(agent_err); }
        sodium_memzero(command, strlen(command));
        g_free(command);
        if (!ok) {
            g_free(agent);
            g_ptr_array_free(grips, TRUE);
            return FALSE;
        }
    }

    g_free(agent);
    g_ptr_array_free(grips, TRUE);
    return TRUE;
}

static char *db_gpg_decrypt(db_manager_t *m, const char *enc_data, size_t enc_len,
    char *err_msg, size_t err_msg_sz)
{
    gpgme_error_t gerr;
    gpgme_data_t in = NULL, out = NULL;
    gpgme_ctx_t decrypt_ctx = NULL;
    gpgme_ctx_t op_ctx = NULL;
    char *gpg_wrapper = NULL;
    char *result = NULL;
    bounded_gpg_output_t bounded = {0};
    struct gpgme_data_cbs cbs = {0};
    gpgme_key_t recipient_pub = NULL;

    if (!m || !enc_data || enc_len == 0 || enc_len > DB_MAX_FILE_BYTES) {
        snprintf(err_msg, err_msg_sz, "Invalid encrypted database size");
        return NULL;
    }


    if (m->force_fresh_pinentry &&
        !db_clear_selected_key_passphrase_cache(m, err_msg, err_msg_sz))
        return NULL;

    bounded.chunks = g_ptr_array_new_with_free_func(secure_gpg_chunk_free);
    bounded.limit = DB_MAX_JSON_BYTES;
    if (!bounded.chunks) {
        snprintf(err_msg, err_msg_sz, "Cannot allocate bounded decryption buffer");
        return NULL;
    }
    cbs.write = bounded_gpg_write;

    op_ctx = m->gpg_ctx;
    const char *engine_home = NULL;
    char helper_err[256] = "";
    gpg_wrapper = db_make_selected_key_gpg_wrapper(m->gpg_ctx, m->recipient,
        &engine_home, helper_err, sizeof(helper_err));
    if (!gpg_wrapper) {
        snprintf(err_msg, err_msg_sz, "Cannot initialize selected-key decryption: %s",
            helper_err[0] ? helper_err : "GnuPG helper unavailable");
        goto cleanup;
    }
    if (gpg_wrapper) {
        gerr = gpgme_new(&decrypt_ctx);
        if (gerr == GPG_ERR_NO_ERROR) gerr = gpgme_set_protocol(decrypt_ctx, GPGME_PROTOCOL_OpenPGP);
        if (gerr == GPG_ERR_NO_ERROR) gpgme_set_armor(decrypt_ctx, 1);
        if (gerr == GPG_ERR_NO_ERROR)
            gerr = gpgme_set_pinentry_mode(decrypt_ctx, GPGME_PINENTRY_MODE_ASK);
        if (gerr == GPG_ERR_NO_ERROR)
            gerr = gpgme_ctx_set_engine_info(decrypt_ctx, GPGME_PROTOCOL_OpenPGP,
                gpg_wrapper, engine_home);
        if (gerr == GPG_ERR_NO_ERROR) {
            op_ctx = decrypt_ctx;
        } else {
            if (decrypt_ctx) gpgme_release(decrypt_ctx);
            decrypt_ctx = NULL;
            snprintf(err_msg, err_msg_sz, "Cannot configure selected-key decryption: %s",
                gpgme_strerror(gerr));
            goto cleanup;
        }
    }

    gerr = gpgme_data_new_from_mem(&in, enc_data, enc_len, 0);
    GPG_CHECK(gerr, "gpgme_data_new_from_mem");
    gerr = gpgme_data_new_from_cbs(&out, &cbs, &bounded);
    GPG_CHECK(gerr, "gpgme_data_new_from_cbs");
    gerr = gpgme_op_decrypt_verify(op_ctx, in, out);
    if (gerr != GPG_ERR_NO_ERROR) {
        if (bounded.overflow)
            snprintf(err_msg, err_msg_sz, "Decrypted database exceeds size limit");
        else
            snprintf(err_msg, err_msg_sz, "%s%s", i18n("gpg_err"), gpgme_strerror(gerr));
        goto cleanup;
    }

    m->is_signed = FALSE;
    gpgme_verify_result_t vres = gpgme_op_verify_result(op_ctx);
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

    if (recipient_pub->revoked || recipient_pub->expired || recipient_pub->disabled || recipient_pub->invalid ||
        (sig->summary & (GPGME_SIGSUM_RED | GPGME_SIGSUM_KEY_REVOKED |
         GPGME_SIGSUM_KEY_EXPIRED | GPGME_SIGSUM_SIG_EXPIRED | GPGME_SIGSUM_SYS_ERROR))) {
        snprintf(err_msg, err_msg_sz, "Invalid, revoked or expired database signing certificate/signature");
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
    gpgme_decrypt_result_t dres = gpgme_op_decrypt_result(op_ctx);
    for (gpgme_recipient_t rec = dres ? dres->recipients : NULL; rec; rec = rec->next) {
        if (rec->status != GPG_ERR_NO_ERROR) continue;

        gboolean hidden = !rec->keyid || !rec->keyid[0];
        if (!hidden && rec->keyid) {
            hidden = TRUE;
            for (const char *p = rec->keyid; *p; p++) {
                if (*p != '0') { hidden = FALSE; break; }
            }
        }
        if (hidden) {
            recipient_matches = TRUE;
            recipient_pqc = rec->pubkey_algo == GPGME_PK_KYBER;
            break;
        }

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
    if (decrypt_ctx) gpgme_release(decrypt_ctx);
    if (gpg_wrapper) { (void)unlink(gpg_wrapper); g_free(gpg_wrapper); }
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


static gboolean gpg_key_has_any_secret(gpgme_key_t key) {
    if (!key) return FALSE;
    if (key->secret) return TRUE;
    for (gpgme_subkey_t sub = key->subkeys; sub; sub = sub->next)
        if (sub->secret) return TRUE;
    return FALSE;
}

static gboolean gpg_key_has_secret_signing(gpgme_key_t key) {
    if (!key) return FALSE;
    for (gpgme_subkey_t sub = key->subkeys; sub; sub = sub->next) {
        if (sub->revoked || sub->expired || sub->disabled || sub->invalid || !sub->can_sign)
            continue;
        if (sub->secret) return TRUE;
    }
    return FALSE;
}

static gboolean gpg_key_has_secret_encryption(gpgme_key_t key) {
    if (!key) return FALSE;
    for (gpgme_subkey_t sub = key->subkeys; sub; sub = sub->next) {
        if (sub->revoked || sub->expired || sub->disabled || sub->invalid || !sub->can_encrypt)
            continue;
        if (sub->secret) return TRUE;
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

static gboolean gpg_key_usable_for_database(gpgme_ctx_t ctx, const char *fingerprint,
    gboolean require_pqc, char *err_msg, size_t err_msg_sz)
{
    gpgme_key_t pub = NULL, sec = NULL;
    if (!ctx || !fingerprint || !fingerprint[0]) {
        if (err_msg && err_msg_sz) snprintf(err_msg, err_msg_sz, "No OpenPGP key selected");
        return FALSE;
    }

    gpgme_error_t pe = gpgme_get_key(ctx, fingerprint, &pub, 0);
    if (pe != GPG_ERR_NO_ERROR || !pub || pub->revoked || pub->expired ||
        pub->disabled || pub->invalid || !pub->can_encrypt) {
        if (err_msg && err_msg_sz)
            snprintf(err_msg, err_msg_sz, "Selected OpenPGP key is not valid for encryption");
        if (pub) gpgme_key_release(pub);
        return FALSE;
    }
    if (require_pqc && !gpg_key_has_pqc_encryption(pub)) {
        if (err_msg && err_msg_sz)
            snprintf(err_msg, err_msg_sz,
                "Selected OpenPGP key has no valid ML-KEM/Kyber encryption subkey");
        gpgme_key_release(pub);
        return FALSE;
    }

    gpgme_error_t se = gpgme_get_key(ctx, fingerprint, &sec, 1);
    gboolean secret_ok = se == GPG_ERR_NO_ERROR && sec &&
        !sec->revoked && !sec->expired && !sec->disabled && !sec->invalid;
    if (!secret_ok || !gpg_key_has_secret_signing(sec)) {
        if (err_msg && err_msg_sz)
            snprintf(err_msg, err_msg_sz,
                "Selected OpenPGP key has no usable private signing key");
        if (sec) gpgme_key_release(sec);
        gpgme_key_release(pub);
        return FALSE;
    }
    if (!gpg_key_has_secret_encryption(sec)) {
        if (err_msg && err_msg_sz)
            snprintf(err_msg, err_msg_sz,
                "Selected OpenPGP key has no usable private decryption key");
        gpgme_key_release(sec);
        gpgme_key_release(pub);
        return FALSE;
    }

    gpgme_key_release(sec);
    gpgme_key_release(pub);
    return TRUE;
}

static gboolean gpg_key_usable_for_unlock(gpgme_ctx_t ctx, const char *fingerprint,
    char *err_msg, size_t err_msg_sz)
{
    if (!ctx || !fingerprint || !fingerprint[0]) {
        if (err_msg && err_msg_sz) snprintf(err_msg, err_msg_sz, "No OpenPGP key selected");
        return FALSE;
    }
    gpgme_key_t sec = NULL;
    gpgme_error_t e = gpgme_get_key(ctx, fingerprint, &sec, 1);
    gboolean ok = e == GPG_ERR_NO_ERROR && sec &&
        !sec->revoked && !sec->expired && !sec->disabled && !sec->invalid &&
        gpg_key_has_secret_encryption(sec);
    if (!ok && err_msg && err_msg_sz)
        snprintf(err_msg, err_msg_sz, "Selected OpenPGP key has no usable private decryption key");
    if (sec) gpgme_key_release(sec);
    return ok;
}

static gboolean gpg_openpgp_engine_is_pqc_capable(void) {
    gpgme_engine_info_t info = NULL;
    if (gpgme_get_engine_info(&info) != GPG_ERR_NO_ERROR) return FALSE;
    for (gpgme_engine_info_t cur = info; cur; cur = cur->next) {
        if (cur->protocol != GPGME_PROTOCOL_OpenPGP || !cur->version) continue;
        unsigned major = 0, minor = 0;
        if (sscanf(cur->version, "%u.%u", &major, &minor) == 2)
            return major > 2 || (major == 2 && minor >= 5);
    }
    return FALSE;
}

static const char *gpg_openpgp_engine_path(void) {
    gpgme_engine_info_t info = NULL;
    if (gpgme_get_engine_info(&info) != GPG_ERR_NO_ERROR) return NULL;
    for (gpgme_engine_info_t cur = info; cur; cur = cur->next)
        if (cur->protocol == GPGME_PROTOCOL_OpenPGP && cur->file_name && cur->file_name[0])
            return cur->file_name;
    return NULL;
}

static unsigned char *db_gpg_encrypt_binary_pqc(db_manager_t *m, const void *plaintext, size_t pt_len,
    gboolean hide_recipient, size_t *out_len, char *err_msg, size_t err_msg_sz)
{
    gpgme_error_t gerr;
    gpgme_data_t in = NULL, out = NULL;
    gpgme_key_t recipient_key = NULL;
    gpgme_key_t signer = NULL;
    unsigned char *result = NULL;
    char *raw = NULL;
    size_t rlen = 0;

    if (out_len) *out_len = 0;
    if (!m || !m->recipient || !plaintext || pt_len == 0 || pt_len > DB_MAX_JSON_BYTES || !out_len) {
        snprintf(err_msg, err_msg_sz, "Invalid data or missing recipient key");
        return NULL;
    }


    gerr = gpgme_data_new_from_mem(&in, plaintext, pt_len, 0);
    if (gerr != GPG_ERR_NO_ERROR) {
        snprintf(err_msg, err_msg_sz, "Cannot allocate GPGME input buffer: %s", gpgme_strerror(gerr));
        goto cleanup;
    }
    gerr = gpgme_data_new(&out);
    if (gerr != GPG_ERR_NO_ERROR) {
        snprintf(err_msg, err_msg_sz, "Cannot allocate GPGME output buffer: %s", gpgme_strerror(gerr));
        goto cleanup;
    }
    gerr = gpgme_get_key(m->gpg_ctx, m->recipient, &recipient_key, 0);
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

    if (!gpg_openpgp_engine_is_pqc_capable()) {
        snprintf(err_msg, err_msg_sz,
            "PQC encryption requires a GnuPG OpenPGP engine with ML-KEM/Kyber support (GnuPG 2.5+)");
        goto cleanup;
    }

    gpgme_signers_clear(m->gpg_ctx);
    gerr = gpgme_signers_add(m->gpg_ctx, signer);
    if (gerr != GPG_ERR_NO_ERROR) {
        snprintf(err_msg, err_msg_sz, "Cannot configure database signer: %s", gpgme_strerror(gerr));
        goto cleanup;
    }

    {
        gpgme_key_t recips[] = { recipient_key, NULL };
        gpgme_encrypt_flags_t enc_flags = GPGME_ENCRYPT_ALWAYS_TRUST |
            GPGME_ENCRYPT_NO_COMPRESS;
        if (hide_recipient) enc_flags |= GPGME_ENCRYPT_THROW_KEYIDS;
        gerr = gpgme_op_encrypt_sign(m->gpg_ctx, recips, enc_flags, in, out);
        if (gerr != GPG_ERR_NO_ERROR) {
            snprintf(err_msg, err_msg_sz, "PQC encryption failed: %s", gpgme_strerror(gerr));
            goto cleanup;
        }
    }

    raw = gpgme_data_release_and_get_mem(out, &rlen);
    out = NULL;
    if (!raw) {
        snprintf(err_msg, err_msg_sz, "GnuPG returned no encrypted envelope");
        goto cleanup;
    }
    if (rlen == 0 || (uint64_t)rlen > (uint64_t)DB_MAX_FILE_BYTES) {
        sodium_memzero(raw, rlen);
        gpgme_free(raw);
        snprintf(err_msg, err_msg_sz, "Invalid or oversized PQC ciphertext");
        goto cleanup;
    }

    result = malloc((size_t)rlen);
    if (!result) {
        sodium_memzero(raw, rlen);
        gpgme_free(raw);
        snprintf(err_msg, err_msg_sz, "Out of memory while encrypting database envelope");
        goto cleanup;
    }
    memcpy(result, raw, (size_t)rlen);
    *out_len = (size_t)rlen;
    sodium_memzero(raw, rlen);
    gpgme_free(raw);

cleanup:
    if (signer) gpgme_key_release(signer);
    if (recipient_key) gpgme_key_release(recipient_key);
    if (in) gpgme_data_release(in);
    if (out) {
        size_t wipe_len = 0;
        char *wipe_buf = gpgme_data_release_and_get_mem(out, &wipe_len);
        if (wipe_buf) { sodium_memzero(wipe_buf, wipe_len); gpgme_free(wipe_buf); }
    }
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
    gpgme_encrypt_flags_t enc_flags = GPGME_ENCRYPT_ALWAYS_TRUST |
        GPGME_ENCRYPT_THROW_KEYIDS | GPGME_ENCRYPT_NO_COMPRESS;
    gerr = gpgme_op_encrypt_sign(m->gpg_ctx, recips, enc_flags, in, out);
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
    if ((!data && len != 0) || len > (SIZE_MAX - 1U) / 2U) return NULL;
    char *out = malloc(len * 2U + 1U);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) snprintf(out + i * 2U, 3, "%02x", data[i]);
    out[len * 2U] = '\0';
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
        char schar = calculate_block_salt_v2(m->noise_key, m->noise_key_len,
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


static gboolean db_label_matches_fields_compatible(db_manager_t *m, const char *label,
    const char *type, const char *size, const char *content_tag, const char *cipher, const char *dsalt)
{
    if (!m || !label || !type || !size || !content_tag || !cipher || !dsalt)
        return FALSE;

    char *current = db_encode_label(m, type, size, content_tag, cipher, dsalt);
    if (current && strcmp(current, label) == 0) {
        free(current);
        return TRUE;
    }
    free(current);

    if (!m->salt || m->salt_len != 32 || !m->noise_key || m->noise_key_len != 32 ||
        !map_has_name(TYPE_MAP, TYPE_MAP_N, type) ||
        !map_has_name(SIZE_MAP, SIZE_MAP_N, size) ||
        !map_has_name(CIPHER_MAP, CIPHER_MAP_N, cipher) ||
        strlen(content_tag) != 2 ||
        !valid_ascii_tag_char((unsigned char)content_tag[0]) ||
        !valid_ascii_tag_char((unsigned char)content_tag[1]) ||
        !valid_alphabet_string(dsalt, 2))
        return FALSE;

    const char *values[SCHEMA_COUNT];
    const char *raw_names[SCHEMA_COUNT];
    gboolean seen_names[SCHEMA_COUNT] = { FALSE, FALSE, FALSE, FALSE, FALSE };
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        if (!m->schema_order[i]) return FALSE;
        if (strcmp(m->schema_order[i], "type") == 0) {
            values[i] = type; raw_names[i] = "type";
        } else if (strcmp(m->schema_order[i], "size") == 0) {
            values[i] = size; raw_names[i] = "size";
        } else if (strcmp(m->schema_order[i], "content_tag") == 0) {
            values[i] = content_tag; raw_names[i] = "content_tag";
        } else if (strcmp(m->schema_order[i], "cipher") == 0) {
            values[i] = cipher; raw_names[i] = "cipher";
        } else if (strcmp(m->schema_order[i], "dsalt") == 0) {
            values[i] = dsalt; raw_names[i] = "dsalt";
        } else {
            return FALSE;
        }
        int name_index = -1;
        for (int j = 0; j < SCHEMA_COUNT; j++) {
            if (strcmp(SCHEMA_PARTS[j], raw_names[i]) == 0) {
                name_index = j;
                break;
            }
        }
        if (name_index < 0 || seen_names[name_index]) return FALSE;
        seen_names[name_index] = TRUE;
    }

    char legacy[128] = "";
    size_t pos = 0;
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        const char *encoded = map_encode(raw_names[i], values[i]);
        int part_index = -1;
        for (int j = 0; j < SCHEMA_COUNT; j++) {
            if (strcmp(SCHEMA_PARTS[j], raw_names[i]) == 0) {
                part_index = j;
                break;
            }
        }
        if (!encoded || part_index < 0 || strlen(encoded) != (size_t)PART_LENGTHS[part_index])
            return FALSE;

        char schar = calculate_block_salt(m->noise_key, m->noise_key_len,
            m->salt, m->salt_len, part_index, encoded);
        char block[8];
        int written = snprintf(block, sizeof(block), "%s%c", encoded, schar);
        if (written < 0 || (size_t)written >= sizeof(block)) return FALSE;

        if (i > 0) {
            if (pos + 1 >= sizeof(legacy)) return FALSE;
            legacy[pos++] = '-';
        }
        size_t blen = strlen(block);
        if (pos + blen >= sizeof(legacy)) return FALSE;
        memcpy(legacy + pos, block, blen);
        pos += blen;
        legacy[pos] = '\0';
    }

    gboolean ok = strcmp(legacy, label) == 0;
    sodium_memzero(legacy, sizeof(legacy));
    return ok;
}

static int db_parse_label(db_manager_t *m, const char *label,
    parsed_block_t *out_blocks, int *out_count,
    char *err_msg, size_t err_msg_sz) {
    if (out_count) *out_count = 0;
    if (!m || !label || !out_blocks || !out_count || !m->salt || !m->noise_key ||
        m->salt_len != 32 || m->noise_key_len != 32 || strnlen(label, 128) >= 128) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("invalid_label"));
        return -1;
    }
    memset(out_blocks, 0, sizeof(*out_blocks) * SCHEMA_COUNT);
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


        char expected_v2 = calculate_block_salt_v2(m->noise_key, m->noise_key_len,
            m->salt, m->salt_len, part_index, out_blocks[i].val);
        char expected_v1 = calculate_block_salt(m->noise_key, m->noise_key_len,
            m->salt, m->salt_len, part_index, out_blocks[i].val);
        out_blocks[i].expected_schar = expected_v2;
        if (out_blocks[i].schar != expected_v2 && out_blocks[i].schar != expected_v1) {
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

    if (!out_count) return NULL;
    *out_count = 0;
    if (!ctx) return NULL;


    gpgme_keylist_mode_t old_mode = gpgme_get_keylist_mode(ctx);
    gpgme_keylist_mode_t list_mode = old_mode | GPGME_KEYLIST_MODE_WITH_SECRET;
    gboolean mode_changed = FALSE;
    gerr = gpgme_set_keylist_mode(ctx, list_mode);
    if (gerr == GPG_ERR_NO_ERROR) {
        mode_changed = TRUE;
    } else {


    }

    gerr = gpgme_op_keylist_start(ctx, NULL, secret_only ? 1 : 0);
    if (gerr != GPG_ERR_NO_ERROR) {
        if (mode_changed) (void)gpgme_set_keylist_mode(ctx, old_mode);
        return NULL;
    }
    while (1) {
        gerr = gpgme_op_keylist_next(ctx, &key);
        if (gerr == GPG_ERR_EOF) break;
        if (gerr != GPG_ERR_NO_ERROR) break;


        const char *fpr_raw = key->fpr;
        if (!fpr_raw || !fpr_raw[0]) {
            for (gpgme_subkey_t sk = key->subkeys; sk; sk = sk->next) {
                if (sk->fpr && sk->fpr[0]) { fpr_raw = sk->fpr; break; }
            }
        }
        const char *uid = (key->uids && key->uids->uid && key->uids->uid[0])
            ? key->uids->uid : "(no uid)";

        gboolean has_secret = gpg_key_has_any_secret(key);
        gboolean has_secret_sign = gpg_key_has_secret_signing(key);
        gboolean has_secret_encrypt = gpg_key_has_secret_encryption(key);

        if (key->revoked || key->expired || key->disabled || key->invalid) {
            gpgme_key_release(key);
            continue;
        }
        if (!fpr_raw || !fpr_raw[0]) {
            gpgme_key_release(key);
            continue;
        }
        if (count >= cap) {
            int new_cap = cap ? cap * 2 : 32;
            if (new_cap < cap ||
                (size_t)new_cap > SIZE_MAX / sizeof(gpg_key_info_t)) {
                gpgme_key_release(key);
                break;
            }
            size_t alloc_bytes = (size_t)new_cap * sizeof(gpg_key_info_t);
            gpg_key_info_t *tmp = realloc(result, alloc_bytes);
            if (!tmp) {
                gpgme_key_release(key); break;
            }
            result = tmp;
            cap = new_cap;
        }
        result[count].fingerprint = xstrdup(fpr_raw);
        result[count].uid = xstrdup(uid);
        result[count].has_pqc = gpg_key_has_pqc_encryption(key);
        result[count].has_secret = has_secret;
        result[count].has_secret_sign = has_secret_sign;
        result[count].has_secret_encrypt = has_secret_encrypt;
        result[count].can_encrypt = key->can_encrypt ? TRUE : FALSE;
        count++;
        gpgme_key_release(key);
    }
    gpgme_op_keylist_end(ctx);
    if (mode_changed) (void)gpgme_set_keylist_mode(ctx, old_mode);
    *out_count = count;
    return result;
}

static void gpg_free_key_list(gpg_key_info_t *list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) { free(list[i].fingerprint); free(list[i].uid); }
    free(list);
}
