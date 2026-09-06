#include "diskpass.h"

void *sec_alloc(size_t n) {
    void *p = sodium_malloc(n);
    if (!p) { fprintf(stderr, "FATAL: sodium_malloc failed\n"); abort(); }
    return p;
}

void sec_free(void *p, size_t n) {
    if (!p) return;
    SECURE_ZERO(p, n);
    sodium_free(p);
}

char *sec_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char *p = sec_alloc(len + 1);
    memcpy(p, s, len + 1);
    return p;
}

void sec_strfree(char *s) {
    if (!s) return;
    sec_free(s, strlen(s) + 1);
}

char *xstrdup(const char *s) {
    if (!s) return NULL;
    char *p = strdup(s);
    if (!p) { fprintf(stderr, "FATAL: strdup failed\n"); abort(); }
    return p;
}

void secure_free_string(char **s) {
    if (!s || !*s) return;
    size_t len = strlen(*s);
    if (len > 0) sodium_memzero(*s, len);
    free(*s);
    *s = NULL;
}

char *generate_salt(int length) {
    char *buf = malloc(length + 1);
    if (!buf) return NULL;
    for (int i = 0; i < length; i++)
        buf[i] = ALPHABET[randombytes_uniform(ALPHABET_LEN)];
    buf[length] = '\0';
    return buf;
}

char *generate_password(int length) {
    static const char pw_alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_+=";
    static const size_t pw_alpha_len = sizeof(pw_alpha) - 1;
    char *buf = sec_alloc(length + 1);
    for (int i = 0; i < length; i++)
        buf[i] = pw_alpha[randombytes_uniform(pw_alpha_len)];
    buf[length] = '\0';
    return buf;
}

char calculate_block_salt(const uint8_t *noise_key, size_t key_len,
    const uint8_t *salt, size_t salt_len,
    int part_index, const char *val_str)
{
    size_t vlen = strlen(val_str);
    size_t msg_len = salt_len + 1 + vlen;
    uint8_t *msg = malloc(msg_len);
    if (!msg) return ALPHABET[0];
    memcpy(msg, salt, salt_len);
    msg[salt_len] = (uint8_t)part_index;
    memcpy(msg + salt_len + 1, val_str, vlen);
    uint8_t hash[8];
    crypto_generichash(hash, sizeof(hash), msg, msg_len, noise_key, key_len);
    free(msg);
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) val = (val << 8) | hash[i];
    return ALPHABET[val % ALPHABET_LEN];
}

void secure_shuffle(const char **arr, int n) {
    for (int i = n - 1; i > 0; i--) {
        uint32_t j = randombytes_uniform((uint32_t)(i + 1));
        const char *tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
}

void db_entry_init(db_entry_t *e) { memset(e, 0, sizeof(*e)); }

void db_entry_clear(db_entry_t *e) {
    if (!e) return;
    secure_free_string(&e->label);
    secure_free_string(&e->type);
    secure_free_string(&e->size);
    secure_free_string(&e->cipher);
    secure_free_string(&e->content_tag);
    secure_free_string(&e->dsalt);
    secure_free_string(&e->tag_full);
    secure_free_string(&e->notes);
    secure_free_string(&e->alias);
    if (e->dpass) { sec_strfree(e->dpass); e->dpass = NULL; }
}

void db_manager_init(db_manager_t *m) { memset(m, 0, sizeof(*m)); strcpy(m->lang, "ru"); }

void db_manager_clear(db_manager_t *m) {
    if (!m) return;
    secure_free_string(&m->file_path);
    secure_free_string(&m->recipient);
    if (m->salt) { SECURE_ZERO(m->salt, m->salt_len); free(m->salt); m->salt = NULL; }
    if (m->noise_key) { SECURE_ZERO(m->noise_key, m->noise_key_len); free(m->noise_key); m->noise_key = NULL; }
    for (int i = 0; i < SCHEMA_COUNT; i++) { secure_free_string(&m->schema_order[i]); }
    for (int i = 0; i < m->entry_count; i++) db_entry_clear(&m->entries[i]);
    free(m->entries); m->entries = NULL; m->entry_count = 0; m->entry_cap = 0;
    if (m->gpg_ctx) { gpgme_release(m->gpg_ctx); m->gpg_ctx = NULL; }
}

int db_init_gpg(db_manager_t *m, char *err_msg, size_t err_msg_sz) {
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

static int gpg_clear_cache(db_manager_t *m) {
    if (!m || !m->recipient || !m->gpg_ctx) return -1;
    gpgme_error_t err;
    gpgme_key_t key = NULL;
    err = gpgme_get_key(m->gpg_ctx, m->recipient, &key, 1);
    if (err != GPG_ERR_NO_ERROR || !key) return -1;
    gpgme_subkey_t sub = key->subkeys;
    while (sub) {
        if (sub->keygrip) {
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "CLEAR_PASSPHRASE %s", sub->keygrip);
            gpgme_op_assuan_transact_ext(m->gpg_ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        }
        sub = sub->next;
    }
    gpgme_key_release(key);
    return 0;
}

int db_read_file(const char *path, char **out_recipient, char **out_enc_data,
    char *err_msg, size_t err_msg_sz)
{
    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(err_msg, err_msg_sz, "Cannot open file: %s", strerror(errno)); return -1; }
    char *recipient = NULL; size_t cap = 0;
    ssize_t len = getline(&recipient, &cap, f);
    if (len <= 0) { snprintf(err_msg, err_msg_sz, "%s", i18n("file_corrupted")); fclose(f); free(recipient); return -1; }
    while (len > 0 && (recipient[len-1]=='\n'||recipient[len-1]=='\r')) recipient[--len]='\0';
    char *enc_data = NULL; size_t enc_len = 0;
    char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        char *tmp = realloc(enc_data, enc_len + n + 1);
        if (!tmp) { fclose(f); free(recipient); free(enc_data); return -1; }
        enc_data = tmp;
        memcpy(enc_data + enc_len, buf, n);
        enc_len += n;
    }
    fclose(f);
    if (enc_data) enc_data[enc_len] = '\0';
    *out_recipient = recipient;
    *out_enc_data = enc_data;
    return 0;
}

char *db_gpg_decrypt(db_manager_t *m, const char *enc_data, size_t enc_len,
    char *err_msg, size_t err_msg_sz)
{
    gpg_clear_cache(m);
    gpgme_error_t gerr;
    gpgme_data_t in = NULL, out = NULL;
    char *result = NULL;
    gerr = gpgme_data_new_from_mem(&in, enc_data, enc_len, 0);
    GPG_CHECK(gerr, "gpgme_data_new_from_mem");
    gerr = gpgme_data_new(&out);
    GPG_CHECK(gerr, "gpgme_data_new");
    gerr = gpgme_op_decrypt(m->gpg_ctx, in, out);
    if (gerr != GPG_ERR_NO_ERROR) {
        snprintf(err_msg, err_msg_sz, "%s%s", i18n("gpg_err"), gpgme_strerror(gerr));
        goto cleanup;
    }
    size_t rlen = 0;
    char *raw = gpgme_data_release_and_get_mem(out, &rlen);
    out = NULL;
    if (!raw) goto cleanup;
    result = malloc(rlen + 1);
    if (!result) { gpgme_free(raw); goto cleanup; }
    memcpy(result, raw, rlen);
    result[rlen] = '\0';
    gpgme_free(raw);
cleanup:
    if (in) gpgme_data_release(in);
    if (out) gpgme_data_release(out);
    return result;
}

char *db_gpg_encrypt(db_manager_t *m, const char *plaintext, size_t pt_len,
    char *err_msg, size_t err_msg_sz)
{
    gpg_clear_cache(m);
    gpgme_error_t gerr;
    gpgme_data_t in = NULL, out = NULL;
    gpgme_key_t keys[2] = {NULL, NULL};
    char *result = NULL;
    gerr = gpgme_data_new_from_mem(&in, plaintext, pt_len, 0);
    GPG_CHECK(gerr, "gpgme_data_new_from_mem");
    gerr = gpgme_data_new(&out);
    GPG_CHECK(gerr, "gpgme_data_new");
    gerr = gpgme_get_key(m->gpg_ctx, m->recipient, &keys[0], 0);
    GPG_CHECK(gerr, "gpgme_get_key");
    gpgme_key_t recips[] = {keys[0], NULL};
    gerr = gpgme_op_encrypt(m->gpg_ctx, recips, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    if (gerr != GPG_ERR_NO_ERROR) {
        snprintf(err_msg, err_msg_sz, "%s%s", i18n("gpg_err"), gpgme_strerror(gerr));
        goto cleanup;
    }
    size_t rlen = 0;
    char *raw = gpgme_data_release_and_get_mem(out, &rlen);
    out = NULL;
    if (!raw) goto cleanup;
    result = malloc(rlen + 1);
    if (!result) { gpgme_free(raw); goto cleanup; }
    memcpy(result, raw, rlen);
    result[rlen] = '\0';
    gpgme_free(raw);
cleanup:
    if (keys[0]) gpgme_key_release(keys[0]);
    if (in) gpgme_data_release(in);
    if (out) gpgme_data_release(out);
    return result;
}

char *hex_encode(const uint8_t *data, size_t len) {
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) snprintf(out + i*2, 3, "%02x", data[i]);
    out[len*2] = '\0';
    return out;
}

uint8_t *hex_decode(const char *hex, size_t *out_len) {
    size_t slen = strlen(hex);
    if (slen % 2 != 0) return NULL;
    size_t dlen = slen / 2;
    uint8_t *out = malloc(dlen);
    if (!out) return NULL;
    for (size_t i = 0; i < dlen; i++) {
        unsigned int byte;
        if (sscanf(hex + i*2, "%2x", &byte) != 1) { free(out); return NULL; }
        out[i] = (uint8_t)byte;
    }
    *out_len = dlen;
    return out;
}

int db_load_json(db_manager_t *m, const char *json_str, char *err_msg, size_t err_msg_sz) {
    cJSON *root = cJSON_Parse(json_str);
    if (!root) { snprintf(err_msg, err_msg_sz, "JSON parse error"); return -1; }
    cJSON *j_salt = cJSON_GetObjectItem(root, "salt");
    if (j_salt && cJSON_IsString(j_salt)) {
        size_t slen = 0;
        uint8_t *s = hex_decode(j_salt->valuestring, &slen);
        if (s && slen == 32) { m->salt = s; m->salt_len = slen; } else free(s);
    }
    cJSON *j_noise = cJSON_GetObjectItem(root, "noise_key");
    if (j_noise && cJSON_IsString(j_noise)) {
        size_t nlen = 0;
        uint8_t *n = hex_decode(j_noise->valuestring, &nlen);
        if (n && nlen == 32) { m->noise_key = n; m->noise_key_len = nlen; } else free(n);
    }
    cJSON *j_schema = cJSON_GetObjectItem(root, "schema");
    if (j_schema && cJSON_IsArray(j_schema)) {
        int n = cJSON_GetArraySize(j_schema);
        if (n == SCHEMA_COUNT) {
            for (int i = 0; i < SCHEMA_COUNT; i++) {
                cJSON *item = cJSON_GetArrayItem(j_schema, i);
                if (item && cJSON_IsString(item)) m->schema_order[i] = xstrdup(item->valuestring);
            }
        }
    }
    bool schema_ok = true;
    for (int i = 0; i < SCHEMA_COUNT; i++) if (!m->schema_order[i]) schema_ok = false;
    if (!schema_ok) {
        for (int i = 0; i < SCHEMA_COUNT; i++) { secure_free_string(&m->schema_order[i]); }
        for (int i = 0; i < SCHEMA_COUNT; i++) m->schema_order[i] = xstrdup(SCHEMA_PARTS[i]);
    }
    cJSON *j_lang = cJSON_GetObjectItem(root, "lang");
    if (j_lang && cJSON_IsString(j_lang)) snprintf(m->lang, sizeof(m->lang), "%s", j_lang->valuestring);
    cJSON *j_entries = cJSON_GetObjectItem(root, "entries");
    if (j_entries && cJSON_IsArray(j_entries)) {
        int n = cJSON_GetArraySize(j_entries);
        m->entry_cap = n + 16;
        m->entries = calloc(m->entry_cap, sizeof(db_entry_t));
        m->entry_count = n;
        for (int i = 0; i < n; i++) {
            cJSON *je = cJSON_GetArrayItem(j_entries, i);
            db_entry_init(&m->entries[i]);
            cJSON *v;
            v = cJSON_GetObjectItem(je, "label");       if (v && cJSON_IsString(v)) m->entries[i].label       = xstrdup(v->valuestring);
            if (!m->entries[i].label) m->entries[i].label = xstrdup("");
            v = cJSON_GetObjectItem(je, "type");        if (v && cJSON_IsString(v)) m->entries[i].type        = xstrdup(v->valuestring);
            v = cJSON_GetObjectItem(je, "size");        if (v && cJSON_IsString(v)) m->entries[i].size        = xstrdup(v->valuestring);
            v = cJSON_GetObjectItem(je, "cipher");      if (v && cJSON_IsString(v)) m->entries[i].cipher      = xstrdup(v->valuestring);
            v = cJSON_GetObjectItem(je, "content_tag"); if (v && cJSON_IsString(v)) m->entries[i].content_tag = xstrdup(v->valuestring);
            v = cJSON_GetObjectItem(je, "dsalt");       if (v && cJSON_IsString(v)) m->entries[i].dsalt       = xstrdup(v->valuestring);
            v = cJSON_GetObjectItem(je, "tag_full");    if (v && cJSON_IsString(v)) m->entries[i].tag_full    = xstrdup(v->valuestring);
            v = cJSON_GetObjectItem(je, "dpass");       if (v && cJSON_IsString(v) && v->valuestring[0]) m->entries[i].dpass = sec_strdup(v->valuestring);
            v = cJSON_GetObjectItem(je, "notes");       if (v && cJSON_IsString(v)) m->entries[i].notes = xstrdup(v->valuestring);
            v = cJSON_GetObjectItem(je, "alias");       if (v && cJSON_IsString(v)) m->entries[i].alias = xstrdup(v->valuestring);
        }
    }
    cJSON_Delete(root);
    return 0;
}

int db_save(db_manager_t *m, char *err_msg, size_t err_msg_sz) {
    cJSON *root = cJSON_CreateObject();
    if (!root) { snprintf(err_msg, err_msg_sz, "JSON alloc failed"); return -1; }
    char *hex_salt = hex_encode(m->salt, m->salt_len);
    cJSON_AddStringToObject(root, "salt", hex_salt ? hex_salt : "");
    free(hex_salt);
    char *hex_noise = hex_encode(m->noise_key, m->noise_key_len);
    cJSON_AddStringToObject(root, "noise_key", hex_noise ? hex_noise : "");
    free(hex_noise);
    cJSON *j_schema = cJSON_CreateArray();
    for (int i = 0; i < SCHEMA_COUNT; i++) cJSON_AddItemToArray(j_schema, cJSON_CreateString(m->schema_order[i]));
    cJSON_AddItemToObject(root, "schema", j_schema);
    cJSON_AddStringToObject(root, "lang", m->lang);
    cJSON *j_entries = cJSON_CreateArray();
    for (int i = 0; i < m->entry_count; i++) {
        db_entry_t *e = &m->entries[i];
        cJSON *je = cJSON_CreateObject();
        if (e->label)       cJSON_AddStringToObject(je, "label",       e->label);
        if (e->type)        cJSON_AddStringToObject(je, "type",        e->type);
        if (e->size)        cJSON_AddStringToObject(je, "size",        e->size);
        if (e->cipher)      cJSON_AddStringToObject(je, "cipher",      e->cipher);
        if (e->content_tag) cJSON_AddStringToObject(je, "content_tag", e->content_tag);
        if (e->dsalt)       cJSON_AddStringToObject(je, "dsalt",       e->dsalt);
        if (e->tag_full)    cJSON_AddStringToObject(je, "tag_full",    e->tag_full);
        if (e->dpass)       cJSON_AddStringToObject(je, "dpass",       e->dpass);
        if (e->notes)       cJSON_AddStringToObject(je, "notes",       e->notes);
        if (e->alias)       cJSON_AddStringToObject(je, "alias",       e->alias);
        cJSON_AddItemToArray(j_entries, je);
    }
    cJSON_AddItemToObject(root, "entries", j_entries);
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) { snprintf(err_msg, err_msg_sz, "JSON print failed"); return -1; }
    char *enc = db_gpg_encrypt(m, json_str, strlen(json_str), err_msg, err_msg_sz);
    SECURE_ZERO(json_str, strlen(json_str));
    free(json_str);
    if (!enc) return -1;

    size_t tmp_len = strlen(m->file_path) + 5;
    char *tmp_path = malloc(tmp_len);
    if (!tmp_path) {
        snprintf(err_msg, err_msg_sz, "alloc failed for temp path");
        free(enc);
        return -1;
    }
    snprintf(tmp_path, tmp_len, "%s.tmp", m->file_path);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        snprintf(err_msg, err_msg_sz, "Cannot create temp file: %s", strerror(errno));
        free(tmp_path);
        free(enc);
        return -1;
    }

    FILE *f = fdopen(fd, "wb");
    if (!f) {
        snprintf(err_msg, err_msg_sz, "fdopen failed: %s", strerror(errno));
        close(fd);
        unlink(tmp_path);
        free(tmp_path);
        free(enc);
        return -1;
    }

    fprintf(f, "%s\n", m->recipient);
    fputs(enc, f);

    int write_err = ferror(f);
    if (fflush(f) != 0) write_err = 1;
    if (fsync(fd) != 0) write_err = 1;

    fclose(f);
    free(enc);

    if (write_err) {
        snprintf(err_msg, err_msg_sz, "Write error or fsync failed: %s", strerror(errno));
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }

    if (rename(tmp_path, m->file_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot rename temp file: %s", strerror(errno));
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }

    free(tmp_path);
    return 0;
}

db_manager_t *db_manager_open(const char *path, const char *forced_key,
    char *err_msg, size_t err_msg_sz) {
    db_manager_t *m = calloc(1, sizeof(db_manager_t));
    if (!m) { snprintf(err_msg, err_msg_sz, "alloc failed"); return NULL; }
    db_manager_init(m);
    if (db_init_gpg(m, err_msg, err_msg_sz) != 0) { db_manager_clear(m); free(m); return NULL; }
    m->file_path = xstrdup(path);
    char *enc_data = NULL;
    if (db_read_file(path, &m->recipient, &enc_data, err_msg, err_msg_sz) != 0) { db_manager_clear(m); free(m); return NULL; }
    if (forced_key && strcmp(forced_key, m->recipient) != 0) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("key_mismatch"));
        free(enc_data); db_manager_clear(m); free(m); return NULL;
    }
    char *json_str = db_gpg_decrypt(m, enc_data, enc_data ? strlen(enc_data) : 0, err_msg, err_msg_sz);
    free(enc_data);
    if (!json_str) { db_manager_clear(m); free(m); return NULL; }
    int rc = db_load_json(m, json_str, err_msg, err_msg_sz);
    SECURE_ZERO(json_str, strlen(json_str));
    free(json_str);
    if (rc != 0) { db_manager_clear(m); free(m); return NULL; }
    return m;
}

db_manager_t *db_manager_create(const char *path, const char *recipient,
    const char *lang, char *err_msg, size_t err_msg_sz) {
    db_manager_t *m = calloc(1, sizeof(db_manager_t));
    if (!m) { snprintf(err_msg, err_msg_sz, "alloc failed"); return NULL; }
    db_manager_init(m);
    if (!recipient) { snprintf(err_msg, err_msg_sz, "%s", i18n("no_recipient")); db_manager_clear(m); free(m); return NULL; }
    if (db_init_gpg(m, err_msg, err_msg_sz) != 0) { db_manager_clear(m); free(m); return NULL; }
    m->file_path = xstrdup(path);
    m->recipient = xstrdup(recipient);
    m->salt = malloc(32); m->noise_key = malloc(32);
    if (!m->salt || !m->noise_key) { db_manager_clear(m); free(m); return NULL; }
    m->salt_len = 32; m->noise_key_len = 32;
    randombytes_buf(m->salt, 32);
    randombytes_buf(m->noise_key, 32);
    char *tmp[SCHEMA_COUNT];
    for (int i = 0; i < SCHEMA_COUNT; i++) tmp[i] = xstrdup(SCHEMA_PARTS[i]);
    secure_shuffle((const char **)tmp, SCHEMA_COUNT);
    for (int i = 0; i < SCHEMA_COUNT; i++) m->schema_order[i] = tmp[i];
    if (lang) snprintf(m->lang, sizeof(m->lang), "%s", lang);

    char *dir = xstrdup(path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        struct stat st;
        if (stat(dir, &st) != 0) {
            if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
                snprintf(err_msg, err_msg_sz, "Cannot create directory: %s", strerror(errno));
                free(dir); db_manager_clear(m); free(m); return NULL;
            }
        } else if (!S_ISDIR(st.st_mode)) {
            snprintf(err_msg, err_msg_sz, "Path exists but is not a directory");
            free(dir); db_manager_clear(m); free(m); return NULL;
        }
        chmod(dir, 0700);
    }
    free(dir);

    m->entry_cap = 16;
    m->entries = calloc(m->entry_cap, sizeof(db_entry_t));
    m->entry_count = 0;
    if (db_save(m, err_msg, err_msg_sz) != 0) { db_manager_clear(m); free(m); return NULL; }
    return m;
}

char *db_encode_label(db_manager_t *m, const char *type, const char *size,
    const char *content_tag, const char *cipher, const char *dsalt) {
    const char *values[SCHEMA_COUNT];
    const char *raw_names[SCHEMA_COUNT];
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        if (strcmp(m->schema_order[i], "type") == 0)        { values[i] = type;        raw_names[i] = "type"; }
        else if (strcmp(m->schema_order[i], "size") == 0)   { values[i] = size;        raw_names[i] = "size"; }
        else if (strcmp(m->schema_order[i], "content_tag")==0){ values[i] = content_tag; raw_names[i] = "content_tag"; }
        else if (strcmp(m->schema_order[i], "cipher") == 0) { values[i] = cipher;      raw_names[i] = "cipher"; }
        else if (strcmp(m->schema_order[i], "dsalt") == 0)  { values[i] = dsalt;       raw_names[i] = "dsalt"; }
    }
    char blocks[SCHEMA_COUNT][8];
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        const char *encoded = map_encode(raw_names[i], values[i]);
        int part_index = 0;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (strcmp(SCHEMA_PARTS[j], raw_names[i]) == 0) { part_index = j; break; }
        char schar = calculate_block_salt(m->noise_key, m->noise_key_len, m->salt, m->salt_len, part_index, encoded);
        snprintf(blocks[i], sizeof(blocks[i]), "%s%c", encoded, schar);
    }
    char label[128] = "";
    size_t pos = 0;
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        if (i > 0) {
            if (pos < sizeof(label) - 1) label[pos++] = '-';
        }
        size_t blen = strlen(blocks[i]);
        if (pos + blen < sizeof(label)) {
            memcpy(label + pos, blocks[i], blen);
            pos += blen;
        }
        label[pos] = '\0';
    }
    return xstrdup(label);
}

int db_parse_label(db_manager_t *m, const char *label,
    parsed_block_t *out_blocks, int *out_count,
    char *err_msg, size_t err_msg_sz) {
    char buf[128];
    strncpy(buf, label, sizeof(buf)-1); buf[sizeof(buf)-1] = '\0';
    for (char *p = buf; *p; p++) *p = toupper((unsigned char)*p);
    char *parts[SCHEMA_COUNT]; int cnt = 0;
    char *save = NULL;
    char *tok = strtok_r(buf, "-", &save);
    while (tok && cnt < SCHEMA_COUNT) { parts[cnt++] = tok; tok = strtok_r(NULL, "-", &save); }
    if (cnt != SCHEMA_COUNT) { snprintf(err_msg, err_msg_sz, "%s", i18n("label_err")); return -1; }
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        const char *part_name = m->schema_order[i];
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
        int part_index = 0;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (strcmp(SCHEMA_PARTS[j], part_name) == 0) { part_index = j; break; }
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

char *build_label_tooltip(db_manager_t *m, const char *label) {
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

int db_add_entry(db_manager_t *m, const char *type, const char *size,
    const char *cipher, const char *content_tag, const char *dsalt,
    const char *tag_full, const char *dpass, const char *notes,
    const char *alias,
    char *err_msg, size_t err_msg_sz) {
    if (m->entry_count >= m->entry_cap) {
        int new_cap = m->entry_cap * 2;
        db_entry_t *ne = realloc(m->entries, new_cap * sizeof(db_entry_t));
        if (!ne) { snprintf(err_msg, err_msg_sz, "alloc failed"); return -1; }
        memset(ne + m->entry_cap, 0, (new_cap - m->entry_cap) * sizeof(db_entry_t));
        m->entries = ne; m->entry_cap = new_cap;
    }
    db_entry_t *e = &m->entries[m->entry_count];
    db_entry_init(e);
    e->label = db_encode_label(m, type, size, content_tag, cipher, dsalt);
    e->type = xstrdup(type); e->size = xstrdup(size); e->cipher = xstrdup(cipher);
    e->content_tag = xstrdup(content_tag); e->dsalt = xstrdup(dsalt);
    e->tag_full = xstrdup(tag_full ? tag_full : "");
    if (dpass && dpass[0]) e->dpass = sec_strdup(dpass);
    if (notes) e->notes = xstrdup(notes);
    if (alias && alias[0]) e->alias = xstrdup(alias);
    m->entry_count++;
    return db_save(m, err_msg, err_msg_sz);
}

int db_remove_entry(db_manager_t *m, const char *label, char *err_msg, size_t err_msg_sz) {
    for (int i = 0; i < m->entry_count; i++) {
        if (strcmp(m->entries[i].label, label) == 0) {
            db_entry_clear(&m->entries[i]);
            memmove(&m->entries[i], &m->entries[i+1], (m->entry_count - i - 1) * sizeof(db_entry_t));
            m->entry_count--;
            memset(&m->entries[m->entry_count], 0, sizeof(db_entry_t));
            return db_save(m, err_msg, err_msg_sz);
        }
    }
    return -1;
}

int db_update_entry(db_manager_t *m, const char *label,
    const char *new_dpass, const char *new_notes,
    const char *new_alias,
    char *err_msg, size_t err_msg_sz) {
    for (int i = 0; i < m->entry_count; i++) {
        if (strcmp(m->entries[i].label, label) == 0) {
            if (m->entries[i].dpass) { sec_strfree(m->entries[i].dpass); m->entries[i].dpass = NULL; }
            if (new_dpass && new_dpass[0]) m->entries[i].dpass = sec_strdup(new_dpass);
            free(m->entries[i].notes); m->entries[i].notes = NULL;
            if (new_notes) m->entries[i].notes = xstrdup(new_notes);
            free(m->entries[i].alias); m->entries[i].alias = NULL;
            if (new_alias && new_alias[0]) m->entries[i].alias = xstrdup(new_alias);
            return db_save(m, err_msg, err_msg_sz);
        }
    }
    return -1;
}

gpg_key_info_t *gpg_list_keys(gpgme_ctx_t ctx, int secret_only, int *out_count) {
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
        if (key->revoked || key->expired || key->disabled || key->invalid) {
            gpgme_key_release(key);
            continue;
        }
        if (count >= cap) {
            cap = cap ? cap * 2 : 32;
            gpg_key_info_t *tmp = realloc(result, cap * sizeof(gpg_key_info_t));
            if (!tmp) break;
            result = tmp;
        }
        result[count].fingerprint = xstrdup(key->fpr ? key->fpr : "");
        result[count].uid = xstrdup((key->uids && key->uids->uid) ? key->uids->uid : "No Name");
        count++;
        gpgme_key_release(key);
    }
    gpgme_op_keylist_end(ctx);
    *out_count = count;
    return result;
}

void gpg_free_key_list(gpg_key_info_t *list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) { free(list[i].fingerprint); free(list[i].uid); }
    free(list);
}
