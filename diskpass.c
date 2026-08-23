#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <locale.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <gtk/gtk.h>
#include <gpgme.h>
#include <sodium.h>
#include <cjson/cJSON.h>

#define ARRAY_SIZE(a) ((sizeof(a)) / sizeof((a)[0]))
#define SECURE_ZERO(p,n) do { if((p)) sodium_memzero((p),(n)); } while(0)
#define GPG_CHECK(gerr, msg) do { \
    if ((gerr) != GPG_ERR_NO_ERROR) { \
        snprintf(err_msg, err_msg_sz, "%s: %s", (msg), gpgme_strerror(gerr)); \
        goto cleanup; \
    } \
} while(0)

static const char ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
static const size_t ALPHABET_LEN = 32;
static const char *SCHEMA_PARTS[] = {"type","size","content_tag","cipher","dsalt"};
static const int SCHEMA_COUNT = 5;
static const int PART_LENGTHS[] = {1, 2, 2, 1, 2};
static const int FULL_PART_LENGTHS[] = {2, 3, 3, 2, 3};

typedef struct { const char *name; const char *code; } map_entry_t;

static const map_entry_t TYPE_MAP[] = {
    {"HDD","H"},{"SSD","S"},{"USB","U"},{"M.2","M"},{"SD","D"},{"CF","C"},
    {"OPTICAL","O"},{"OTHER","X"},
    {"LTO1","1"},{"LTO2","2"},{"LTO3","3"},{"LTO4","4"},
    {"LTO5","5"},{"LTO6","6"},{"LTO7","7"},{"LTO8","8"},{"LTO9","9"}
};
static const int TYPE_MAP_N = ARRAY_SIZE(TYPE_MAP);

static const map_entry_t SIZE_MAP[] = {
    {"700MB","7M"},{"1GB","1A"},{"2GB","2A"},{"4GB","4G"},{"8GB","8G"},
    {"16GB","1F"},{"32GB","3F"},{"64GB","6F"},
    {"4.7GB","D4"},{"8.5GB","D8"},{"25GB","B5"},{"50GB","B0"},{"100GB","B1"},
    {"120GB","C1"},{"128GB","C2"},{"200GB","E1"},{"240GB","C3"},{"250GB","C4"},{"256GB","C5"},
    {"320GB","C6"},{"400GB","E2"},{"480GB","C7"},{"500GB","C8"},{"512GB","C9"},{"800GB","E3"},
    {"1TB","T1"},{"1.5TB","T2"},{"1.6TB","T3"},{"2TB","T4"},{"2.5TB","T5"},
    {"3TB","T6"},{"3.0TB","T7"},{"4TB","T8"},{"6TB","T9"},{"6.25TB","TA"},
    {"8TB","TB"},{"10TB","TC"},{"12TB","TD"},{"14TB","TE"},{"15TB","TF"},
    {"16TB","TG"},{"18TB","TH"},{"20TB","TJ"},{"22TB","TK"},
    {"24TB","TM"},{"30TB","TN"},{"36TB","TP"},{"45TB","TQ"}
};
static const int SIZE_MAP_N = ARRAY_SIZE(SIZE_MAP);

static const map_entry_t CIPHER_MAP[] = {
    {"LUKS","L"},{"VERACRYPT","V"},{"BITLOCKER","B"},
    {"7ZIP","7"},{"AGE","A"},{"GPG","G"},{"NONE","N"}
};
static const int CIPHER_MAP_N = ARRAY_SIZE(CIPHER_MAP);

static const char *SIZE_FOR_USB[] = {"1GB","2GB","4GB","8GB","16GB","32GB","64GB","128GB","256GB","512GB","1TB","2TB",NULL};
static const char *SIZE_FOR_SD[] = {"4GB","8GB","16GB","32GB","64GB","128GB","256GB","512GB","1TB","2TB",NULL};
static const char *SIZE_FOR_CF[] = {"4GB","8GB","16GB","32GB","64GB","128GB","256GB","512GB",NULL};
static const char *SIZE_FOR_HDD[] = {"250GB","320GB","500GB","1TB","2TB","3TB","4TB","6TB","8TB","10TB","12TB","14TB","16TB","18TB","20TB","22TB","24TB",NULL};
static const char *SIZE_FOR_SSD[] = {"120GB","128GB","240GB","250GB","256GB","480GB","500GB","512GB","1TB","2TB","4TB","8TB","16TB",NULL};
static const char *SIZE_FOR_M2[] = {"128GB","250GB","256GB","500GB","512GB","1TB","2TB","4TB","8TB",NULL};
static const char *SIZE_FOR_OPT[] = {"700MB","4.7GB","8.5GB","25GB","50GB","100GB",NULL};
static const char *SIZE_FOR_LTO1[] = {"100GB","200GB",NULL};
static const char *SIZE_FOR_LTO2[] = {"200GB","400GB",NULL};
static const char *SIZE_FOR_LTO3[] = {"400GB","800GB",NULL};
static const char *SIZE_FOR_LTO4[] = {"800GB","1.6TB",NULL};
static const char *SIZE_FOR_LTO5[] = {"1.5TB","3.0TB",NULL};
static const char *SIZE_FOR_LTO6[] = {"2.5TB","6.25TB",NULL};
static const char *SIZE_FOR_LTO7[] = {"6TB","15TB",NULL};
static const char *SIZE_FOR_LTO8[] = {"12TB","30TB",NULL};
static const char *SIZE_FOR_LTO9[] = {"18TB","45TB",NULL};
static const char *SIZE_FOR_OTHER[] = {
    "700MB","1GB","2GB","4GB","8GB","16GB","32GB","64GB",
    "4.7GB","8.5GB","25GB","50GB","100GB",
    "120GB","128GB","200GB","240GB","250GB","256GB",
    "320GB","400GB","480GB","500GB","512GB","800GB",
    "1TB","1.5TB","1.6TB","2TB","2.5TB","3TB","3.0TB",
    "4TB","6TB","6.25TB","8TB","10TB","12TB","14TB","15TB",
    "16TB","18TB","20TB","22TB","24TB","30TB","36TB","45TB",NULL
};

typedef struct { const char *type; const char **sizes; } type_size_assoc_t;
static const type_size_assoc_t TYPE_SIZE_MAP[] = {
    {"USB",SIZE_FOR_USB},{"SD",SIZE_FOR_SD},{"CF",SIZE_FOR_CF},
    {"HDD",SIZE_FOR_HDD},{"SSD",SIZE_FOR_SSD},{"M.2",SIZE_FOR_M2},
    {"OPTICAL",SIZE_FOR_OPT},{"OTHER",SIZE_FOR_OTHER},
    {"LTO1",SIZE_FOR_LTO1},{"LTO2",SIZE_FOR_LTO2},{"LTO3",SIZE_FOR_LTO3},
    {"LTO4",SIZE_FOR_LTO4},{"LTO5",SIZE_FOR_LTO5},{"LTO6",SIZE_FOR_LTO6},
    {"LTO7",SIZE_FOR_LTO7},{"LTO8",SIZE_FOR_LTO8},{"LTO9",SIZE_FOR_LTO9}
};
static const int TYPE_SIZE_MAP_N = ARRAY_SIZE(TYPE_SIZE_MAP);

static void *sec_alloc(size_t n) {
    void *p = sodium_malloc(n);
    if (!p) { fprintf(stderr, "FATAL: sodium_malloc failed\n"); abort(); }
    return p;
}

static void sec_free(void *p, size_t n) {
    if (!p) return;
    SECURE_ZERO(p, n);
    sodium_free(p);
}

static char *sec_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char *p = sec_alloc(len + 1);
    memcpy(p, s, len + 1);
    return p;
}

static void sec_strfree(char *s) {
    if (!s) return;
    sec_free(s, strlen(s) + 1);
}

static char *xstrdup(const char *s) {
    if (!s) return NULL;
    char *p = strdup(s);
    if (!p) { fprintf(stderr, "FATAL: strdup failed\n"); abort(); }
    return p;
}

static void secure_free_string(char **s) {
    if (!s || !*s) return;
    size_t len = strlen(*s);
    if (len > 0) sodium_memzero(*s, len);
    free(*s);
    *s = NULL;
}

typedef struct { const char *key; const char *ru; const char *en; } i18n_entry_t;

static const i18n_entry_t I18N[] = {
    {"app_desc","Безопасное хранилище паролей для дисков","Secure password storage for disks"},
    {"open_db","Открыть базу","Open Database"},
    {"create_db","Создать новую базу","Create New Database"},
    {"setup_title","Настройка шифрования","Encryption Setup"},
    {"db_file","Файл базы:","Database File:"},
    {"not_selected","не выбран","not selected"},
    {"pgp_key","Ключ OpenPGP:","OpenPGP Key:"},
    {"language","Язык:","Language:"},
    {"back","Назад","Back"},
    {"create_btn","Создать базу","Create Database"},
    {"no_keys","Подходящие OpenPGP ключи не найдены.","No suitable OpenPGP keys found."},
    {"gpg_err","Ошибка GPG: ","GPG Error: "},
    {"locked_title","База заблокирована","Database Locked"},
    {"file","Файл:","File:"},
    {"unlock_btn","Разблокировать","Unlock"},
    {"lock_db","Заблокировать базу","Lock Database"},
    {"add_entry","Добавить запись","Add Entry"},
    {"edit_entry","Изменить запись","Edit Entry"},
    {"del_entry","Удалить запись","Delete Entry"},
    {"show_schema","Показать схему меток","Show Label Schema"},
    {"search","Поиск...","Search..."},
    {"select_entry","Выберите запись","Select an entry"},
    {"copy_label","Копировать метку","Copy Label"},
    {"copy_pass","Копировать пароль","Copy Password"},
    {"full_tag","Полный тег","Full Tag"},
    {"password","Пароль","Password"},
    {"notes","Заметки","Notes"},
    {"delete_msg","Удалить?","Delete?"},
    {"schema_title","Схема меток","Label Schema"},
    {"block","Блок","Block"},
    {"val","Значение","Value"},
    {"chk","Соль","Salt"},
    {"schema_footer","Последний символ блока — соль-символ.","The last character of the block is a salt character."},
    {"size_hint_title","Расшифровка кодов объёма","Size Code Reference"},
    {"cancel","Отмена","Cancel"},
    {"create","Создать","Create"},
    {"save","Сохранить","Save"},
    {"media_type","Тип носителя","Media Type"},
    {"size","Объём","Size"},
    {"cipher","Шифр","Cipher"},
    {"tag_min","Тег (мин. 2 симв.)","Tag (min. 2 chars)"},
    {"salt","Соль","Salt"},
    {"generate","Сгенерировать","Generate"},
    {"label","Метка","Label"},
    {"block_err","Ошибка в блоке","Error in block"},
    {"block_len_err","Неверная длина блока","Invalid block length"},
    {"label_err","Метка: должно быть 5 блоков","Label: must be 5 blocks"},
    {"invalid_label","Неверная метка","Invalid label"},
    {"type","Тип","Type"},
    {"content_tag","Содержимое","Content"},
    {"dsalt","Соль","Salt"},
    {"close","Закрыть","Close"},
    {"key_mismatch","Выбранный ключ не подходит для этой базы.","The selected key does not match this database."},
    {"alias","Название (для себя)","Name (for yourself)"},
    {"alias_placeholder","необязательно","optional"},
    {"file_corrupted","Файл повреждён","File corrupted"},
    {"no_recipient","Не выбран GPG сертификат","No GPG certificate selected"},
};
static const int I18N_N = ARRAY_SIZE(I18N);
static char g_lang[8] = "ru";

static const char *i18n(const char *key) {
    for (int i = 0; i < I18N_N; i++)
        if (strcmp(I18N[i].key, key) == 0)
            return (g_lang[0] == 'e' && g_lang[1] == 'n') ? I18N[i].en : I18N[i].ru;
    return key;
}

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

static const char **get_sizes_for_type(const char *type_name) {
    for (int i = 0; i < TYPE_SIZE_MAP_N; i++)
        if (strcmp(TYPE_SIZE_MAP[i].type, type_name) == 0)
            return (const char **)TYPE_SIZE_MAP[i].sizes;
    return (const char **)SIZE_FOR_OTHER;
}

static char *generate_salt(int length) {
    char *buf = malloc(length + 1);
    if (!buf) return NULL;
    for (int i = 0; i < length; i++)
        buf[i] = ALPHABET[randombytes_uniform(ALPHABET_LEN)];
    buf[length] = '\0';
    return buf;
}

static char *generate_password(int length) {
    static const char pw_alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_+=";
    static const size_t pw_alpha_len = sizeof(pw_alpha) - 1;
    char *buf = sec_alloc(length + 1);
    for (int i = 0; i < length; i++)
        buf[i] = pw_alpha[randombytes_uniform(pw_alpha_len)];
    buf[length] = '\0';
    return buf;
}

static char calculate_block_salt(const uint8_t *noise_key, size_t key_len,
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

static void secure_shuffle(const char **arr, int n) {
    for (int i = n - 1; i > 0; i--) {
        uint32_t j = randombytes_uniform((uint32_t)(i + 1));
        const char *tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
}

typedef struct {
    char *label, *type, *size, *cipher, *content_tag, *dsalt, *tag_full, *dpass, *notes, *alias;
} db_entry_t;

static void db_entry_init(db_entry_t *e) { memset(e, 0, sizeof(*e)); }

static void db_entry_clear(db_entry_t *e) {
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

typedef struct {
    char *file_path, *recipient;
    uint8_t *salt; size_t salt_len;
    uint8_t *noise_key; size_t noise_key_len;
    char *schema_order[5];
    char lang[8];
    db_entry_t *entries;
    int entry_count, entry_cap;
    gpgme_ctx_t gpg_ctx;
} db_manager_t;

static void db_manager_init(db_manager_t *m) { memset(m, 0, sizeof(*m)); strcpy(m->lang, "ru"); }

static void db_manager_clear(db_manager_t *m) {
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

static char *db_gpg_decrypt(db_manager_t *m, const char *enc_data, size_t enc_len,
    char *err_msg, size_t err_msg_sz)
{
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

static char *db_gpg_encrypt(db_manager_t *m, const char *plaintext, size_t pt_len,
    char *err_msg, size_t err_msg_sz)
{
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

static char *hex_encode(const uint8_t *data, size_t len) {
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) snprintf(out + i*2, 3, "%02x", data[i]);
    out[len*2] = '\0';
    return out;
}

static uint8_t *hex_decode(const char *hex, size_t *out_len) {
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

static int db_load_json(db_manager_t *m, const char *json_str, char *err_msg, size_t err_msg_sz) {
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

static int db_save(db_manager_t *m, char *err_msg, size_t err_msg_sz) {
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

static db_manager_t *db_manager_open(const char *path, const char *forced_key,
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

static db_manager_t *db_manager_create(const char *path, const char *recipient,
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

static char *db_encode_label(db_manager_t *m, const char *type, const char *size,
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

typedef struct {
    char part_name[32], block[8], val[8], decoded[64];
    char schar, expected_schar;
} parsed_block_t;

static int db_parse_label(db_manager_t *m, const char *label,
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

static int db_add_entry(db_manager_t *m, const char *type, const char *size,
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

static int db_remove_entry(db_manager_t *m, const char *label, char *err_msg, size_t err_msg_sz) {
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

static int db_update_entry(db_manager_t *m, const char *label,
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

typedef struct { char *fingerprint; char *uid; } gpg_key_info_t;

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

static void gpg_free_key_list(gpg_key_info_t *list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) { free(list[i].fingerprint); free(list[i].uid); }
    free(list);
}

typedef struct {
    GtkWindow *window;
    GtkStack *stack;
    GtkWidget *welcome_title, *welcome_desc, *lbl_lang_welcome;
    GtkWidget *btn_open, *btn_create, *lang_combo_welcome;
    GtkWidget *setup_title, *lbl_setup_file, *lbl_setup_key, *lbl_setup_lang;
    GtkWidget *setup_file_label, *key_combo, *lang_combo, *setup_err;
    GtkWidget *btn_setup_back, *btn_setup_create;
    GtkWidget *unlock_title, *lbl_unlock_file, *lbl_unlock_key;
    GtkWidget *unlock_file_label, *unlock_key_combo, *unlock_err;
    GtkWidget *btn_unlock_back, *btn_unlock;
    GtkWidget *search;
    GtkListBox *listbox;
    GtkWidget *detail_box, *lbl_main, *grid, *notes_text;
    GtkWidget *btn_copy_label, *btn_copy_pass;
    GtkWidget *btn_lock, *btn_add, *btn_edit, *btn_del, *btn_sch;
    GtkWidget *notes_lbl;
    db_manager_t *db;
    char *current_file;
    char *expected_fp;
    guint clipboard_timer_id;
} AppData;

static AppData g_app;

static GdkPixbuf *icon_pb;

static char *find_icon_path(void) {
    char *p1 = g_build_filename(g_get_user_data_dir(), "diskpass", "disk-icon.png", NULL);
    if (g_file_test(p1, G_FILE_TEST_EXISTS)) return p1;
    g_free(p1);
    char *p2 = g_build_filename("/usr/local/share/diskpass", "disk-icon.png", NULL);
    if (g_file_test(p2, G_FILE_TEST_EXISTS)) return p2;
    g_free(p2);
    char *p3 = g_build_filename("/usr/share/diskpass", "disk-icon.png", NULL);
    if (g_file_test(p3, G_FILE_TEST_EXISTS)) return p3;
    g_free(p3);
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        char *dir = g_path_get_dirname(exe_path);
        char *p4 = g_build_filename(dir, "disk-icon.png", NULL);
        g_free(dir);
        if (g_file_test(p4, G_FILE_TEST_EXISTS)) return p4;
        g_free(p4);
    }
    if (g_file_test("disk-icon.png", G_FILE_TEST_EXISTS)) return g_strdup("disk-icon.png");
    return NULL;
}

static GdkPixbuf *load_icon(int size) {
    if (icon_pb) return gdk_pixbuf_scale_simple(icon_pb, size, size, GDK_INTERP_BILINEAR);
    return NULL;
}

static GtkWidget *make_icon_img(int size) {
    GdkPixbuf *pb = load_icon(size);
    if (pb) {
        GtkWidget *img = gtk_image_new_from_pixbuf(pb);
        g_object_unref(pb);
        return img;
    }
    return gtk_image_new_from_icon_name("system-lock-screen", GTK_ICON_SIZE_BUTTON);
}

static gboolean clipboard_clear_timer(gpointer user_data) {
    (void)user_data;
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    g_app.clipboard_timer_id = 0;
    return G_SOURCE_REMOVE;
}

static void clipboard_copy_secure(const char *text) {
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, text, -1);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    if (g_app.clipboard_timer_id) g_source_remove(g_app.clipboard_timer_id);
    g_app.clipboard_timer_id = g_timeout_add_seconds(30, clipboard_clear_timer, NULL);
}

static void on_gen_password(GtkButton *b, gpointer d) {
    (void)b;
    char *pw = generate_password(24);
    gtk_entry_set_text(GTK_ENTRY(d), pw);
    sec_strfree(pw);
}

static void on_back_to_welcome(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    gtk_stack_set_visible_child_name(g_app.stack, "welcome");
}

static void update_ui_text(void) {
    if (g_app.welcome_title) gtk_label_set_text(GTK_LABEL(g_app.welcome_title), "DiskPass");
    if (g_app.welcome_desc) gtk_label_set_text(GTK_LABEL(g_app.welcome_desc), i18n("app_desc"));
    if (g_app.btn_open) gtk_button_set_label(GTK_BUTTON(g_app.btn_open), i18n("open_db"));
    if (g_app.btn_create) gtk_button_set_label(GTK_BUTTON(g_app.btn_create), i18n("create_db"));
    if (g_app.lbl_lang_welcome) gtk_label_set_text(GTK_LABEL(g_app.lbl_lang_welcome), i18n("language"));
    if (g_app.setup_title) gtk_label_set_text(GTK_LABEL(g_app.setup_title), i18n("setup_title"));
    if (g_app.lbl_setup_file) gtk_label_set_text(GTK_LABEL(g_app.lbl_setup_file), i18n("db_file"));
    if (g_app.lbl_setup_key) gtk_label_set_text(GTK_LABEL(g_app.lbl_setup_key), i18n("pgp_key"));
    if (g_app.lbl_setup_lang) gtk_label_set_text(GTK_LABEL(g_app.lbl_setup_lang), i18n("language"));
    if (g_app.btn_setup_back) gtk_button_set_label(GTK_BUTTON(g_app.btn_setup_back), i18n("back"));
    if (g_app.btn_setup_create) gtk_button_set_label(GTK_BUTTON(g_app.btn_setup_create), i18n("create_btn"));
    if (g_app.unlock_title) gtk_label_set_text(GTK_LABEL(g_app.unlock_title), i18n("locked_title"));
    if (g_app.lbl_unlock_file) gtk_label_set_text(GTK_LABEL(g_app.lbl_unlock_file), i18n("file"));
    if (g_app.lbl_unlock_key) gtk_label_set_text(GTK_LABEL(g_app.lbl_unlock_key), i18n("pgp_key"));
    if (g_app.btn_unlock_back) gtk_button_set_label(GTK_BUTTON(g_app.btn_unlock_back), i18n("back"));
    if (g_app.btn_unlock) gtk_button_set_label(GTK_BUTTON(g_app.btn_unlock), i18n("unlock_btn"));
    if (g_app.btn_lock) gtk_widget_set_tooltip_text(g_app.btn_lock, i18n("lock_db"));
    if (g_app.btn_add) gtk_widget_set_tooltip_text(g_app.btn_add, i18n("add_entry"));
    if (g_app.btn_edit) gtk_widget_set_tooltip_text(g_app.btn_edit, i18n("edit_entry"));
    if (g_app.btn_del) gtk_widget_set_tooltip_text(g_app.btn_del, i18n("del_entry"));
    if (g_app.btn_sch) gtk_widget_set_tooltip_text(g_app.btn_sch, i18n("show_schema"));
    if (g_app.search) gtk_entry_set_placeholder_text(GTK_ENTRY(g_app.search), i18n("search"));
    if (g_app.lbl_main) gtk_label_set_text(GTK_LABEL(g_app.lbl_main), i18n("select_entry"));
    if (g_app.btn_copy_label) gtk_button_set_label(GTK_BUTTON(g_app.btn_copy_label), i18n("copy_label"));
    if (g_app.btn_copy_pass) gtk_button_set_label(GTK_BUTTON(g_app.btn_copy_pass), i18n("copy_pass"));
    if (g_app.notes_lbl) gtk_label_set_text(GTK_LABEL(g_app.notes_lbl), i18n("notes"));
}

static void refresh_entry_list(void) {
    if (!g_app.db) return;
    GList *children = gtk_container_get_children(GTK_CONTAINER(g_app.listbox));
    for (GList *l = children; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);
    for (int i = 0; i < g_app.db->entry_count; i++) {
        db_entry_t *e = &g_app.db->entries[i];
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
        gtk_widget_set_margin_top(box, 6); gtk_widget_set_margin_bottom(box, 6);
        gtk_widget_set_margin_start(box, 10); gtk_widget_set_margin_end(box, 10);
        char *tip = build_label_tooltip(g_app.db, e->label);
        gboolean has_alias = e->alias && e->alias[0];
        GtkWidget *lbl = gtk_label_new(has_alias ? e->alias : e->label);
        gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "row-title");
        gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_END);
        gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, TRUE, 0);
        if (has_alias) {
            GtkWidget *tag_lbl = gtk_label_new(e->label);
            gtk_style_context_add_class(gtk_widget_get_style_context(tag_lbl), "dim-label");
            gtk_label_set_xalign(GTK_LABEL(tag_lbl), 0.0);
            gtk_label_set_ellipsize(GTK_LABEL(tag_lbl), PANGO_ELLIPSIZE_END);
            gtk_widget_set_tooltip_text(tag_lbl, tip);
            gtk_box_pack_start(GTK_BOX(box), tag_lbl, FALSE, TRUE, 0);
        } else {
            gtk_widget_set_tooltip_text(lbl, tip);
        }
        g_free(tip);
        GtkWidget *sub = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *l1 = gtk_label_new(e->type ? e->type : "");
        GtkWidget *l2 = gtk_label_new(e->size ? e->size : "");
        GtkWidget *l3 = gtk_label_new(e->cipher ? e->cipher : "");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0); gtk_label_set_xalign(GTK_LABEL(l2), 0.0); gtk_label_set_xalign(GTK_LABEL(l3), 0.0);
        gtk_box_pack_start(GTK_BOX(sub), l1, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(sub), l2, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(sub), l3, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), sub, FALSE, FALSE, 0);
        gtk_container_add(GTK_CONTAINER(row), box);
        g_object_set_data(G_OBJECT(row), "entry_idx", GINT_TO_POINTER(i));
        gtk_list_box_insert(g_app.listbox, row, -1);
    }
    gtk_widget_show_all(GTK_WIDGET(g_app.listbox));
}

static void clear_details(void) {
    gtk_label_set_text(GTK_LABEL(g_app.lbl_main), i18n("select_entry"));
    GList *children = gtk_container_get_children(GTK_CONTAINER(g_app.grid));
    for (GList *l = children; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);
    gtk_label_set_text(GTK_LABEL(g_app.notes_text), "");
    gtk_widget_set_sensitive(g_app.btn_copy_label, FALSE);
    gtk_widget_set_sensitive(g_app.btn_copy_pass, FALSE);
}

static void show_entry_details(int idx) {
    clear_details();
    if (!g_app.db || idx < 0 || idx >= g_app.db->entry_count) return;
    db_entry_t *e = &g_app.db->entries[idx];
    gboolean has_alias = e->alias && e->alias[0];
    gtk_label_set_text(GTK_LABEL(g_app.lbl_main), has_alias ? e->alias : (e->label ? e->label : ""));
    char *tip = build_label_tooltip(g_app.db, e->label);
    gtk_widget_set_tooltip_text(g_app.lbl_main, tip);
    g_free(tip);
    gtk_widget_set_sensitive(g_app.btn_copy_label, TRUE);
    gtk_widget_set_sensitive(g_app.btn_copy_pass, e->dpass != NULL);
    parsed_block_t blocks[SCHEMA_COUNT];
    int block_count = 0;
    char err_buf[256] = "";
    if (db_parse_label(g_app.db, e->label, blocks, &block_count, err_buf, sizeof(err_buf)) != 0) {
        gtk_label_set_text(GTK_LABEL(g_app.lbl_main), err_buf);
        return;
    }
    GtkGrid *grid = GTK_GRID(g_app.grid);
    int row = 0;
    if (has_alias) {
        GtkWidget *l1 = gtk_label_new(i18n("label"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        GtkWidget *l2 = gtk_label_new(e->label);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(l2), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(l2, TRUE);
        char *tip2 = build_label_tooltip(g_app.db, e->label);
        gtk_widget_set_tooltip_text(l2, tip2);
        g_free(tip2);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }
    for (int i = 0; i < block_count; i++) {
        char header[64];
        snprintf(header, sizeof(header), "%s %d (%s)", i18n("block"), i+1, i18n(blocks[i].part_name));
        GtkWidget *l1 = gtk_label_new(header);
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        char val_text[128];
        if (strcmp(blocks[i].part_name, "type") == 0 || strcmp(blocks[i].part_name, "size") == 0 || strcmp(blocks[i].part_name, "cipher") == 0)
            snprintf(val_text, sizeof(val_text), "%s (%s)", blocks[i].val, blocks[i].decoded);
        else
            snprintf(val_text, sizeof(val_text), "%s", blocks[i].decoded);
        GtkWidget *l2 = gtk_label_new(val_text);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(l2), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(l2, TRUE);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }
    {
        GtkWidget *l1 = gtk_label_new(i18n("full_tag"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        GtkWidget *l2 = gtk_label_new(e->tag_full && e->tag_full[0] ? e->tag_full : "â");
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(l2), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(l2, TRUE);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }
    {
        GtkWidget *l1 = gtk_label_new(i18n("password"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        GtkWidget *l2 = gtk_label_new(e->dpass ? "ââââââââ" : "â");
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }
    gtk_label_set_text(GTK_LABEL(g_app.notes_text), e->notes && e->notes[0] ? e->notes : "â");
    gtk_widget_show_all(GTK_WIDGET(grid));
}

static void on_row_selected(GtkListBox *box, GtkListBoxRow *row, gpointer user_data) {
    (void)box; (void)user_data;
    if (!row) { clear_details(); return; }
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    show_entry_details(idx);
}

static gboolean filter_func(GtkListBoxRow *row, gpointer user_data) {
    (void)user_data;
    const char *query = gtk_entry_get_text(GTK_ENTRY(g_app.search));
    if (!query[0]) return TRUE;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (!g_app.db || idx < 0 || idx >= g_app.db->entry_count) return TRUE;
    db_entry_t *e = &g_app.db->entries[idx];
    char searchable[512];
    snprintf(searchable, sizeof(searchable), "%s %s %s %s %s %s %s",
        e->label?e->label:"", e->type?e->type:"", e->size?e->size:"",
        e->content_tag?e->content_tag:"", e->cipher?e->cipher:"", e->dsalt?e->dsalt:"",
        e->alias?e->alias:"");
    char lq[64]; strncpy(lq, query, sizeof(lq)-1); lq[sizeof(lq)-1]='\0';
    for (char *p = lq; *p; p++) *p = tolower((unsigned char)*p);
    char ls[512]; strncpy(ls, searchable, sizeof(ls)-1); ls[sizeof(ls)-1]='\0';
    for (char *p = ls; *p; p++) *p = tolower((unsigned char)*p);
    return strstr(ls, lq) != NULL;
}

static void on_search_changed(GtkSearchEntry *entry, gpointer user_data) {
    (void)entry; (void)user_data;
    gtk_list_box_invalidate_filter(g_app.listbox);
}

static void on_copy_label_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (g_app.db && idx >= 0 && idx < g_app.db->entry_count && g_app.db->entries[idx].label)
        clipboard_copy_secure(g_app.db->entries[idx].label);
}

static void on_copy_pass_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (g_app.db && idx >= 0 && idx < g_app.db->entry_count && g_app.db->entries[idx].dpass)
        clipboard_copy_secure(g_app.db->entries[idx].dpass);
}

static void on_lock_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    free(g_app.current_file); g_app.current_file = NULL;
    free(g_app.expected_fp); g_app.expected_fp = NULL;
    clear_details();
    refresh_entry_list();
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    if (g_app.clipboard_timer_id) {
        g_source_remove(g_app.clipboard_timer_id);
        g_app.clipboard_timer_id = 0;
    }
    gtk_stack_set_visible_child_name(g_app.stack, "welcome");
}

static void populate_gpg_keys(GtkComboBoxText *combo, int secret_only, GtkWidget *err_label) {
    gtk_combo_box_text_remove_all(combo);
    if (!g_app.db) return;
    int count = 0;
    gpg_key_info_t *keys = gpg_list_keys(g_app.db->gpg_ctx, secret_only, &count);
    if (!keys || count == 0) { gtk_label_set_text(GTK_LABEL(err_label), i18n("no_keys")); gpg_free_key_list(keys, count); return; }
    int active = 0;
    for (int i = 0; i < count; i++) {
        gtk_combo_box_text_append(combo, keys[i].fingerprint, keys[i].uid);
        if (g_app.expected_fp && strcmp(keys[i].fingerprint, g_app.expected_fp) == 0) active = i;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), active);
    gtk_label_set_text(GTK_LABEL(err_label), "");
    gpg_free_key_list(keys, count);
}

static void on_open_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    GtkWidget *dlg = gtk_file_chooser_dialog_new(i18n("open_db"), g_app.window, GTK_FILE_CHOOSER_ACTION_OPEN,
        i18n("cancel"), GTK_RESPONSE_CANCEL, i18n("open_db"), GTK_RESPONSE_OK, NULL);
    GtkFileFilter *f = gtk_file_filter_new();
    gtk_file_filter_set_name(f, "DiskPass (*.dpdb)");
    gtk_file_filter_add_pattern(f, "*.dpdb");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), f);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        free(g_app.current_file);
        gchar *chosen_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        g_app.current_file = xstrdup(chosen_path);
        g_free(chosen_path);
        char info[256];
        snprintf(info, sizeof(info), "%s %s", i18n("file"), g_app.current_file);
        gtk_label_set_text(GTK_LABEL(g_app.unlock_file_label), info);
        free(g_app.expected_fp); g_app.expected_fp = NULL;
        FILE *fp = fopen(g_app.current_file, "r");
        if (fp) {
            char line[256];
            if (fgets(line, sizeof(line), fp)) {
                char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
                char *cr = strchr(line, '\r'); if (cr) *cr = '\0';
                g_app.expected_fp = xstrdup(line);
            }
            fclose(fp);
        }
        if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); }
        g_app.db = calloc(1, sizeof(db_manager_t));
        db_manager_init(g_app.db);
        gpgme_error_t gerr = gpgme_new(&g_app.db->gpg_ctx);
        if (gerr != GPG_ERR_NO_ERROR) {
            db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL;
        } else {
            gpgme_set_protocol(g_app.db->gpg_ctx, GPGME_PROTOCOL_OpenPGP);
            populate_gpg_keys(GTK_COMBO_BOX_TEXT(g_app.unlock_key_combo), 1, g_app.unlock_err);
            gtk_stack_set_visible_child_name(g_app.stack, "unlock");
        }
    }
    gtk_widget_destroy(dlg);
}

static void on_create_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    GtkWidget *dlg = gtk_file_chooser_dialog_new(i18n("create_db"), g_app.window, GTK_FILE_CHOOSER_ACTION_SAVE,
        i18n("cancel"), GTK_RESPONSE_CANCEL, i18n("create_btn"), GTK_RESPONSE_OK, NULL);
    GtkFileFilter *f = gtk_file_filter_new();
    gtk_file_filter_set_name(f, "DiskPass (*.dpdb)");
    gtk_file_filter_add_pattern(f, "*.dpdb");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), f);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        free(g_app.current_file);
        gchar *chosen_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        g_app.current_file = xstrdup(chosen_path);
        g_free(chosen_path);
        if (!g_str_has_suffix(g_app.current_file, ".dpdb")) {
            char *tmp = g_strconcat(g_app.current_file, ".dpdb", NULL);
            free(g_app.current_file);
            g_app.current_file = xstrdup(tmp);
            g_free(tmp);
        }
        gtk_label_set_text(GTK_LABEL(g_app.setup_file_label), g_app.current_file);
        gtk_label_set_text(GTK_LABEL(g_app.setup_err), "");
        if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); }
        g_app.db = calloc(1, sizeof(db_manager_t));
        db_manager_init(g_app.db);
        gpgme_error_t gerr = gpgme_new(&g_app.db->gpg_ctx);
        if (gerr != GPG_ERR_NO_ERROR) {
            db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL;
        } else {
            gpgme_set_protocol(g_app.db->gpg_ctx, GPGME_PROTOCOL_OpenPGP);
            populate_gpg_keys(GTK_COMBO_BOX_TEXT(g_app.key_combo), 0, g_app.setup_err);
            gtk_stack_set_visible_child_name(g_app.stack, "setup");
        }
    }
    gtk_widget_destroy(dlg);
}

static void on_setup_create_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.current_file) return;
    gchar *recipient = (gchar*)gtk_combo_box_get_active_id(GTK_COMBO_BOX(g_app.key_combo));
    if (!recipient) { gtk_label_set_text(GTK_LABEL(g_app.setup_err), i18n("pgp_key")); return; }
    char err_buf[256] = "";
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    g_app.db = db_manager_create(g_app.current_file, recipient, g_lang, err_buf, sizeof(err_buf));
    if (!g_app.db) { gtk_label_set_text(GTK_LABEL(g_app.setup_err), err_buf); return; }
    update_ui_text();
    gtk_stack_set_visible_child_name(g_app.stack, "main");
    refresh_entry_list();
}

static void on_unlock_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.current_file) return;
    gchar *selected_fp = (gchar*)gtk_combo_box_get_active_id(GTK_COMBO_BOX(g_app.unlock_key_combo));
    if (!selected_fp) { gtk_label_set_text(GTK_LABEL(g_app.unlock_err), i18n("pgp_key")); return; }
    char err_buf[256] = "";
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    g_app.db = db_manager_open(g_app.current_file, selected_fp, err_buf, sizeof(err_buf));
    if (!g_app.db) { gtk_label_set_text(GTK_LABEL(g_app.unlock_err), err_buf); return; }
    update_ui_text();
    gtk_stack_set_visible_child_name(g_app.stack, "main");
    refresh_entry_list();
}

static void on_delete_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx < 0 || idx >= g_app.db->entry_count) return;
    char msg[256];
    snprintf(msg, sizeof(msg), "%s %s?", i18n("delete_msg"), g_app.db->entries[idx].label);
    GtkWidget *dlg = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "%s", msg);
    GtkWidget *yes_btn = gtk_dialog_get_widget_for_response(GTK_DIALOG(dlg), GTK_RESPONSE_YES);
    if (yes_btn) gtk_style_context_add_class(gtk_widget_get_style_context(yes_btn), "destructive-action");
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_YES) {
        char err_buf[256] = "";
        db_remove_entry(g_app.db, g_app.db->entries[idx].label, err_buf, sizeof(err_buf));
        refresh_entry_list();
        clear_details();
    }
    gtk_widget_destroy(dlg);
}

static void on_add_type_changed(GtkComboBoxText *combo, gpointer user_data) {
    GtkComboBoxText *vsz = GTK_COMBO_BOX_TEXT(user_data);
    gchar *type_val = gtk_combo_box_text_get_active_text(combo);
    gtk_combo_box_text_remove_all(vsz);
    if (type_val) {
        const char **sizes = get_sizes_for_type(type_val);
        for (int i = 0; sizes[i]; i++) gtk_combo_box_text_append_text(vsz, sizes[i]);
        g_free(type_val);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(vsz), 0);
}

static void on_toggle_password_visibility(GtkEntry *entry, GtkEntryIconPosition pos, GdkEvent *event, gpointer user_data) {
    (void)pos; (void)event; (void)user_data;
    gboolean visible = gtk_entry_get_visibility(entry);
    gtk_entry_set_visibility(entry, !visible);
    gtk_entry_set_icon_from_icon_name(entry, GTK_ENTRY_ICON_SECONDARY,
        !visible ? "eye-open-symbolic" : "eye-not-looking-symbolic");
}

static void on_add_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("add_entry"), g_app.window, GTK_DIALOG_MODAL,
        i18n("cancel"), GTK_RESPONSE_CANCEL, i18n("create"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 450, 500);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 12);
    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(grid, 12); gtk_grid_set_row_spacing(grid, 10);
    gtk_widget_set_hexpand(GTK_WIDGET(grid), TRUE);
    gtk_box_pack_start(GTK_BOX(content), GTK_WIDGET(grid), TRUE, TRUE, 0);
    int row = 0;
    gtk_grid_attach(grid, gtk_label_new(i18n("alias")), 0, row, 1, 1);
    GtkWidget *valias = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(valias), i18n("alias_placeholder"));
    gtk_widget_set_hexpand(valias, TRUE);
    gtk_grid_attach(grid, valias, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("media_type")), 0, row, 1, 1);
    GtkWidget *vtp = gtk_combo_box_text_new();
    for (int i = 0; i < TYPE_MAP_N; i++) gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(vtp), TYPE_MAP[i].name);
    gtk_combo_box_set_active(GTK_COMBO_BOX(vtp), 0); gtk_widget_set_hexpand(vtp, TRUE);
    gtk_grid_attach(grid, vtp, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("size")), 0, row, 1, 1);
    GtkWidget *vsz = gtk_combo_box_text_new(); gtk_widget_set_hexpand(vsz, TRUE);
    gtk_grid_attach(grid, vsz, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("cipher")), 0, row, 1, 1);
    GtkWidget *vci = gtk_combo_box_text_new();
    for (int i = 0; i < CIPHER_MAP_N; i++) gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(vci), CIPHER_MAP[i].name);
    gtk_combo_box_set_active(GTK_COMBO_BOX(vci), 0); gtk_widget_set_hexpand(vci, TRUE);
    gtk_grid_attach(grid, vci, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("password")), 0, row, 1, 1);
    GtkWidget *ph = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *vdp = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(vdp), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(vdp), '*');
    gtk_entry_set_icon_from_icon_name(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, "eye-not-looking-symbolic");
    gtk_entry_set_icon_activatable(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, TRUE);
    gtk_entry_set_icon_tooltip_text(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, "Toggle visibility");
    g_signal_connect(vdp, "icon-press", G_CALLBACK(on_toggle_password_visibility), NULL);
    gtk_widget_set_hexpand(vdp, TRUE);
    gtk_box_pack_start(GTK_BOX(ph), vdp, TRUE, TRUE, 0);
    GtkWidget *bg = gtk_button_new_from_icon_name("view-refresh", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(bg, i18n("generate"));
    gtk_box_pack_start(GTK_BOX(ph), bg, FALSE, FALSE, 0);
    gtk_grid_attach(grid, ph, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("tag_min")), 0, row, 1, 1);
    GtkWidget *vt = gtk_entry_new(); gtk_widget_set_hexpand(vt, TRUE);
    gtk_grid_attach(grid, vt, 1, row++, 1, 1);
    gtk_grid_attach(grid, gtk_label_new(i18n("salt")), 0, row, 1, 1);
    char *salt_str = generate_salt(2);
    GtkWidget *vd = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(vd), salt_str);
    gtk_editable_set_editable(GTK_EDITABLE(vd), FALSE); gtk_widget_set_hexpand(vd, TRUE);
    gtk_grid_attach(grid, vd, 1, row++, 1, 1);
    free(salt_str);
    gtk_grid_attach(grid, gtk_label_new(i18n("notes")), 0, row, 1, 1);
    GtkWidget *nt = gtk_text_view_new(); gtk_widget_set_size_request(nt, -1, 60);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sw), nt); gtk_widget_set_hexpand(sw, TRUE);
    gtk_grid_attach(grid, sw, 1, row++, 1, 1);
    const char **sizes = get_sizes_for_type(TYPE_MAP[0].name);
    for (int i = 0; sizes[i]; i++) gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(vsz), sizes[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(vsz), 0);
    g_signal_connect(vtp, "changed", G_CALLBACK(on_add_type_changed), vsz);
    g_signal_connect(bg, "clicked", G_CALLBACK(on_gen_password), vdp);
    gtk_widget_show_all(dlg);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *tag_str = gtk_entry_get_text(GTK_ENTRY(vt));
        if (strlen(tag_str) < 2) { gtk_widget_destroy(dlg); return; }
        char tag_val[3] = { toupper((unsigned char)tag_str[0]), toupper((unsigned char)tag_str[1]), '\0' };
        gchar *type_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(vtp));
        gchar *size_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(vsz));
        gchar *cipher_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(vci));
        const char *dpass_val = gtk_entry_get_text(GTK_ENTRY(vdp));
        const char *dsalt_val = gtk_entry_get_text(GTK_ENTRY(vd));
        GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(nt));
        GtkTextIter start, end;
        gtk_text_buffer_get_start_iter(buf, &start); gtk_text_buffer_get_end_iter(buf, &end);
        char *notes_val = gtk_text_buffer_get_text(buf, &start, &end, FALSE);
        const char *actual_dpass = (strcmp(cipher_val, "NONE") == 0) ? "" : dpass_val;
        const char *alias_val = gtk_entry_get_text(GTK_ENTRY(valias));
        char err_buf[256] = "";
        char *label = db_encode_label(g_app.db, type_val, size_val, tag_val, cipher_val, dsalt_val);
        if (db_add_entry(g_app.db, type_val, size_val, cipher_val, tag_val, dsalt_val, tag_str, actual_dpass, notes_val, alias_val, err_buf, sizeof(err_buf)) == 0) {
            clipboard_copy_secure(label);
            refresh_entry_list();
        }
        free(label);
        g_free(notes_val);
        g_free(type_val);
        g_free(size_val);
        g_free(cipher_val);
    }
    gtk_widget_destroy(dlg);
}

static void on_edit_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx < 0 || idx >= g_app.db->entry_count) return;
    db_entry_t *e = &g_app.db->entries[idx];
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("edit_entry"), g_app.window, GTK_DIALOG_MODAL,
        i18n("cancel"), GTK_RESPONSE_CANCEL, i18n("save"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 450, 350);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 12);
    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(grid, 12); gtk_grid_set_row_spacing(grid, 10);
    gtk_widget_set_hexpand(GTK_WIDGET(grid), TRUE);
    gtk_box_pack_start(GTK_BOX(content), GTK_WIDGET(grid), TRUE, TRUE, 0);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new(i18n("alias")), 0, 0, 1, 1);
    GtkWidget *valias = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(valias), i18n("alias_placeholder"));
    if (e->alias) gtk_entry_set_text(GTK_ENTRY(valias), e->alias);
    gtk_widget_set_hexpand(valias, TRUE);
    gtk_grid_attach(GTK_GRID(grid), valias, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new(i18n("label")), 0, 1, 1, 1);
    GtkWidget *lbl = gtk_label_new(e->label);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(lbl, TRUE);
    gtk_grid_attach(GTK_GRID(grid), lbl, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new(i18n("password")), 0, 2, 1, 1);
    GtkWidget *ph = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *vdp = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(vdp), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(vdp), '*');
    gtk_entry_set_icon_from_icon_name(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, "eye-not-looking-symbolic");
    gtk_entry_set_icon_activatable(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, TRUE);
    gtk_entry_set_icon_tooltip_text(GTK_ENTRY(vdp), GTK_ENTRY_ICON_SECONDARY, "Toggle visibility");
    g_signal_connect(vdp, "icon-press", G_CALLBACK(on_toggle_password_visibility), NULL);
    if (e->dpass) gtk_entry_set_text(GTK_ENTRY(vdp), e->dpass);
    gtk_widget_set_hexpand(vdp, TRUE);
    gtk_box_pack_start(GTK_BOX(ph), vdp, TRUE, TRUE, 0);
    GtkWidget *bg = gtk_button_new_from_icon_name("view-refresh", GTK_ICON_SIZE_BUTTON);
    gtk_box_pack_start(GTK_BOX(ph), bg, FALSE, FALSE, 0);
    gtk_grid_attach(GTK_GRID(grid), ph, 1, 2, 1, 1);
    g_signal_connect(bg, "clicked", G_CALLBACK(on_gen_password), vdp);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new(i18n("notes")), 0, 3, 1, 1);
    GtkWidget *nt = gtk_text_view_new(); gtk_widget_set_size_request(nt, -1, 60);
    if (e->notes) gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(nt)), e->notes, -1);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sw), nt); gtk_widget_set_hexpand(sw, TRUE);
    gtk_grid_attach(GTK_GRID(grid), sw, 1, 3, 1, 1);
    if (e->cipher && strcmp(e->cipher, "NONE") == 0) gtk_widget_hide(ph);
    gtk_widget_show_all(dlg);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *new_dpass = gtk_entry_get_text(GTK_ENTRY(vdp));
        const char *new_alias = gtk_entry_get_text(GTK_ENTRY(valias));
        GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(nt));
        GtkTextIter start, end;
        gtk_text_buffer_get_start_iter(buf, &start); gtk_text_buffer_get_end_iter(buf, &end);
        char *new_notes = gtk_text_buffer_get_text(buf, &start, &end, FALSE);
        char err_buf[256] = "";
        db_update_entry(g_app.db, e->label, new_dpass, new_notes, new_alias, err_buf, sizeof(err_buf));
        g_free(new_notes);
        refresh_entry_list();
        GtkListBoxRow *new_row = gtk_list_box_get_row_at_index(g_app.listbox, idx);
        if (new_row) gtk_list_box_select_row(g_app.listbox, new_row);
        show_entry_details(idx);
    }
    gtk_widget_destroy(dlg);
}

static void on_schema_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("schema_title"), g_app.window, GTK_DIALOG_MODAL, i18n("close"), GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 450, 430);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 15);
    GtkWidget *vis_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_widget_set_halign(vis_box, GTK_ALIGN_CENTER);
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        const char *p = g_app.db->schema_order[i];
        int vl = 0;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (strcmp(SCHEMA_PARTS[j], p) == 0) { vl = PART_LENGTHS[j]; break; }
        GtkWidget *block_wrap = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
        GtkWidget *str_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        char val_str[8]; memset(val_str, 'X', vl); val_str[vl] = '\0';
        GtkWidget *val_lbl = gtk_label_new(val_str);
        gtk_style_context_add_class(gtk_widget_get_style_context(val_lbl), "schema-val");
        gtk_box_pack_start(GTK_BOX(str_box), val_lbl, FALSE, FALSE, 0);
        GtkWidget *salt_lbl = gtk_label_new("Y");
        gtk_style_context_add_class(gtk_widget_get_style_context(salt_lbl), "schema-salt");
        gtk_box_pack_start(GTK_BOX(str_box), salt_lbl, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(block_wrap), str_box, FALSE, FALSE, 0);
        char desc[64]; snprintf(desc, sizeof(desc), "%s\n(%d+1)", i18n(p), vl);
        GtkWidget *name_lbl = gtk_label_new(desc);
        gtk_style_context_add_class(gtk_widget_get_style_context(name_lbl), "dim-label");
        gtk_box_pack_start(GTK_BOX(block_wrap), name_lbl, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(vis_box), block_wrap, FALSE, FALSE, 0);
        if (i < SCHEMA_COUNT - 1) {
            GtkWidget *dash = gtk_label_new("-");
            gtk_style_context_add_class(gtk_widget_get_style_context(dash), "schema-dash");
            gtk_box_pack_start(GTK_BOX(vis_box), dash, FALSE, FALSE, 0);
        }
    }
    gtk_box_pack_start(GTK_BOX(content), vis_box, FALSE, FALSE, 0);
    GtkGrid *bgrid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(bgrid, 12); gtk_grid_set_row_spacing(bgrid, 8);
    gtk_widget_set_margin_start(GTK_WIDGET(bgrid), 20); gtk_widget_set_margin_top(GTK_WIDGET(bgrid), 10);
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        const char *p = g_app.db->schema_order[i];
        int vl = 0;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (strcmp(SCHEMA_PARTS[j], p) == 0) { vl = PART_LENGTHS[j]; break; }
        char btxt[32]; snprintf(btxt, sizeof(btxt), "%s %d", i18n("block"), i+1);
        GtkWidget *bl = gtk_label_new(btxt);
        gtk_style_context_add_class(gtk_widget_get_style_context(bl), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(bl), 0.0);
        gtk_grid_attach(bgrid, bl, 0, i, 1, 1);
        char dtxt[64]; snprintf(dtxt, sizeof(dtxt), "-> %s (%s: %d, %s: 1)", i18n(p), i18n("val"), vl, i18n("chk"));
        GtkWidget *dl = gtk_label_new(dtxt);
        gtk_label_set_xalign(GTK_LABEL(dl), 0.0);
        gtk_grid_attach(bgrid, dl, 1, i, 1, 1);
    }
    gtk_box_pack_start(GTK_BOX(content), GTK_WIDGET(bgrid), FALSE, FALSE, 0);
    GtkWidget *footer = gtk_label_new(i18n("schema_footer"));
    gtk_style_context_add_class(gtk_widget_get_style_context(footer), "dim-label");
    gtk_label_set_xalign(GTK_LABEL(footer), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(footer), TRUE);
    gtk_widget_set_margin_top(footer, 10);
    gtk_box_pack_start(GTK_BOX(content), footer, FALSE, FALSE, 0);
    GtkWidget *size_hint_exp = gtk_expander_new(i18n("size_hint_title"));
    gtk_widget_set_margin_top(size_hint_exp, 8);
    GtkWidget *hint_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(hint_scroll, -1, 160);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(hint_scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    GtkGrid *hgrid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(hgrid, 14);
    gtk_grid_set_row_spacing(hgrid, 3);
    gtk_widget_set_margin_start(GTK_WIDGET(hgrid), 8);
    gtk_widget_set_margin_top(GTK_WIDGET(hgrid), 6);
    gtk_widget_set_margin_bottom(GTK_WIDGET(hgrid), 6);
    for (int i = 0; i < SIZE_MAP_N; i++) {
        GtkWidget *code_lbl = gtk_label_new(SIZE_MAP[i].code);
        gtk_style_context_add_class(gtk_widget_get_style_context(code_lbl), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(code_lbl), 0.0);
        gtk_grid_attach(hgrid, code_lbl, 0, i, 1, 1);
        GtkWidget *name_lbl2 = gtk_label_new(SIZE_MAP[i].name);
        gtk_label_set_xalign(GTK_LABEL(name_lbl2), 0.0);
        gtk_grid_attach(hgrid, name_lbl2, 1, i, 1, 1);
    }
    gtk_container_add(GTK_CONTAINER(hint_scroll), GTK_WIDGET(hgrid));
    gtk_container_add(GTK_CONTAINER(size_hint_exp), hint_scroll);
    gtk_box_pack_start(GTK_BOX(content), size_hint_exp, FALSE, FALSE, 0);
    gtk_widget_show_all(dlg);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static void on_lang_changed_welcome(GtkComboBoxText *combo, gpointer user_data) {
    (void)user_data;
    gchar *id = (gchar*)gtk_combo_box_get_active_id(GTK_COMBO_BOX(combo));
    if (id && strcmp(id, g_lang) != 0) {
        snprintf(g_lang, sizeof(g_lang), "%s", id);
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(g_app.lang_combo), g_lang);
        update_ui_text();
    }
}

static void build_welcome(void) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(box, 40); gtk_widget_set_margin_end(box, 40);
    GtkWidget *img = make_icon_img(72);
    gtk_box_pack_start(GTK_BOX(box), img, FALSE, FALSE, 0);
    g_app.welcome_title = gtk_label_new("DiskPass");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.welcome_title), "welcome-title");
    gtk_box_pack_start(GTK_BOX(box), g_app.welcome_title, FALSE, FALSE, 0);
    g_app.welcome_desc = gtk_label_new(i18n("app_desc"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.welcome_desc), "dim-label");
    gtk_box_pack_start(GTK_BOX(box), g_app.welcome_desc, FALSE, FALSE, 0);
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(btn_box, 18);
    g_app.btn_open = gtk_button_new_with_label(i18n("open_db"));
    g_signal_connect(g_app.btn_open, "clicked", G_CALLBACK(on_open_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_open, FALSE, FALSE, 0);
    g_app.btn_create = gtk_button_new_with_label(i18n("create_db"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_create), "suggested-action");
    g_signal_connect(g_app.btn_create, "clicked", G_CALLBACK(on_create_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_create, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), btn_box, FALSE, FALSE, 0);
    GtkWidget *lang_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_margin_top(lang_box, 20);
    g_app.lbl_lang_welcome = gtk_label_new(i18n("language"));
    gtk_box_pack_start(GTK_BOX(lang_box), g_app.lbl_lang_welcome, FALSE, FALSE, 0);
    g_app.lang_combo_welcome = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(g_app.lang_combo_welcome), "ru", "Русский");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(g_app.lang_combo_welcome), "en", "English");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(g_app.lang_combo_welcome), g_lang);
    g_signal_connect(g_app.lang_combo_welcome, "changed", G_CALLBACK(on_lang_changed_welcome), NULL);
    gtk_box_pack_start(GTK_BOX(lang_box), g_app.lang_combo_welcome, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), lang_box, FALSE, FALSE, 0);
    gtk_stack_add_named(g_app.stack, box, "welcome");
}

static void build_setup(void) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER); gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(box, 40); gtk_widget_set_margin_end(box, 40);
    g_app.setup_title = gtk_label_new(i18n("setup_title"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.setup_title), "welcome-title");
    gtk_box_pack_start(GTK_BOX(box), g_app.setup_title, FALSE, FALSE, 0);
    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(grid, 10); gtk_grid_set_row_spacing(grid, 10);
    gtk_widget_set_margin_top(GTK_WIDGET(grid), 15);
    g_app.lbl_setup_file = gtk_label_new(i18n("db_file"));
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_setup_file), 1.0);
    gtk_grid_attach(grid, g_app.lbl_setup_file, 0, 0, 1, 1);
    g_app.setup_file_label = gtk_label_new(i18n("not_selected"));
    gtk_label_set_xalign(GTK_LABEL(g_app.setup_file_label), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(g_app.setup_file_label), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(g_app.setup_file_label, TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.setup_file_label), "dim-label");
    gtk_grid_attach(grid, g_app.setup_file_label, 1, 0, 1, 1);
    g_app.lbl_setup_key = gtk_label_new(i18n("pgp_key"));
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_setup_key), 1.0);
    gtk_grid_attach(grid, g_app.lbl_setup_key, 0, 1, 1, 1);
    g_app.key_combo = gtk_combo_box_text_new();
    gtk_widget_set_size_request(g_app.key_combo, 250, -1); gtk_widget_set_hexpand(g_app.key_combo, TRUE);
    gtk_grid_attach(grid, g_app.key_combo, 1, 1, 1, 1);
    g_app.lbl_setup_lang = gtk_label_new(i18n("language"));
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_setup_lang), 1.0);
    gtk_grid_attach(grid, g_app.lbl_setup_lang, 0, 2, 1, 1);
    g_app.lang_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(g_app.lang_combo), "ru", "Русский");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(g_app.lang_combo), "en", "English");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(g_app.lang_combo), g_lang);
    gtk_grid_attach(grid, g_app.lang_combo, 1, 2, 1, 1);
    gtk_box_pack_start(GTK_BOX(box), GTK_WIDGET(grid), FALSE, TRUE, 0);
    g_app.setup_err = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.setup_err), "error");
    gtk_box_pack_start(GTK_BOX(box), g_app.setup_err, FALSE, FALSE, 0);
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_top(btn_box, 8);
    g_app.btn_setup_back = gtk_button_new_with_label(i18n("back"));
    g_signal_connect(g_app.btn_setup_back, "clicked", G_CALLBACK(on_back_to_welcome), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_setup_back, FALSE, FALSE, 0);
    g_app.btn_setup_create = gtk_button_new_with_label(i18n("create_btn"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_setup_create), "suggested-action");
    g_signal_connect(g_app.btn_setup_create, "clicked", G_CALLBACK(on_setup_create_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_setup_create, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), btn_box, FALSE, FALSE, 0);
    gtk_stack_add_named(g_app.stack, box, "setup");
}

static void build_unlock(void) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER); gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(box, 40); gtk_widget_set_margin_end(box, 40);
    g_app.unlock_title = gtk_label_new(i18n("locked_title"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.unlock_title), "welcome-title");
    gtk_box_pack_start(GTK_BOX(box), g_app.unlock_title, FALSE, FALSE, 0);
    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(grid, 10); gtk_grid_set_row_spacing(grid, 10);
    gtk_widget_set_margin_top(GTK_WIDGET(grid), 15);
    g_app.lbl_unlock_file = gtk_label_new(i18n("file"));
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_unlock_file), 1.0);
    gtk_grid_attach(grid, g_app.lbl_unlock_file, 0, 0, 1, 1);
    g_app.unlock_file_label = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(g_app.unlock_file_label), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(g_app.unlock_file_label), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(g_app.unlock_file_label, TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.unlock_file_label), "dim-label");
    gtk_grid_attach(grid, g_app.unlock_file_label, 1, 0, 1, 1);
    g_app.lbl_unlock_key = gtk_label_new(i18n("pgp_key"));
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_unlock_key), 1.0);
    gtk_grid_attach(grid, g_app.lbl_unlock_key, 0, 1, 1, 1);
    g_app.unlock_key_combo = gtk_combo_box_text_new();
    gtk_widget_set_size_request(g_app.unlock_key_combo, 250, -1); gtk_widget_set_hexpand(g_app.unlock_key_combo, TRUE);
    gtk_grid_attach(grid, g_app.unlock_key_combo, 1, 1, 1, 1);
    gtk_box_pack_start(GTK_BOX(box), GTK_WIDGET(grid), FALSE, TRUE, 0);
    g_app.unlock_err = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.unlock_err), "error");
    gtk_box_pack_start(GTK_BOX(box), g_app.unlock_err, FALSE, FALSE, 0);
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_top(btn_box, 8);
    g_app.btn_unlock_back = gtk_button_new_with_label(i18n("back"));
    g_signal_connect(g_app.btn_unlock_back, "clicked", G_CALLBACK(on_back_to_welcome), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_unlock_back, FALSE, FALSE, 0);
    g_app.btn_unlock = gtk_button_new_with_label(i18n("unlock_btn"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_unlock), "suggested-action");
    GtkWidget *unlock_img = make_icon_img(24);
    gtk_button_set_image(GTK_BUTTON(g_app.btn_unlock), unlock_img);
    gtk_button_set_always_show_image(GTK_BUTTON(g_app.btn_unlock), TRUE);
    g_signal_connect(g_app.btn_unlock, "clicked", G_CALLBACK(on_unlock_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_unlock, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), btn_box, FALSE, FALSE, 0);
    gtk_stack_add_named(g_app.stack, box, "unlock");
}

static void build_main(void) {
    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(toolbar), "main-toolbar");
    gtk_widget_set_margin_top(toolbar, 6); gtk_widget_set_margin_bottom(toolbar, 6);
    gtk_widget_set_margin_start(toolbar, 6); gtk_widget_set_margin_end(toolbar, 6);
    g_app.btn_lock = gtk_button_new_from_icon_name("changes-prevent-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(g_app.btn_lock, i18n("lock_db"));
    g_signal_connect(g_app.btn_lock, "clicked", G_CALLBACK(on_lock_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_lock, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(toolbar), gtk_label_new(""), TRUE, TRUE, 0);
    g_app.btn_sch = gtk_button_new_from_icon_name("dialog-information-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(g_app.btn_sch, i18n("show_schema"));
    g_signal_connect(g_app.btn_sch, "clicked", G_CALLBACK(on_schema_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(toolbar), g_app.btn_sch, FALSE, FALSE, 0);
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_box), "linked");
    g_app.btn_add = gtk_button_new_from_icon_name("list-add-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_add), "suggested-action");
    gtk_widget_set_tooltip_text(g_app.btn_add, i18n("add_entry"));
    g_signal_connect(g_app.btn_add, "clicked", G_CALLBACK(on_add_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_add, FALSE, FALSE, 0);
    g_app.btn_edit = gtk_button_new_from_icon_name("document-edit-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(g_app.btn_edit, i18n("edit_entry"));
    g_signal_connect(g_app.btn_edit, "clicked", G_CALLBACK(on_edit_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_edit, FALSE, FALSE, 0);
    g_app.btn_del = gtk_button_new_from_icon_name("edit-delete-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_del), "destructive-action");
    gtk_widget_set_tooltip_text(g_app.btn_del, i18n("del_entry"));
    g_signal_connect(g_app.btn_del, "clicked", G_CALLBACK(on_delete_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_box), g_app.btn_del, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(toolbar), btn_box, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), toolbar, FALSE, FALSE, 0);
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(paned), 300);
    gtk_paned_set_wide_handle(GTK_PANED(paned), TRUE);
    GtkWidget *left_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *search_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(search_box), "sidebar");
    gtk_widget_set_margin_top(search_box, 6); gtk_widget_set_margin_bottom(search_box, 6);
    gtk_widget_set_margin_start(search_box, 6); gtk_widget_set_margin_end(search_box, 6);
    g_app.search = gtk_search_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(g_app.search), i18n("search"));
    g_signal_connect(g_app.search, "search-changed", G_CALLBACK(on_search_changed), NULL);
    gtk_box_pack_start(GTK_BOX(search_box), g_app.search, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(left_box), search_box, FALSE, FALSE, 0);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(sw, TRUE);
    g_app.listbox = GTK_LIST_BOX(gtk_list_box_new());
    gtk_list_box_set_selection_mode(g_app.listbox, GTK_SELECTION_SINGLE);
    gtk_style_context_add_class(gtk_widget_get_style_context(GTK_WIDGET(g_app.listbox)), "sidebar");
    g_signal_connect(g_app.listbox, "row-selected", G_CALLBACK(on_row_selected), NULL);
    gtk_list_box_set_filter_func(g_app.listbox, filter_func, NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sw), GTK_WIDGET(g_app.listbox));
    gtk_box_pack_start(GTK_BOX(left_box), sw, TRUE, TRUE, 0);
    gtk_paned_pack1(GTK_PANED(paned), left_box, TRUE, FALSE);
    GtkWidget *detail_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(detail_scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(detail_scroll, TRUE);
    g_app.detail_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    gtk_widget_set_margin_top(g_app.detail_box, 18); gtk_widget_set_margin_bottom(g_app.detail_box, 18);
    gtk_widget_set_margin_start(g_app.detail_box, 24); gtk_widget_set_margin_end(g_app.detail_box, 24);
    gtk_widget_set_valign(g_app.detail_box, GTK_ALIGN_START);
    GtkWidget *top_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    g_app.lbl_main = gtk_label_new(i18n("select_entry"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.lbl_main), "detail-title");
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_main), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(g_app.lbl_main), PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_set_hexpand(g_app.lbl_main, TRUE);
    gtk_box_pack_start(GTK_BOX(top_box), g_app.lbl_main, TRUE, TRUE, 0);
    g_app.btn_copy_label = gtk_button_new_with_label(i18n("copy_label"));
    gtk_button_set_image(GTK_BUTTON(g_app.btn_copy_label), gtk_image_new_from_icon_name("edit-copy-symbolic", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(g_app.btn_copy_label), TRUE);
    gtk_widget_set_sensitive(g_app.btn_copy_label, FALSE);
    g_signal_connect(g_app.btn_copy_label, "clicked", G_CALLBACK(on_copy_label_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(top_box), g_app.btn_copy_label, FALSE, FALSE, 0);
    g_app.btn_copy_pass = gtk_button_new_with_label(i18n("copy_pass"));
    gtk_button_set_image(GTK_BUTTON(g_app.btn_copy_pass), gtk_image_new_from_icon_name("dialog-password-symbolic", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(g_app.btn_copy_pass), TRUE);
    gtk_widget_set_sensitive(g_app.btn_copy_pass, FALSE);
    g_signal_connect(g_app.btn_copy_pass, "clicked", G_CALLBACK(on_copy_pass_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(top_box), g_app.btn_copy_pass, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), top_box, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);
    g_app.grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(g_app.grid), 18);
    gtk_grid_set_row_spacing(GTK_GRID(g_app.grid), 10);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.grid, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);
    g_app.notes_lbl = gtk_label_new(i18n("notes"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.notes_lbl), "dim-label");
    gtk_label_set_xalign(GTK_LABEL(g_app.notes_lbl), 0.0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.notes_lbl, FALSE, FALSE, 0);
    g_app.notes_text = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(g_app.notes_text), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(g_app.notes_text), TRUE);
    g_object_set(g_app.notes_text, "hexpand", TRUE, "max-width-chars", 40, NULL);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.notes_text, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(detail_scroll), g_app.detail_box);
    gtk_paned_pack2(GTK_PANED(paned), detail_scroll, TRUE, FALSE);
    gtk_box_pack_start(GTK_BOX(main_box), paned, TRUE, TRUE, 0);
    gtk_stack_add_named(g_app.stack, main_box, "main");
}

static void load_css(void) {
    static const char css[] =
        ".welcome-title { font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }"
        ".detail-title { font-size: 18px; font-weight: 600; letter-spacing: 0.5px; }"
        ".row-title { font-size: 13px; font-weight: 600; }"
        ".dim-label { color: alpha(@theme_fg_color, 0.5); font-weight: 400; }"
        ".error { color: @error_color; font-weight: 600; margin-top: 4px; }"
        ".sidebar { background-color: @theme_base_color; border-right: 1px solid alpha(@borders, 0.5); }"
        ".main-toolbar { background-color: @theme_bg_color; border-bottom: 1px solid alpha(@borders, 0.5); }"
        "row { border-bottom: 1px solid alpha(@borders, 0.2); padding: 2px 0; }"
        "row:hover { background-color: alpha(@theme_fg_color, 0.05); }"
        "row:selected { background-color: @theme_selected_bg_color; color: @theme_selected_fg_color; }"
        "row:selected .dim-label { color: alpha(@theme_selected_fg_color, 0.7); }"
        "button { border-radius: 5px; }"
        ".linked button { border-radius: 0; }"
        ".linked button:first-child { border-radius: 5px 0 0 5px; }"
        ".linked button:last-child { border-radius: 0 5px 5px 0; }"
        "entry, combobox entry { border-radius: 5px; }"
        ".schema-val { background-color: #aee; color: #333; font-family: monospace;"
        " font-weight: bold; font-size: 18px; padding: 8px 4px;"
        " border-radius: 4px 0 0 4px; border: 1px solid #3aa; }"
        ".schema-salt { background-color: #fea; color: #333; font-family: monospace;"
        " font-weight: bold; font-size: 18px; padding: 8px 4px;"
        " border-radius: 0 4px 4px 0; border: 1px solid #c93; }"
        ".schema-dash { font-family: monospace; font-weight: bold; font-size: 18px;"
        " padding: 8px 0; color: #999; }";
    GtkCssProvider *provider = gtk_css_provider_new();
    GError *error = NULL;
    gtk_css_provider_load_from_data(provider, css, -1, &error);
    if (error) g_error_free(error);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

static void graceful_shutdown(int sig) {
    (void)sig;
    if (g_app.clipboard_timer_id) g_source_remove(g_app.clipboard_timer_id);
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    free(g_app.current_file); g_app.current_file = NULL;
    free(g_app.expected_fp); g_app.expected_fp = NULL;
    gtk_main_quit();
}

static void setup_accelerators(GtkWidget *win) {
    GtkAccelGroup *accel = gtk_accel_group_new();
    gtk_window_add_accel_group(GTK_WINDOW(win), accel);
    gtk_widget_add_accelerator(g_app.btn_add, "clicked", accel,
        GDK_KEY_n, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_del, "clicked", accel,
        GDK_KEY_Delete, 0, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_lock, "clicked", accel,
        GDK_KEY_l, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_sch, "clicked", accel,
        GDK_KEY_s, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_copy_label, "clicked", accel,
        GDK_KEY_c, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_copy_pass, "clicked", accel,
        GDK_KEY_p, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.search, "grab-focus", accel,
        GDK_KEY_f, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
}

int main(int argc, char **argv) {
    umask(0077);
    setlocale(LC_ALL, "");
    if (!g_get_charset(NULL)) {
        g_setenv("LANG", "C.UTF-8", TRUE);
        g_setenv("LC_ALL", "C.UTF-8", TRUE);
    }
    if (sodium_init() < 0) { fprintf(stderr, "FATAL: libsodium init failed\n"); return 1; }
    if (!gpgme_check_version("1.14.0")) { fprintf(stderr, "FATAL: GPGME >= 1.14.0 required\n"); return 1; }
    gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1) {
        fprintf(stderr, "WARNING: mlockall failed: %s\n", strerror(errno));
    }
    signal(SIGINT, graceful_shutdown);
    signal(SIGTERM, graceful_shutdown);
    gtk_init(&argc, &argv);
    load_css();
    memset(&g_app, 0, sizeof(g_app));
    char *icon_path = find_icon_path();
    if (icon_path) {
        icon_pb = gdk_pixbuf_new_from_file_at_size(icon_path, 256, 256, NULL);
        g_free(icon_path);
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "DiskPass");
    gtk_window_set_default_size(GTK_WINDOW(win), 850, 550);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    if (icon_pb) gtk_window_set_icon(GTK_WINDOW(win), icon_pb);
    g_app.window = GTK_WINDOW(win);
    g_app.stack = GTK_STACK(gtk_stack_new());
    gtk_stack_set_transition_type(g_app.stack, GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_container_add(GTK_CONTAINER(win), GTK_WIDGET(g_app.stack));
    build_welcome();
    build_setup();
    build_unlock();
    build_main();
    setup_accelerators(win);
    gtk_stack_set_visible_child_name(g_app.stack, "welcome");
    g_signal_connect(win, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_widget_show_all(win);
    gtk_main();
    if (g_app.clipboard_timer_id) g_source_remove(g_app.clipboard_timer_id);
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); }
    free(g_app.current_file);
    free(g_app.expected_fp);
    if (icon_pb) g_object_unref(icon_pb);
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    return 0;
}
