#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <locale.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <glib/gstdio.h>
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

#define DB_VERSION 3
#define AUTOLOCK_SECONDS 300

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

static char *format_bytes(long long bytes) {
    if (bytes < 0) return g_strdup("—");
    if (bytes < 1024) return g_strdup_printf("%lld B", bytes);
    const char *units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double v = (double)bytes;
    int u = 0;
    while (v >= 1024.0 && u < 5) { v /= 1024.0; u++; }
    return g_strdup_printf("%.1f %s", v, units[u]);
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
    {"snapshot_btn","Слепок папки диска","Folder snapshot"},
    {"snapshot_title","Выберите корень диска (точку монтирования)","Choose disk root (mount point)"},
    {"scan","Сканировать","Scan"},
    {"scanning","Сканирование...","Scanning..."},
    {"indexed_files","Проиндексировано файлов","Indexed files"},
    {"find_btn","Глобальный поиск файлов","Global file search"},
    {"find_title","Поиск по всем дискам","Search across all disks"},
    {"find_hint","Имя файла или фрагмент пути...","File name or path fragment..."},
    {"matches","совпадений","matches"},
    {"files_on_disk","Файлы на диске","Files on disk"},
    {"no_results","Ничего не найдено","No results"},
    {"files_found","файлов","files"},
    {"disks_found","дисков","disks"},
    {"copy_path","Копировать путь","Copy path"},
    {"copy_name","Копировать имя","Copy name"},
    {"empty_index","Нет дисков с индексом. Сделайте слепок диска.","No disks with file index. Create a disk snapshot."},
    {"disks_with_index","дисков с индексом","disks with index"},
    {"no_index_yet","Индекс не создан","No index yet"},
    {"filter_add","Добавить фильтр","Add filter"},
    {"filter_name","Имя фильтра:","Filter name:"},
    {"filter_exts","Расширения (через запятую):","Extensions (comma-separated):"},
    {"filter_delete","Удалить фильтр","Delete filter"},
    {"smart_model","Модель","Model"},
    {"smart_serial","Серийный номер","Serial"},
    {"smart_capacity","Объём","Capacity"},
    {"smart_temp","Температура","Temperature"},
    {"smart_hours","Наработка","Power-on hours"},
    {"smart_realloc","Переназнач. секторов","Reallocated sectors"},
    {"smart_wear","Износ","Wear level"},
    {"smart_crc","Ошибки CRC","CRC errors"},
    {"smart_unavailable","SMART недоступен для этого устройства","SMART not available for this device"},
    {"save_error","Ошибка сохранения","Save error"},
    {"signed_ok","Подпись БД верна","Database signature verified"},
    {"unsigned_warn","БД без подписи — будет подписана при следующем сохранении","Database unsigned — will be signed on next save"},
    {"sig_mismatch","Подпись БД сделана чужим ключом","Database signature was made by a foreign key"},
    {"add_auto","Выбрать подключённый диск","Select connected disk"},
    {"add_manual","Создать вручную","Create manually"},
    {"uuid","UUID","UUID"},
    {"connected_yes","Подключён","Connected"},
    {"connected_no","Не подключён","Disconnected"},
    {"disk_detected","Диск подключён","Disk connected"},
    {"last_snapshot","Последний слепок","Last snapshot"},
    {"today","сегодня","today"},
    {"yesterday","вчера","yesterday"},
    {"days_ago","дн. назад","days ago"},
    {"batch_reindex","Обновить все подключённые","Refresh all connected"},
    {"batch_title","Обновление слепков","Batch reindex"},
    {"batch_progress","%d из %d…","%d of %d..."},
    {"batch_done","Обновлено: %d, пропущено: %d, ошибок: %d","Done: %d, skipped: %d, errors: %d"},
    {"also_on","Также на:","Also on:"},
    {"no_connected","Нет подключённых дисков с сохранённым UUID","No connected disks with saved UUID"},
    {"refresh_connections","Обновить статус дисков","Refresh disk status"},
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
    char *name;
    char *exts;
} search_filter_t;

typedef struct {
    char *label, *type, *size, *cipher, *content_tag, *dsalt, *tag_full, *dpass, *notes, *alias;
    char *files;
    char *smart;
    char *uuid;
    long long last_snapshot;
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
    secure_free_string(&e->files);
    secure_free_string(&e->smart);
    secure_free_string(&e->uuid);
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
    search_filter_t *filters;
    int filter_count, filter_cap;
    gpgme_ctx_t gpg_ctx;
    gboolean is_signed;
} db_manager_t;

static void db_manager_init(db_manager_t *m) { memset(m, 0, sizeof(*m)); strcpy(m->lang, "ru"); }

static void db_init_default_filters(db_manager_t *m) {
    static const struct { const char *n; const char *e; } defs[] = {
        {"PDF",     "pdf"},
        {"DOC",     "doc,docx,odt,rtf,txt,md"},
        {"IMG",     "jpg,jpeg,png,gif,webp,svg,bmp,tiff"},
        {"VIDEO",   "mp4,mkv,avi,mov,webm,m4v"},
        {"AUDIO",   "mp3,flac,wav,ogg,m4a,opus"},
        {"ARCHIVE", "zip,tar,gz,xz,bz2,7z,rar"},
        {"CODE",    "c,h,cpp,hpp,py,js,ts,sh,go,rs,java"},
        {"EXEC",    "exe,bin,appimage,deb,rpm"},
    };
    m->filter_cap = 16;
    m->filters = calloc(m->filter_cap, sizeof(search_filter_t));
    m->filter_count = 0;
    for (size_t i = 0; i < ARRAY_SIZE(defs); i++) {
        m->filters[m->filter_count].name = xstrdup(defs[i].n);
        m->filters[m->filter_count].exts = xstrdup(defs[i].e);
        m->filter_count++;
    }
}

static int ensure_db_gpg(db_manager_t *m) {
    if (!m) return -1;
    gpgme_error_t gerr = gpgme_new(&m->gpg_ctx);
    if (gerr != GPG_ERR_NO_ERROR) return -1;
    gpgme_set_protocol(m->gpg_ctx, GPGME_PROTOCOL_OpenPGP);
    return 0;
}

static void db_manager_clear(db_manager_t *m) {
    if (!m) return;
    for (int i = 0; i < m->filter_count; i++) {
        free(m->filters[i].name);
        free(m->filters[i].exts);
    }
    free(m->filters); m->filters = NULL;
    m->filter_count = 0; m->filter_cap = 0;
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
    gerr = gpgme_op_decrypt_verify(m->gpg_ctx, in, out);
    if (gerr != GPG_ERR_NO_ERROR) {
        snprintf(err_msg, err_msg_sz, "%s%s", i18n("gpg_err"), gpgme_strerror(gerr));
        goto cleanup;
    }
    m->is_signed = FALSE;
    gpgme_verify_result_t vres = gpgme_op_verify_result(m->gpg_ctx);
    if (vres && vres->signatures && vres->signatures->fpr) {
        if (vres->signatures->status != GPG_ERR_NO_ERROR) {
            snprintf(err_msg, err_msg_sz, "%s%s", i18n("gpg_err"),
                     gpgme_strerror(vres->signatures->status));
            goto cleanup;
        }
        if (strcmp(vres->signatures->fpr, m->recipient) != 0) {
            snprintf(err_msg, err_msg_sz, "%s", i18n("sig_mismatch"));
            goto cleanup;
        }
        m->is_signed = TRUE;
    }
    size_t rlen = 0;
    char *raw = gpgme_data_release_and_get_mem(out, &rlen);
    out = NULL;
    if (!raw) goto cleanup;
    result = malloc(rlen + 1);
    if (!result) { sodium_memzero(raw, rlen); gpgme_free(raw); goto cleanup; }
    memcpy(result, raw, rlen);
    result[rlen] = '\0';
    sodium_memzero(raw, rlen);
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
    gpgme_key_t signer = NULL;
    gboolean have_signer = FALSE;
    char *result = NULL;

    gerr = gpgme_data_new_from_mem(&in, plaintext, pt_len, 0);
    GPG_CHECK(gerr, "gpgme_data_new_from_mem");
    gerr = gpgme_data_new(&out);
    GPG_CHECK(gerr, "gpgme_data_new");
    gerr = gpgme_get_key(m->gpg_ctx, m->recipient, &keys[0], 0);
    GPG_CHECK(gerr, "gpgme_get_key");

    if (gpgme_get_key(m->gpg_ctx, m->recipient, &signer, 1) == GPG_ERR_NO_ERROR && signer) {
        gpgme_signers_clear(m->gpg_ctx);
        gpgme_signers_add(m->gpg_ctx, signer);
        gpgme_key_release(signer);
        signer = NULL;
        have_signer = TRUE;
    }

    gpgme_key_t recips[] = {keys[0], NULL};
    if (have_signer)
        gerr = gpgme_op_encrypt_sign(m->gpg_ctx, recips,
            GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    else
        gerr = gpgme_op_encrypt(m->gpg_ctx, recips,
            GPGME_ENCRYPT_ALWAYS_TRUST, in, out);

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
    if (signer) gpgme_key_release(signer);
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
        if (n < 0) n = 0;
        m->entry_cap = n + 16;
        m->entries = calloc(m->entry_cap, sizeof(db_entry_t));
        if (!m->entries) {
            cJSON_Delete(root);
            snprintf(err_msg, err_msg_sz, "alloc failed");
            return -1;
        }
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
            v = cJSON_GetObjectItem(je, "files");       if (v && cJSON_IsString(v)) m->entries[i].files = xstrdup(v->valuestring);
            v = cJSON_GetObjectItem(je, "smart");       if (v && cJSON_IsString(v)) m->entries[i].smart = xstrdup(v->valuestring);
            v = cJSON_GetObjectItem(je, "uuid");        if (v && cJSON_IsString(v)) m->entries[i].uuid = xstrdup(v->valuestring);
            v = cJSON_GetObjectItem(je, "last_snapshot");
            if (v && cJSON_IsNumber(v)) m->entries[i].last_snapshot = (long long)v->valuedouble;
        }
    }
    cJSON *j_filters = cJSON_GetObjectItem(root, "filters");
    if (j_filters && cJSON_IsArray(j_filters)) {
        int n = cJSON_GetArraySize(j_filters);
        if (n < 0) n = 0;
        m->filter_cap = n + 4;
        m->filters = calloc(m->filter_cap, sizeof(search_filter_t));
        if (!m->filters) {
            cJSON_Delete(root);
            snprintf(err_msg, err_msg_sz, "alloc failed");
            return -1;
        }
        m->filter_count = 0;
        for (int i = 0; i < n; i++) {
            cJSON *jf = cJSON_GetArrayItem(j_filters, i);
            if (!cJSON_IsObject(jf)) continue;
            cJSON *jn = cJSON_GetObjectItem(jf, "name");
            cJSON *je = cJSON_GetObjectItem(jf, "exts");
            if (jn && je && cJSON_IsString(jn) && cJSON_IsString(je)) {
                m->filters[m->filter_count].name = xstrdup(jn->valuestring);
                m->filters[m->filter_count].exts = xstrdup(je->valuestring);
                m->filter_count++;
            }
        }
    }
    if (!m->filters) db_init_default_filters(m);
    cJSON_Delete(root);
    return 0;
}

static int db_save(db_manager_t *m, char *err_msg, size_t err_msg_sz) {
    cJSON *root = cJSON_CreateObject();
    if (!root) { snprintf(err_msg, err_msg_sz, "JSON alloc failed"); return -1; }
    cJSON_AddNumberToObject(root, "version", DB_VERSION);
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
        if (e->files && e->files[0]) cJSON_AddStringToObject(je, "files", e->files);
        if (e->smart && e->smart[0]) cJSON_AddStringToObject(je, "smart", e->smart);
        if (e->uuid && e->uuid[0])   cJSON_AddStringToObject(je, "uuid",  e->uuid);
        if (e->last_snapshot > 0)
            cJSON_AddNumberToObject(je, "last_snapshot", (double)e->last_snapshot);
        cJSON_AddItemToArray(j_entries, je);
    }
    cJSON_AddItemToObject(root, "entries", j_entries);
    cJSON *j_filters = cJSON_CreateArray();
    for (int i = 0; i < m->filter_count; i++) {
        cJSON *jf = cJSON_CreateObject();
        cJSON_AddStringToObject(jf, "name", m->filters[i].name);
        cJSON_AddStringToObject(jf, "exts", m->filters[i].exts);
        cJSON_AddItemToArray(j_filters, jf);
    }
    cJSON_AddItemToObject(root, "filters", j_filters);
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) { snprintf(err_msg, err_msg_sz, "JSON print failed"); return -1; }
    char *enc = db_gpg_encrypt(m, json_str, strlen(json_str), err_msg, err_msg_sz);
    SECURE_ZERO(json_str, strlen(json_str));
    free(json_str);
    if (!enc) return -1;

    size_t tmp_len = strlen(m->file_path) + 5;
    char *tmp_path = malloc(tmp_len);
    if (!tmp_path) { free(enc); return -1; }
    snprintf(tmp_path, tmp_len, "%s.tmp", m->file_path);

    unlink(tmp_path);
    int fd = open(tmp_path,
        O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_EXCL, 0600);
    if (fd < 0) {
        snprintf(err_msg, err_msg_sz, "Cannot create temp file: %s", strerror(errno));
        free(tmp_path); free(enc); return -1;
    }

    FILE *f = fdopen(fd, "wb");
    if (!f) {
        snprintf(err_msg, err_msg_sz, "fdopen failed: %s", strerror(errno));
        close(fd); unlink(tmp_path); free(tmp_path); free(enc); return -1;
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
        unlink(tmp_path); free(tmp_path); return -1;
    }

    size_t prev_len = strlen(m->file_path) + 6;
    char *prev_path = malloc(prev_len);
    if (prev_path) {
        snprintf(prev_path, prev_len, "%s.prev", m->file_path);
        unlink(prev_path);
        if (link(m->file_path, prev_path) != 0) {
            (void)0;
        }
        free(prev_path);
    }

    if (rename(tmp_path, m->file_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot rename temp file: %s", strerror(errno));
        unlink(tmp_path); free(tmp_path); return -1;
    }

    char *dir_copy = xstrdup(m->file_path);
    char *slash = strrchr(dir_copy, '/');
    if (slash) {
        *slash = '\0';
        int dfd = open(dir_copy, O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) { fsync(dfd); close(dfd); }
    }
    free(dir_copy);

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
        g_mkdir_with_parents(dir, 0700);
        chmod(dir, 0700);
    }
    free(dir);

    m->entry_cap = 16;
    m->entries = calloc(m->entry_cap, sizeof(db_entry_t));
    if (!m->entries) { db_manager_clear(m); free(m); return NULL; }
    m->entry_count = 0;
    db_init_default_filters(m);
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

typedef struct fs_node {
    char *name;
    gboolean is_dir;
    long long size;
    GList *children;
    GHashTable *children_index;
} fs_node_t;

static fs_node_t *fs_node_new(const char *name, gboolean is_dir) {
    fs_node_t *n = g_new0(fs_node_t, 1);
    n->name = g_strdup(name);
    n->is_dir = is_dir;
    n->size = -1;
    n->children = NULL;
    n->children_index = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    return n;
}

static void fs_node_free(fs_node_t *n) {
    if (!n) return;
    g_free(n->name);
    for (GList *l = n->children; l; l = l->next)
        fs_node_free((fs_node_t*)l->data);
    g_list_free(n->children);
    if (n->children_index) g_hash_table_destroy(n->children_index);
    g_free(n);
}

static fs_node_t *fs_find_child(fs_node_t *parent, const char *name) {
    return g_hash_table_lookup(parent->children_index, name);
}

static gint fs_cmp(gconstpointer a, gconstpointer b) {
    const fs_node_t *na = a, *nb = b;
    if (na->is_dir != nb->is_dir) return na->is_dir ? -1 : 1;
    return g_strcmp0(na->name, nb->name);
}

static fs_node_t *fs_build_tree(const char *files) {
    fs_node_t *root = fs_node_new("", TRUE);
    if (!files || !files[0]) return root;

    char *copy = xstrdup(files);
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (!line[0]) continue;
        long long sz = -1;
        char *tab = strchr(line, '\t');
        if (tab) { *tab = '\0'; sz = atoll(tab + 1); }
        char **parts = g_strsplit(line, "/", -1);
        int n = g_strv_length(parts);
        int last = -1;
        for (int i = n - 1; i >= 0; i--)
            if (parts[i][0]) { last = i; break; }
        fs_node_t *cur = root;
        for (int i = 0; i < n; i++) {
            if (!parts[i][0]) continue;
            gboolean is_last = (i == last);
            fs_node_t *child = fs_find_child(cur, parts[i]);
            if (!child) {
                child = fs_node_new(parts[i], !is_last);
                cur->children = g_list_append(cur->children, child);
                g_hash_table_insert(cur->children_index, child->name, child);
            }
            if (is_last) child->size = sz;
            cur = child;
        }
        g_strfreev(parts);
    }
    free(copy);

    GQueue *q = g_queue_new();
    g_queue_push_tail(q, root);
    while (!g_queue_is_empty(q)) {
        fs_node_t *nd = g_queue_pop_head(q);
        nd->children = g_list_sort(nd->children, fs_cmp);
        for (GList *l = nd->children; l; l = l->next)
            g_queue_push_tail(q, l->data);
    }
    g_queue_free(q);
    return root;
}

static void fs_to_store(fs_node_t *node, GtkTreeStore *store, GtkTreeIter *parent) {
    for (GList *l = node->children; l; l = l->next) {
        fs_node_t *c = l->data;
        GtkTreeIter iter;
        char szbuf[64] = "";
        if (!c->is_dir && c->size >= 0) {
            char *f = format_bytes(c->size);
            snprintf(szbuf, sizeof(szbuf), "%s", f);
            g_free(f);
        }
        gtk_tree_store_append(store, &iter, parent);
        gtk_tree_store_set(store, &iter,
            0, c->name,
            1, c->is_dir,
            2, szbuf,
            -1);
        if (c->is_dir) fs_to_store(c, store, &iter);
    }
}

static char *scan_directory_recursive(const char *root) {
    GString *s = g_string_new(NULL);
    GQueue *queue = g_queue_new();
    g_queue_push_tail(queue, g_strdup(root));
    size_t root_len = strlen(root);

    while (!g_queue_is_empty(queue)) {
        char *dir = g_queue_pop_head(queue);
        GDir *d = g_dir_open(dir, 0, NULL);
        if (d) {
            const char *name;
            while ((name = g_dir_read_name(d))) {
                char *full = g_build_filename(dir, name, NULL);
                struct stat st;
                if (lstat(full, &st) != 0) { g_free(full); continue; }
                if (S_ISDIR(st.st_mode)) {
                    g_queue_push_tail(queue, full);
                } else if (S_ISREG(st.st_mode)) {
                    const char *rel = full + root_len;
                    while (*rel == '/' || *rel == '\\') rel++;
                    g_string_append_printf(s, "%s\t%lld\n", rel, (long long)st.st_size);
                    g_free(full);
                } else {
                    g_free(full);
                }
            }
            g_dir_close(d);
        }
        g_free(dir);
    }
    g_queue_free(queue);
    return g_string_free(s, FALSE);
}

typedef struct {
    char *device;
    char *uuid;
    long long size_bytes;
    char *size_h;
    char *fstype;
    char *mountpoint;
    char *model;
    char *transport;
    char *label;
    gboolean connected;
} disk_info_t;

static void free_disk_list(disk_info_t *list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) {
        free(list[i].device);
        free(list[i].uuid);
        free(list[i].size_h);
        free(list[i].fstype);
        free(list[i].mountpoint);
        free(list[i].model);
        free(list[i].transport);
        free(list[i].label);
    }
    free(list);
}

static gboolean uuid_is_connected(const char *uuid) {
    if (!uuid || !uuid[0]) return FALSE;
    char path[512];
    snprintf(path, sizeof(path), "/dev/disk/by-uuid/%s", uuid);
    return access(path, F_OK) == 0;
}

static void walk_lsblk(cJSON *arr, disk_info_t **list, int *count, int *cap) {
    int n = cJSON_GetArraySize(arr);
    for (int i = 0; i < n; i++) {
        cJSON *dev = cJSON_GetArrayItem(arr, i);
        cJSON *j_uuid = cJSON_GetObjectItem(dev, "uuid");
        cJSON *j_path = cJSON_GetObjectItem(dev, "path");
        if (j_uuid && cJSON_IsString(j_uuid) && j_uuid->valuestring[0] &&
            j_path && cJSON_IsString(j_path)) {

            if (*count >= *cap) {
                *cap = *cap ? (*cap) * 2 : 16;
                disk_info_t *tmp = realloc(*list, (*cap) * sizeof(disk_info_t));
                if (!tmp) return;
                *list = tmp;
            }
            disk_info_t *d = &(*list)[*count];
            memset(d, 0, sizeof(*d));

            d->device = xstrdup(j_path->valuestring);
            d->uuid = xstrdup(j_uuid->valuestring);

            cJSON *j_size = cJSON_GetObjectItem(dev, "size");
            if (j_size && cJSON_IsNumber(j_size)) {
                d->size_bytes = (long long)j_size->valuedouble;
                d->size_h = format_bytes(d->size_bytes);
            } else {
                d->size_h = xstrdup("?");
            }

            cJSON *j_fs = cJSON_GetObjectItem(dev, "fstype");
            if (j_fs && cJSON_IsString(j_fs)) d->fstype = xstrdup(j_fs->valuestring);

            cJSON *j_mnt = cJSON_GetObjectItem(dev, "mountpoint");
            if (j_mnt && cJSON_IsString(j_mnt) && j_mnt->valuestring[0])
                d->mountpoint = xstrdup(j_mnt->valuestring);

            cJSON *j_model = cJSON_GetObjectItem(dev, "model");
            if (j_model && cJSON_IsString(j_model)) d->model = xstrdup(j_model->valuestring);

            cJSON *j_tran = cJSON_GetObjectItem(dev, "tran");
            if (j_tran && cJSON_IsString(j_tran)) d->transport = xstrdup(j_tran->valuestring);

            cJSON *j_label = cJSON_GetObjectItem(dev, "label");
            if (j_label && cJSON_IsString(j_label) && j_label->valuestring[0])
                d->label = xstrdup(j_label->valuestring);

            d->connected = TRUE;
            (*count)++;
        }

        cJSON *children = cJSON_GetObjectItem(dev, "children");
        if (children && cJSON_IsArray(children))
            walk_lsblk(children, list, count, cap);
    }
}

static disk_info_t *list_disks(int *out_count) {
    *out_count = 0;
    gchar *argv[] = { "lsblk", "-J", "-b",
        "-o", "PATH,UUID,SIZE,FSTYPE,MOUNTPOINT,MODEL,TRAN,TYPE,LABEL",
        NULL };
    gchar *out = NULL;
    GError *err = NULL;
    gint status = 0;
    if (!g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH,
            NULL, NULL, &out, NULL, &status, &err)) {
        if (err) g_error_free(err);
        g_free(out);
        return NULL;
    }
    if (!out || status != 0) { g_free(out); return NULL; }

    cJSON *root = cJSON_Parse(out);
    g_free(out);
    if (!root) return NULL;

    cJSON *devices = cJSON_GetObjectItem(root, "blockdevices");
    if (!devices || !cJSON_IsArray(devices)) { cJSON_Delete(root); return NULL; }

    disk_info_t *list = NULL;
    int count = 0, cap = 0;
    walk_lsblk(devices, &list, &count, &cap);
    cJSON_Delete(root);
    *out_count = count;
    return list;
}

static double parse_size_to_gb(const char *s) {
    double v = 0; char unit[8] = "";
    if (sscanf(s, "%lf%7s", &v, unit) != 2) return 0;
    if (strcasecmp(unit, "MB") == 0) return v / 1000.0;
    if (strcasecmp(unit, "GB") == 0) return v;
    if (strcasecmp(unit, "TB") == 0) return v * 1000.0;
    return v;
}

static int closest_size_index_in(const char **sizes, int n, long long bytes) {
    double gb = bytes / 1000000000.0;
    int best = 0;
    double best_diff = 1e18;
    for (int i = 0; i < n; i++) {
        double sz = parse_size_to_gb(sizes[i]);
        double diff = gb > sz ? gb - sz : sz - gb;
        if (diff < best_diff) { best_diff = diff; best = i; }
    }
    return best;
}

static const char *transport_to_type(const char *tran) {
    if (!tran) return NULL;
    if (strcasecmp(tran, "usb") == 0) return "USB";
    if (strcasecmp(tran, "nvme") == 0) return "M.2";
    if (strcasecmp(tran, "mmc") == 0) return "SD";
    if (strcasecmp(tran, "sata") == 0 || strcasecmp(tran, "ata") == 0) return "SSD";
    return NULL;
}

static char *find_device_for_path(const char *path) {
    char *real = realpath(path, NULL);
    const char *use = real ? real : path;
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) { free(real); return NULL; }
    char line[2048];
    char *best_dev = NULL;
    size_t best_len = 0;
    size_t path_len = strlen(use);
    while (fgets(line, sizeof(line), f)) {
        char dev[1024], mnt[1024];
        if (sscanf(line, "%1023s %1023s", dev, mnt) != 2) continue;
        size_t mnt_len = strlen(mnt);
        if (mnt_len > path_len || mnt_len < best_len) continue;
        if (strncmp(use, mnt, mnt_len) != 0) continue;
        free(best_dev);
        best_dev = xstrdup(dev);
        best_len = mnt_len;
    }
    fclose(f);
    free(real);
    return best_dev;
}

static char *get_uuid_for_path(const char *mount_path) {
    char *dev = find_device_for_path(mount_path);
    if (!dev) return NULL;
    if (strncmp(dev, "/dev/", 5) != 0) { free(dev); return NULL; }

    gchar *argv[] = { "lsblk", "-no", "UUID", dev, NULL };
    gchar *out = NULL;
    GError *err = NULL;
    if (!g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH,
            NULL, NULL, &out, NULL, NULL, &err)) {
        if (err) g_error_free(err);
        free(dev);
        g_free(out);
        return NULL;
    }
    free(dev);
    if (!out) return NULL;

    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
    char *res = out[0] ? xstrdup(out) : NULL;
    g_free(out);
    return res;
}

static char *collect_smart_data(const char *mount_path) {
    if (!mount_path) return NULL;
    char *dev = find_device_for_path(mount_path);
    if (!dev) return NULL;
    if (strncmp(dev, "/dev/", 5) != 0) { free(dev); return NULL; }

    gchar *argv[] = { "smartctl", "-j", "-H", "-i", "-A", dev, NULL };
    gchar *stdout_buf = NULL;
    gint exit_status = 0;
    GError *serr = NULL;
    gboolean ok = g_spawn_sync(NULL, argv, NULL,
        G_SPAWN_SEARCH_PATH | G_SPAWN_STDERR_TO_DEV_NULL,
        NULL, NULL, &stdout_buf, NULL, &exit_status, &serr);
    free(dev);

    if (!ok || !stdout_buf) {
        if (serr) g_error_free(serr);
        g_free(stdout_buf);
        return NULL;
    }
    if (exit_status != 0 || !stdout_buf[0]) {
        g_free(stdout_buf);
        return NULL;
    }

    cJSON *root = cJSON_Parse(stdout_buf);
    g_free(stdout_buf);
    if (!root) return NULL;

    cJSON *result = cJSON_CreateObject();

    cJSON *model = cJSON_GetObjectItem(root, "model_name");
    if (!model) model = cJSON_GetObjectItem(root, "device_model");
    if (model && cJSON_IsString(model))
        cJSON_AddStringToObject(result, "model", model->valuestring);

    cJSON *serial = cJSON_GetObjectItem(root, "serial_number");
    if (serial && cJSON_IsString(serial))
        cJSON_AddStringToObject(result, "serial", serial->valuestring);

    cJSON *fw = cJSON_GetObjectItem(root, "firmware_version");
    if (fw && cJSON_IsString(fw))
        cJSON_AddStringToObject(result, "firmware", fw->valuestring);

    cJSON *cap = cJSON_GetObjectItem(root, "user_capacity");
    if (cap) {
        cJSON *bytes = cJSON_GetObjectItem(cap, "bytes");
        if (bytes && cJSON_IsNumber(bytes)) {
            char *s = format_bytes((long long)bytes->valuedouble);
            cJSON_AddStringToObject(result, "capacity", s);
            g_free(s);
        }
    }

    cJSON *status = cJSON_GetObjectItem(root, "smart_status");
    if (status) {
        cJSON *passed = cJSON_GetObjectItem(status, "passed");
        if (cJSON_IsBool(passed))
            cJSON_AddStringToObject(result, "health",
                cJSON_IsTrue(passed) ? "PASSED" : "FAILED");
    }

    cJSON *temp = cJSON_GetObjectItem(root, "temperature");
    if (temp) {
        cJSON *cur = cJSON_GetObjectItem(temp, "current");
        if (cur && cJSON_IsNumber(cur)) {
            char t[32]; snprintf(t, sizeof(t), "%.0f °C", cur->valuedouble);
            cJSON_AddStringToObject(result, "temperature", t);
        }
    }

    cJSON *pot = cJSON_GetObjectItem(root, "power_on_time");
    if (pot) {
        cJSON *h = cJSON_GetObjectItem(pot, "hours");
        if (h && cJSON_IsNumber(h)) {
            char t[32]; snprintf(t, sizeof(t), "%.0f", h->valuedouble);
            cJSON_AddStringToObject(result, "hours", t);
        }
    }

    cJSON *attrs = cJSON_GetObjectItem(root, "ata_smart_attributes");
    if (attrs) {
        cJSON *table = cJSON_GetObjectItem(attrs, "table");
        if (table && cJSON_IsArray(table)) {
            int n = cJSON_GetArraySize(table);
            for (int i = 0; i < n; i++) {
                cJSON *row = cJSON_GetArrayItem(table, i);
                cJSON *name = cJSON_GetObjectItem(row, "name");
                if (!name || !cJSON_IsString(name)) continue;
                cJSON *raw = cJSON_GetObjectItem(row, "raw");
                if (!raw) continue;
                cJSON *val = cJSON_GetObjectItem(raw, "value");
                if (!val || !cJSON_IsNumber(val)) continue;

                const char *nm = name->valuestring;
                char t[32]; snprintf(t, sizeof(t), "%.0f", val->valuedouble);

                if (strcmp(nm, "Reallocated_Sector_Ct") == 0)
                    cJSON_AddStringToObject(result, "reallocated", t);
                else if (strcmp(nm, "Power_Cycle_Count") == 0)
                    cJSON_AddStringToObject(result, "power_cycles", t);
                else if (strcmp(nm, "Wear_Leveling_Count") == 0 ||
                         strcmp(nm, "Media_Wearout_Indicator") == 0 ||
                         strcmp(nm, "Percentage_Used") == 0)
                    cJSON_AddStringToObject(result, "wear", t);
                else if (strcmp(nm, "UDMA_CRC_Error_Count") == 0 ||
                         strcmp(nm, "CRC_Error_Count") == 0)
                    cJSON_AddStringToObject(result, "crc_errors", t);
            }
        }
    }

    cJSON_Delete(root);
    char *final = cJSON_PrintUnformatted(result);
    cJSON_Delete(result);
    return final;
}

static int db_set_entry_snapshot(db_manager_t *m, const char *label,
    const char *files, const char *smart_json,
    char *err_msg, size_t err_msg_sz)
{
    for (int i = 0; i < m->entry_count; i++) {
        if (strcmp(m->entries[i].label, label) == 0) {
            free(m->entries[i].files);
            m->entries[i].files = (files && files[0]) ? xstrdup(files) : NULL;
            free(m->entries[i].smart);
            m->entries[i].smart = (smart_json && smart_json[0]) ? xstrdup(smart_json) : NULL;
            m->entries[i].last_snapshot = (long long)time(NULL);
            return db_save(m, err_msg, err_msg_sz);
        }
    }
    return -1;
}

static int count_lines(const char *s) {
    if (!s) return 0;
    int n = 0;
    for (const char *p = s; *p; p++) if (*p == '\n') n++;
    return n;
}

static long long total_bytes_in_files(const char *files) {
    if (!files) return 0;
    long long total = 0;
    char *copy = xstrdup(files);
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *tab = strchr(line, '\t');
        if (tab) total += atoll(tab + 1);
    }
    free(copy);
    return total;
}

static int db_add_entry(db_manager_t *m, const char *type, const char *size,
    const char *cipher, const char *content_tag, const char *dsalt,
    const char *tag_full, const char *dpass, const char *notes,
    const char *alias, const char *uuid,
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
    if (uuid && uuid[0]) e->uuid = xstrdup(uuid);
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
    GtkWidget *btn_snapshot, *btn_find, *btn_batch;
    GtkWidget *btn_refresh;
    GtkWidget *notes_lbl;
    GtkWidget *notes_sep;
    GtkWidget *tree_view;
    GtkTreeStore *tree_store;
    GtkWidget *tree_summary;
    GtkWidget *tree_filter;
    GtkWidget *tree_expand_btn;
    GtkWidget *tree_collapse_btn;
    GtkWidget *tree_sw;
    GtkWidget *toast_revealer;
    GtkWidget *toast_label;
    int        toast_entry_idx;
    db_manager_t *db;
    char *current_file;
    char *expected_fp;
    guint clipboard_timer_id;
    guint autolock_timer_id;
    guint connection_timer_id;
    int current_entry_idx;
} AppData;

static AppData g_app;
static GdkPixbuf *icon_pb;
static volatile sig_atomic_t g_shutdown_requested = 0;
static guint g_toast_timer_id = 0;
static GHashTable *g_known_uuids = NULL;
static gboolean g_uuids_initialized = FALSE;
static gboolean g_batch_running = FALSE;

static char *config_path(void) {
    char *dir = g_build_filename(g_get_user_config_dir(), "diskpass", NULL);
    g_mkdir_with_parents(dir, 0700);
    char *path = g_build_filename(dir, "config", NULL);
    g_free(dir);
    return path;
}

static void save_config(void) {
    char *path = config_path();
    GKeyFile *kf = g_key_file_new();
    g_key_file_set_string(kf, "main", "lang", g_lang);
    if (g_app.current_file)
        g_key_file_set_string(kf, "main", "last_db", g_app.current_file);
    gsize len;
    char *data = g_key_file_to_data(kf, &len, NULL);
    if (data) {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            ssize_t w = write(fd, data, len);
            (void)w;
            close(fd);
        }
        g_free(data);
    }
    g_key_file_free(kf);
    g_free(path);
}

static void load_config(void) {
    char *path = config_path();
    GKeyFile *kf = g_key_file_new();
    if (g_key_file_load_from_file(kf, path, 0, NULL)) {
        char *lang = g_key_file_get_string(kf, "main", "lang", NULL);
        if (lang && lang[0]) snprintf(g_lang, sizeof(g_lang), "%s", lang);
        g_free(lang);
    }
    g_key_file_free(kf);
    g_free(path);
}

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
    return gtk_image_new_from_icon_name("drive-harddisk-symbolic", GTK_ICON_SIZE_BUTTON);
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

static void on_minimize_clicked(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    gtk_window_iconify(GTK_WINDOW(g_app.window));
}

static void on_maximize_clicked(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    GtkWindow *win = GTK_WINDOW(g_app.window);
    if (gtk_window_is_maximized(win)) gtk_window_unmaximize(win);
    else gtk_window_maximize(win);
}

static void on_close_clicked(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    gtk_window_close(GTK_WINDOW(g_app.window));
}

static gboolean on_window_state_changed(GtkWidget *w, GdkEventWindowState *ev,
    gpointer user_data)
{
    (void)w;
    GtkButton *btn = GTK_BUTTON(user_data);
    if (ev->new_window_state & GDK_WINDOW_STATE_MAXIMIZED)
        gtk_button_set_label(btn, "❐");
    else
        gtk_button_set_label(btn, "□");
    return FALSE;
}

static void install_dialog_title(GtkWindow *win, const char *text) {
    gtk_window_set_title(win, text);
    GtkWidget *hb = NULL;
    if (GTK_IS_DIALOG(win))
        hb = gtk_dialog_get_header_bar(GTK_DIALOG(win));
    if (!GTK_IS_HEADER_BAR(hb))
        hb = gtk_window_get_titlebar(win);
    if (!GTK_IS_HEADER_BAR(hb)) {
        hb = gtk_header_bar_new();
        gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);
        gtk_window_set_titlebar(win, hb);
    }
    GtkWidget *lbl = gtk_label_new(text);
    gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_NONE);
    gtk_widget_set_size_request(lbl, 420, -1);
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(hb), lbl);
    gtk_widget_show_all(hb);
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
    if (g_app.btn_snapshot) gtk_widget_set_tooltip_text(g_app.btn_snapshot, i18n("snapshot_btn"));
    if (g_app.btn_find) gtk_widget_set_tooltip_text(g_app.btn_find, i18n("find_btn"));
    if (g_app.btn_batch) gtk_widget_set_tooltip_text(g_app.btn_batch, i18n("batch_reindex"));
    if (g_app.btn_refresh) gtk_widget_set_tooltip_text(g_app.btn_refresh, i18n("refresh_connections"));
    if (g_app.search) gtk_entry_set_placeholder_text(GTK_ENTRY(g_app.search), i18n("search"));
    if (g_app.tree_filter) gtk_entry_set_placeholder_text(GTK_ENTRY(g_app.tree_filter), i18n("search"));
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

        GtkWidget *title_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        if (e->uuid && e->uuid[0]) {
            gboolean conn = uuid_is_connected(e->uuid);
            GtkWidget *dot = gtk_label_new(conn ? "●" : "○");
            gtk_style_context_add_class(gtk_widget_get_style_context(dot),
                conn ? "connected-dot" : "disconnected-dot");
            gtk_box_pack_start(GTK_BOX(title_row), dot, FALSE, FALSE, 0);
        }

        GtkWidget *lbl = gtk_label_new(has_alias ? e->alias : e->label);
        gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "row-title");
        gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_END);
        gtk_box_pack_start(GTK_BOX(title_row), lbl, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(box), title_row, FALSE, TRUE, 0);

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

        GtkWidget *sub = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        GtkWidget *l1 = gtk_label_new(e->type ? e->type : "");
        GtkWidget *l2 = gtk_label_new(e->size ? e->size : "");
        GtkWidget *l3 = gtk_label_new(e->cipher ? e->cipher : "");
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_style_context_add_class(gtk_widget_get_style_context(l2), "dim-label");
        gtk_style_context_add_class(gtk_widget_get_style_context(l3), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_xalign(GTK_LABEL(l3), 0.0);
        gtk_box_pack_start(GTK_BOX(sub), l1, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(sub), l2, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(sub), l3, FALSE, FALSE, 0);

        if (e->last_snapshot > 0) {
            char *rel = g_strdup_printf("%lld", (long long)((time(NULL) - e->last_snapshot) / 86400));
            char *formatted = g_strdup_printf("%s %s", rel, i18n("days_ago"));
            GtkWidget *rl = gtk_label_new(formatted);
            gtk_style_context_add_class(gtk_widget_get_style_context(rl), "dim-label");
            gtk_box_pack_end(GTK_BOX(sub), rl, FALSE, FALSE, 0);
            g_free(rel);
            g_free(formatted);
        }

        if (e->files && e->files[0]) {
            char fc[32];
            snprintf(fc, sizeof(fc), "%d", count_lines(e->files));
            GtkWidget *fl = gtk_label_new(fc);
            gtk_style_context_add_class(gtk_widget_get_style_context(fl), "row-count");
            gtk_box_pack_end(GTK_BOX(sub), fl, FALSE, FALSE, 0);
        }
        gtk_box_pack_start(GTK_BOX(box), sub, FALSE, FALSE, 0);
        gtk_container_add(GTK_CONTAINER(row), box);
        g_object_set_data(G_OBJECT(row), "entry_idx", GINT_TO_POINTER(i));
        gtk_list_box_insert(g_app.listbox, row, -1);
    }
    gtk_widget_show_all(GTK_WIDGET(g_app.listbox));
}

static void set_tree_visible(gboolean visible) {
    if (visible) {
        gtk_widget_show(g_app.tree_summary);
        gtk_widget_show(g_app.tree_expand_btn);
        gtk_widget_show(g_app.tree_collapse_btn);
        gtk_widget_show(g_app.tree_filter);
        if (g_app.tree_view) gtk_widget_show(g_app.tree_view);
        gtk_widget_show(g_app.tree_sw);
    } else {
        gtk_widget_hide(g_app.tree_summary);
        gtk_widget_hide(g_app.tree_filter);
        gtk_widget_hide(g_app.tree_expand_btn);
        gtk_widget_hide(g_app.tree_collapse_btn);
        gtk_widget_hide(g_app.tree_sw);
    }
}

static void set_notes_visible(gboolean visible) {
    if (visible) {
        gtk_widget_show(g_app.notes_sep);
        gtk_widget_show(g_app.notes_lbl);
        gtk_widget_show(g_app.notes_text);
    } else {
        gtk_widget_hide(g_app.notes_sep);
        gtk_widget_hide(g_app.notes_lbl);
        gtk_widget_hide(g_app.notes_text);
    }
}

static void clear_details(void) {
    gtk_label_set_text(GTK_LABEL(g_app.lbl_main), i18n("select_entry"));
    GList *children = gtk_container_get_children(GTK_CONTAINER(g_app.grid));
    for (GList *l = children; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(children);
    gtk_label_set_text(GTK_LABEL(g_app.notes_text), "");
    gtk_widget_set_sensitive(g_app.btn_copy_label, FALSE);
    gtk_widget_set_sensitive(g_app.btn_copy_pass, FALSE);

    if (g_app.tree_store) gtk_tree_store_clear(g_app.tree_store);
    set_tree_visible(FALSE);
    set_notes_visible(FALSE);
}

static void tree_icon_func(GtkTreeViewColumn *col, GtkCellRenderer *rend,
    GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
    (void)col; (void)data;
    gboolean is_dir = FALSE;
    gtk_tree_model_get(model, iter, 1, &is_dir, -1);
    g_object_set(rend, "icon-name",
        is_dir ? "folder" : "text-x-generic", NULL);
}

static void on_tree_row_activated(GtkTreeView *tv, GtkTreePath *path,
    GtkTreeViewColumn *col, gpointer user_data)
{
    (void)tv; (void)col; (void)user_data;
    if (gtk_tree_view_row_expanded(GTK_TREE_VIEW(g_app.tree_view), path))
        gtk_tree_view_collapse_row(GTK_TREE_VIEW(g_app.tree_view), path);
    else
        gtk_tree_view_expand_row(GTK_TREE_VIEW(g_app.tree_view), path, FALSE);
}

static char *g_tree_filter_needle = NULL;

static gboolean tree_filter_func(GtkTreeModel *model, GtkTreeIter *iter, gpointer data) {
    (void)data;
    if (!g_tree_filter_needle || !g_tree_filter_needle[0]) return TRUE;

    char *name = NULL;
    gtk_tree_model_get(model, iter, 0, &name, -1);
    gboolean match = FALSE;
    if (name) {
        char *low = g_ascii_strdown(name, -1);
        match = (strstr(low, g_tree_filter_needle) != NULL);
        g_free(low);
        g_free(name);
    }
    if (match) return TRUE;

    GtkTreeIter child;
    if (gtk_tree_model_iter_children(model, &child, iter)) {
        do {
            if (tree_filter_func(model, &child, data)) return TRUE;
        } while (gtk_tree_model_iter_next(model, &child));
    }
    return FALSE;
}

static void on_tree_filter_changed(GtkSearchEntry *e, gpointer u) {
    (void)u;
    const char *txt = gtk_entry_get_text(GTK_ENTRY(e));

    free(g_tree_filter_needle);
    g_tree_filter_needle = (txt && txt[0]) ? g_ascii_strdown(txt, -1) : NULL;

    GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(g_app.tree_view));
    if (GTK_IS_TREE_MODEL_FILTER(model))
        gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(model));
    if (txt && txt[0])
        gtk_tree_view_expand_all(GTK_TREE_VIEW(g_app.tree_view));
}

static void on_tree_expand_all(GtkButton *b, gpointer u) {
    (void)b; (void)u;
    gtk_tree_view_expand_all(GTK_TREE_VIEW(g_app.tree_view));
}

static void on_tree_collapse_all(GtkButton *b, gpointer u) {
    (void)b; (void)u;
    gtk_tree_view_collapse_all(GTK_TREE_VIEW(g_app.tree_view));
}

static char *tree_build_path(GtkTreeModel *model, GtkTreeIter *iter) {
    GtkTreeIter cur = *iter;
    GString *s = g_string_new(NULL);
    while (1) {
        char *name = NULL;
        gtk_tree_model_get(model, &cur, 0, &name, -1);
        if (!name) break;
        g_string_prepend(s, name);
        g_free(name);
        GtkTreeIter parent;
        if (!gtk_tree_model_iter_parent(model, &parent, &cur)) break;
        g_string_prepend_c(s, '/');
        cur = parent;
    }
    return g_string_free(s, FALSE);
}

static void on_tree_copy_path(GtkMenuItem *item, gpointer u) {
    (void)item; (void)u;
    char *p = g_object_get_data(G_OBJECT(item), "path");
    if (p) clipboard_copy_secure(p);
}

static void on_tree_copy_name(GtkMenuItem *item, gpointer u) {
    (void)item; (void)u;
    char *p = g_object_get_data(G_OBJECT(item), "name");
    if (p) clipboard_copy_secure(p);
}

static gboolean on_tree_button_press(GtkWidget *tv, GdkEventButton *ev, gpointer u) {
    (void)u;
    if (ev->button != 3) return FALSE;

    GtkTreePath *path = NULL;
    if (!gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(tv),
            (int)ev->x, (int)ev->y, &path, NULL, NULL, NULL))
        return FALSE;

    GtkTreeIter iter;
    GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(tv));
    if (!gtk_tree_model_get_iter(model, &iter, path)) {
        gtk_tree_path_free(path);
        return FALSE;
    }

    char *name = NULL;
    gtk_tree_model_get(model, &iter, 0, &name, -1);
    char *full = tree_build_path(model, &iter);

    GtkWidget *menu = gtk_menu_new();

    GtkWidget *mi1 = gtk_menu_item_new_with_label(i18n("copy_path"));
    g_object_set_data_full(G_OBJECT(mi1), "path", full, g_free);
    g_signal_connect(mi1, "activate", G_CALLBACK(on_tree_copy_path), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi1);

    GtkWidget *mi2 = gtk_menu_item_new_with_label(i18n("copy_name"));
    g_object_set_data_full(G_OBJECT(mi2), "name", name, g_free);
    g_signal_connect(mi2, "activate", G_CALLBACK(on_tree_copy_name), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi2);

    gtk_widget_show_all(menu);
    gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent*)ev);

    gtk_tree_path_free(path);
    return TRUE;
}

static void build_file_tree(const char *files) {
    if (!g_app.tree_store) return;
    gtk_tree_store_clear(g_app.tree_store);
    if (!files || !files[0]) return;
    fs_node_t *root = fs_build_tree(files);
    fs_to_store(root, g_app.tree_store, NULL);
    fs_node_free(root);

    if (gtk_tree_model_iter_n_children(GTK_TREE_MODEL(g_app.tree_store), NULL) <= 100) {
        GtkTreePath *p = gtk_tree_path_new_first();
        gtk_tree_view_expand_row(GTK_TREE_VIEW(g_app.tree_view), p, FALSE);
        gtk_tree_path_free(p);
    }
}

static char *format_relative_time(long long ts) {
    if (ts <= 0) return g_strdup("");
    time_t now = time(NULL);
    long long diff = (long long)now - ts;
    if (diff < 0) diff = 0;
    long long days = diff / 86400;
    if (days == 0) return g_strdup(i18n("today"));
    if (days == 1) return g_strdup(i18n("yesterday"));
    if (days < 30) return g_strdup_printf("%lld %s", days, i18n("days_ago"));

    time_t t = (time_t)ts;
    struct tm tmv;
    localtime_r(&t, &tmv);
    char buf[32];
    strftime(buf, sizeof(buf), "%d.%m.%Y", &tmv);
    return g_strdup(buf);
}

static void show_smart_grid(GtkGrid *grid, int *row, const char *smart_json) {
    cJSON *root = cJSON_Parse(smart_json);
    if (!root) return;
    int r = *row;

    cJSON *health    = cJSON_GetObjectItem(root, "health");
    cJSON *model     = cJSON_GetObjectItem(root, "model");
    cJSON *serial    = cJSON_GetObjectItem(root, "serial");
    cJSON *capacity  = cJSON_GetObjectItem(root, "capacity");
    cJSON *temp      = cJSON_GetObjectItem(root, "temperature");
    cJSON *hours     = cJSON_GetObjectItem(root, "hours");
    cJSON *realloc_d = cJSON_GetObjectItem(root, "reallocated");
    cJSON *wear      = cJSON_GetObjectItem(root, "wear");
    cJSON *crc       = cJSON_GetObjectItem(root, "crc_errors");

    if (health && cJSON_IsString(health)) {
        GtkWidget *l1 = gtk_label_new("SMART");
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, r, 1, 1);

        GtkWidget *l2 = gtk_label_new(health->valuestring);
        gtk_style_context_add_class(gtk_widget_get_style_context(l2),
            strcmp(health->valuestring, "PASSED") == 0 ? "smart-ok" : "smart-bad");
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_grid_attach(grid, l2, 1, r, 1, 1);
        r++;
    }

    #define ADD_SMART_FIELD(label_key, node) do { \
        if ((node) && cJSON_IsString(node)) { \
            GtkWidget *a = gtk_label_new(i18n(label_key)); \
            gtk_style_context_add_class(gtk_widget_get_style_context(a), "dim-label"); \
            gtk_label_set_xalign(GTK_LABEL(a), 0.0); \
            gtk_grid_attach(grid, a, 0, r, 1, 1); \
            GtkWidget *b = gtk_label_new((node)->valuestring); \
            gtk_label_set_xalign(GTK_LABEL(b), 0.0); \
            gtk_label_set_ellipsize(GTK_LABEL(b), PANGO_ELLIPSIZE_END); \
            gtk_widget_set_hexpand(b, TRUE); \
            gtk_grid_attach(grid, b, 1, r, 1, 1); \
            r++; \
        } \
    } while (0)

    ADD_SMART_FIELD("smart_model",    model);
    ADD_SMART_FIELD("smart_serial",   serial);
    ADD_SMART_FIELD("smart_capacity", capacity);
    ADD_SMART_FIELD("smart_temp",     temp);
    ADD_SMART_FIELD("smart_hours",    hours);
    ADD_SMART_FIELD("smart_realloc",  realloc_d);
    ADD_SMART_FIELD("smart_wear",     wear);
    ADD_SMART_FIELD("smart_crc",      crc);

    #undef ADD_SMART_FIELD

    cJSON_Delete(root);
    *row = r;
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

        GtkWidget *vrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        GtkWidget *vlbl = make_visual_label(g_app.db, e->label);
        if (vlbl) {
            gtk_box_pack_start(GTK_BOX(vrow), vlbl, FALSE, FALSE, 0);
            char *tip2 = build_label_tooltip(g_app.db, e->label);
            gtk_widget_set_tooltip_text(vrow, tip2);
            g_free(tip2);
        } else {
            GtkWidget *l2 = gtk_label_new(e->label);
            gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
            gtk_box_pack_start(GTK_BOX(vrow), l2, FALSE, FALSE, 0);
        }

        gtk_widget_set_hexpand(vrow, TRUE);
        gtk_grid_attach(grid, vrow, 1, row, 1, 1);
        row++;
    }

    for (int i = 0; i < block_count; i++) {
        char header[64];
        snprintf(header, sizeof(header), "%d · %s", i+1, i18n(blocks[i].part_name));
        GtkWidget *l1 = gtk_label_new(header);
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        char val_text[128];
        if (strcmp(blocks[i].part_name, "type") == 0 ||
            strcmp(blocks[i].part_name, "size") == 0 ||
            strcmp(blocks[i].part_name, "cipher") == 0)
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

    if (e->tag_full && e->tag_full[0]) {
        GtkWidget *l1 = gtk_label_new(i18n("full_tag"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        GtkWidget *l2 = gtk_label_new(e->tag_full);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(l2), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(l2, TRUE);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }

    if (e->dpass) {
        GtkWidget *l1 = gtk_label_new(i18n("password"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        GtkWidget *l2 = gtk_label_new("••••••••••••");
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }

    if (e->uuid && e->uuid[0]) {
        GtkWidget *l1 = gtk_label_new(i18n("uuid"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);

        char buf[512];
        gboolean conn = uuid_is_connected(e->uuid);
        snprintf(buf, sizeof(buf), "%s · %s",
            e->uuid, conn ? i18n("connected_yes") : i18n("connected_no"));
        GtkWidget *l2 = gtk_label_new(buf);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_label_set_ellipsize(GTK_LABEL(l2), PANGO_ELLIPSIZE_MIDDLE);
        gtk_widget_set_hexpand(l2, TRUE);
        if (conn)
            gtk_style_context_add_class(gtk_widget_get_style_context(l2), "connected-dot");
        else
            gtk_style_context_add_class(gtk_widget_get_style_context(l2), "dim-label");
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }

    if (e->last_snapshot > 0) {
        GtkWidget *l1 = gtk_label_new(i18n("last_snapshot"));
        gtk_style_context_add_class(gtk_widget_get_style_context(l1), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(l1), 0.0);
        gtk_grid_attach(grid, l1, 0, row, 1, 1);
        char *rel = format_relative_time(e->last_snapshot);
        GtkWidget *l2 = gtk_label_new(rel);
        g_free(rel);
        gtk_label_set_xalign(GTK_LABEL(l2), 0.0);
        gtk_grid_attach(grid, l2, 1, row, 1, 1);
        row++;
    }

    if (e->smart && e->smart[0]) {
        show_smart_grid(grid, &row, e->smart);
    }

    if (e->files && e->files[0]) {
        int fc = count_lines(e->files);
        long long total = total_bytes_in_files(e->files);
        char *ts = format_bytes(total);
        char hdr[200];
        snprintf(hdr, sizeof(hdr), "%s · %d · %s", i18n("files_on_disk"), fc, ts);
        g_free(ts);
        gtk_label_set_text(GTK_LABEL(g_app.tree_summary), hdr);
        build_file_tree(e->files);
        set_tree_visible(TRUE);
    } else {
        gtk_label_set_text(GTK_LABEL(g_app.tree_summary), i18n("no_index_yet"));
        gtk_widget_show(g_app.tree_summary);
        gtk_widget_hide(g_app.tree_expand_btn);
        gtk_widget_hide(g_app.tree_collapse_btn);
        gtk_widget_hide(g_app.tree_filter);
        gtk_widget_hide(g_app.tree_sw);
        if (g_app.tree_store) gtk_tree_store_clear(g_app.tree_store);
    }

    if (e->notes && e->notes[0]) {
        gtk_label_set_text(GTK_LABEL(g_app.notes_text), e->notes);
        set_notes_visible(TRUE);
    } else {
        set_notes_visible(FALSE);
    }

    gtk_widget_show_all(GTK_WIDGET(grid));
}

static void on_row_selected(GtkListBox *box, GtkListBoxRow *row, gpointer user_data) {
    (void)box; (void)user_data;
    if (!row) {
        if (g_app.current_entry_idx != -1) {
            g_app.current_entry_idx = -1;
            clear_details();
        }
        return;
    }
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx == g_app.current_entry_idx) return;
    g_app.current_entry_idx = idx;
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

static void copy_selected_entry_field(gboolean password) {
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row || !g_app.db) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx < 0 || idx >= g_app.db->entry_count) return;
    db_entry_t *e = &g_app.db->entries[idx];
    const char *v = password ? e->dpass : e->label;
    if (v) clipboard_copy_secure(v);
}

static void on_copy_label_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    copy_selected_entry_field(FALSE);
}

static void on_copy_pass_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    copy_selected_entry_field(TRUE);
}

static void show_toast(const char *text, int duration_ms, int entry_idx);
static void reset_autolock(void);
static void on_lock_clicked(GtkButton *btn, gpointer user_data);

static void on_lock_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (g_app.autolock_timer_id) {
        g_source_remove(g_app.autolock_timer_id);
        g_app.autolock_timer_id = 0;
    }
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    free(g_app.current_file); g_app.current_file = NULL;
    free(g_app.expected_fp); g_app.expected_fp = NULL;
    g_app.current_entry_idx = -1;
    clear_details();
    refresh_entry_list();
    if (g_known_uuids) g_hash_table_remove_all(g_known_uuids);
    g_uuids_initialized = FALSE;
    if (g_toast_timer_id) { g_source_remove(g_toast_timer_id); g_toast_timer_id = 0; }
    if (g_app.toast_revealer)
        gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), FALSE);
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

static gboolean autolock_cb(gpointer user_data) {
    (void)user_data;
    g_app.autolock_timer_id = 0;
    if (g_batch_running) {
        reset_autolock();
        return G_SOURCE_REMOVE;
    }
    if (g_app.db) on_lock_clicked(NULL, NULL);
    return G_SOURCE_REMOVE;
}

static void reset_autolock(void) {
    if (g_app.autolock_timer_id) g_source_remove(g_app.autolock_timer_id);
    g_app.autolock_timer_id = 0;
    if (g_app.db)
        g_app.autolock_timer_id =
            g_timeout_add_seconds(AUTOLOCK_SECONDS, autolock_cb, NULL);
}

static gboolean on_user_activity(GtkWidget *w, GdkEvent *ev, gpointer u) {
    (void)w; (void)ev; (void)u;
    reset_autolock();
    return FALSE;
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
        if (!g_app.db) { gtk_widget_destroy(dlg); return; }
        db_manager_init(g_app.db);
        if (ensure_db_gpg(g_app.db) != 0) {
            db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL;
        } else {
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
        if (!g_app.db) { gtk_widget_destroy(dlg); return; }
        db_manager_init(g_app.db);
        if (ensure_db_gpg(g_app.db) != 0) {
            db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL;
        } else {
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
    g_app.current_entry_idx = -1;
    if (g_known_uuids) g_hash_table_remove_all(g_known_uuids);
    g_uuids_initialized = FALSE;
    save_config();
    reset_autolock();
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
    g_app.current_entry_idx = -1;
    if (g_known_uuids) g_hash_table_remove_all(g_known_uuids);
    g_uuids_initialized = FALSE;
    save_config();
    reset_autolock();
    gtk_stack_set_visible_child_name(g_app.stack, "main");
    refresh_entry_list();
    if (!g_app.db->is_signed)
        show_toast(i18n("unsigned_warn"), 8000, -1);
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
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_YES) {
        char err_buf[256] = "";
        if (db_remove_entry(g_app.db, g_app.db->entries[idx].label, err_buf, sizeof(err_buf)) != 0) {
            GtkWidget *edlg = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
                GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s: %s", i18n("save_error"), err_buf);
            gtk_dialog_run(GTK_DIALOG(edlg));
            gtk_widget_destroy(edlg);
        }
        g_app.current_entry_idx = -1;
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

static GtkWidget *make_password_field(GtkWidget **out_entry) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(entry), '*');
    gtk_entry_set_icon_from_icon_name(GTK_ENTRY(entry),
        GTK_ENTRY_ICON_SECONDARY, "eye-not-looking-symbolic");
    gtk_entry_set_icon_activatable(GTK_ENTRY(entry), GTK_ENTRY_ICON_SECONDARY, TRUE);
    gtk_entry_set_icon_tooltip_text(GTK_ENTRY(entry),
        GTK_ENTRY_ICON_SECONDARY, "Toggle visibility");
    g_signal_connect(entry, "icon-press",
        G_CALLBACK(on_toggle_password_visibility), NULL);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_box_pack_start(GTK_BOX(box), entry, TRUE, TRUE, 0);

    GtkWidget *btn = gtk_button_new_from_icon_name("view-refresh", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(btn, i18n("generate"));
    gtk_box_pack_start(GTK_BOX(box), btn, FALSE, FALSE, 0);
    g_signal_connect(btn, "clicked", G_CALLBACK(on_gen_password), entry);

    *out_entry = entry;
    return box;
}

static void show_save_error(const char *err) {
    GtkWidget *dlg = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
        GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
        "%s: %s", i18n("save_error"), err ? err : "?");
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

typedef struct {
    GtkWidget *radio_auto;
    GtkWidget *radio_manual;
    GtkWidget *disk_combo;
    GtkWidget *refresh_btn;
    GtkWidget *type_combo;
    GtkWidget *size_combo;
    GtkWidget *uuid_label;
    disk_info_t *disks;
    int disk_count;
} add_ctx_t;

static void populate_disk_combo(add_ctx_t *ctx) {
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(ctx->disk_combo));
    free_disk_list(ctx->disks, ctx->disk_count);
    ctx->disks = NULL;
    ctx->disk_count = 0;

    ctx->disks = list_disks(&ctx->disk_count);
    if (ctx->disk_count == 0) {
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(ctx->disk_combo),
            NULL, "— нет подключённых дисков —");
        gtk_combo_box_set_active(GTK_COMBO_BOX(ctx->disk_combo), 0);
        gtk_widget_set_sensitive(ctx->disk_combo, FALSE);
        return;
    }

    gtk_widget_set_sensitive(ctx->disk_combo, TRUE);
    for (int i = 0; i < ctx->disk_count; i++) {
        disk_info_t *d = &ctx->disks[i];
        char label[512];
        const char *nm = d->label ? d->label : (d->model ? d->model : "");
        snprintf(label, sizeof(label), "%s · %s · %s",
            d->device ? d->device : "?",
            nm[0] ? nm : "?",
            d->fstype ? d->fstype : "?");
        char id[64];
        snprintf(id, sizeof(id), "%d", i);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(ctx->disk_combo), id, label);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(ctx->disk_combo), 0);
}

static void on_disk_combo_changed(GtkComboBox *cb, gpointer user_data) {
    add_ctx_t *ctx = user_data;
    const char *id = gtk_combo_box_get_active_id(cb);
    if (!id) return;
    int idx = atoi(id);
    if (idx < 0 || idx >= ctx->disk_count) return;
    disk_info_t *d = &ctx->disks[idx];

    if (ctx->uuid_label) {
        char buf[600];
        snprintf(buf, sizeof(buf), "UUID: %s", d->uuid ? d->uuid : "?");
        gtk_label_set_text(GTK_LABEL(ctx->uuid_label), buf);
    }

    const char *guess_type = transport_to_type(d->transport);
    if (guess_type) {
        GtkTreeModel *model = gtk_combo_box_get_model(GTK_COMBO_BOX(ctx->type_combo));
        GtkTreeIter it;
        int i = 0;
        if (gtk_tree_model_get_iter_first(model, &it)) {
            do {
                char *txt = NULL;
                gtk_tree_model_get(model, &it, 0, &txt, -1);
                if (txt && strcmp(txt, guess_type) == 0) {
                    gtk_combo_box_set_active(GTK_COMBO_BOX(ctx->type_combo), i);
                    g_free(txt);
                    break;
                }
                g_free(txt);
                i++;
            } while (gtk_tree_model_iter_next(model, &it));
        }
    }

    gchar *cur_type = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(ctx->type_combo));
    const char **sizes = get_sizes_for_type(cur_type ? cur_type : "OTHER");
    if (cur_type) g_free(cur_type);

    int n = 0;
    while (sizes[n]) n++;
    if (n > 0) {
        int si = closest_size_index_in(sizes, n, d->size_bytes);
        gtk_combo_box_set_active(GTK_COMBO_BOX(ctx->size_combo), si);
    }
}

static void on_disk_refresh(GtkButton *b, gpointer user_data) {
    (void)b;
    populate_disk_combo((add_ctx_t *)user_data);
}

static void on_add_mode_changed(GtkToggleButton *btn, gpointer user_data) {
    add_ctx_t *ctx = user_data;
    if (!gtk_toggle_button_get_active(btn)) return;
    gboolean auto_mode = (btn == GTK_TOGGLE_BUTTON(ctx->radio_auto));
    gtk_widget_set_sensitive(ctx->disk_combo, auto_mode);
    gtk_widget_set_sensitive(ctx->refresh_btn, auto_mode);
    gtk_widget_set_sensitive(ctx->size_combo, !auto_mode);
    if (auto_mode)
        on_disk_combo_changed(GTK_COMBO_BOX(ctx->disk_combo), ctx);
}

static void on_add_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;

    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("add_entry"), g_app.window,
        GTK_DIALOG_MODAL,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("create"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 520, 600);
    install_dialog_title(GTK_WINDOW(dlg), i18n("add_entry"));

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 12);

    add_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    GtkWidget *mode_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    ctx.radio_auto = gtk_radio_button_new_with_label(NULL, i18n("add_auto"));
    ctx.radio_manual = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(ctx.radio_auto), i18n("add_manual"));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ctx.radio_auto), TRUE);
    gtk_box_pack_start(GTK_BOX(mode_box), ctx.radio_auto, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mode_box), ctx.radio_manual, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(content), mode_box, FALSE, FALSE, 0);

    GtkWidget *disk_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    ctx.disk_combo = gtk_combo_box_text_new();
    gtk_widget_set_hexpand(ctx.disk_combo, TRUE);
    gtk_box_pack_start(GTK_BOX(disk_row), ctx.disk_combo, TRUE, TRUE, 0);

    ctx.refresh_btn = gtk_button_new_from_icon_name("view-refresh-symbolic",
        GTK_ICON_SIZE_BUTTON);
    gtk_box_pack_start(GTK_BOX(disk_row), ctx.refresh_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(content), disk_row, FALSE, FALSE, 0);

    ctx.uuid_label = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx.uuid_label), "dim-label");
    gtk_label_set_xalign(GTK_LABEL(ctx.uuid_label), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(ctx.uuid_label), PANGO_ELLIPSIZE_MIDDLE);
    gtk_box_pack_start(GTK_BOX(content), ctx.uuid_label, FALSE, FALSE, 0);

    GtkGrid *grid = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(grid, 12);
    gtk_grid_set_row_spacing(grid, 10);
    gtk_widget_set_hexpand(GTK_WIDGET(grid), TRUE);
    gtk_box_pack_start(GTK_BOX(content), GTK_WIDGET(grid), TRUE, TRUE, 0);

    int row = 0;
    gtk_grid_attach(grid, gtk_label_new(i18n("alias")), 0, row, 1, 1);
    GtkWidget *valias = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(valias), i18n("alias_placeholder"));
    gtk_widget_set_hexpand(valias, TRUE);
    gtk_grid_attach(grid, valias, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("media_type")), 0, row, 1, 1);
    ctx.type_combo = gtk_combo_box_text_new();
    for (int i = 0; i < TYPE_MAP_N; i++)
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ctx.type_combo), TYPE_MAP[i].name);
    gtk_combo_box_set_active(GTK_COMBO_BOX(ctx.type_combo), 0);
    gtk_widget_set_hexpand(ctx.type_combo, TRUE);
    gtk_grid_attach(grid, ctx.type_combo, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("size")), 0, row, 1, 1);
    ctx.size_combo = gtk_combo_box_text_new();
    gtk_widget_set_hexpand(ctx.size_combo, TRUE);
    gtk_grid_attach(grid, ctx.size_combo, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("cipher")), 0, row, 1, 1);
    GtkWidget *vci = gtk_combo_box_text_new();
    for (int i = 0; i < CIPHER_MAP_N; i++)
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(vci), CIPHER_MAP[i].name);
    gtk_combo_box_set_active(GTK_COMBO_BOX(vci), 0);
    gtk_widget_set_hexpand(vci, TRUE);
    gtk_grid_attach(grid, vci, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("password")), 0, row, 1, 1);
    GtkWidget *vdp = NULL;
    GtkWidget *ph = make_password_field(&vdp);
    gtk_grid_attach(grid, ph, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("tag_min")), 0, row, 1, 1);
    GtkWidget *vt = gtk_entry_new(); gtk_widget_set_hexpand(vt, TRUE);
    gtk_grid_attach(grid, vt, 1, row++, 1, 1);

    gtk_grid_attach(grid, gtk_label_new(i18n("salt")), 0, row, 1, 1);
    char *salt_str = generate_salt(2);
    GtkWidget *vd = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(vd), salt_str);
    gtk_editable_set_editable(GTK_EDITABLE(vd), FALSE);
    gtk_widget_set_hexpand(vd, TRUE);
    gtk_grid_attach(grid, vd, 1, row++, 1, 1);
    free(salt_str);

    gtk_grid_attach(grid, gtk_label_new(i18n("notes")), 0, row, 1, 1);
    GtkWidget *nt = gtk_text_view_new(); gtk_widget_set_size_request(nt, -1, 60);
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sw), nt); gtk_widget_set_hexpand(sw, TRUE);
    gtk_grid_attach(grid, sw, 1, row++, 1, 1);

    const char **sizes = get_sizes_for_type(TYPE_MAP[0].name);
    for (int i = 0; sizes[i]; i++)
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ctx.size_combo), sizes[i]);
    gtk_combo_box_set_active(GTK_COMBO_BOX(ctx.size_combo), 0);

    g_signal_connect(ctx.type_combo, "changed", G_CALLBACK(on_add_type_changed), ctx.size_combo);
    g_signal_connect(ctx.radio_auto, "toggled", G_CALLBACK(on_add_mode_changed), &ctx);
    g_signal_connect(ctx.radio_manual, "toggled", G_CALLBACK(on_add_mode_changed), &ctx);
    g_signal_connect(ctx.disk_combo, "changed", G_CALLBACK(on_disk_combo_changed), &ctx);
    g_signal_connect(ctx.refresh_btn, "clicked", G_CALLBACK(on_disk_refresh), &ctx);

    populate_disk_combo(&ctx);
    on_add_mode_changed(GTK_TOGGLE_BUTTON(ctx.radio_auto), &ctx);

    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *tag_str = gtk_entry_get_text(GTK_ENTRY(vt));
        if (strlen(tag_str) < 2) {
            gtk_widget_destroy(dlg);
            free_disk_list(ctx.disks, ctx.disk_count);
            return;
        }
        char tag_val[3] = {
            toupper((unsigned char)tag_str[0]),
            toupper((unsigned char)tag_str[1]),
            '\0'
        };
        gchar *type_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(ctx.type_combo));
        gchar *size_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(ctx.size_combo));
        gchar *cipher_val = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(vci));
        const char *dpass_val = gtk_entry_get_text(GTK_ENTRY(vdp));
        const char *dsalt_val = gtk_entry_get_text(GTK_ENTRY(vd));
        GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(nt));
        GtkTextIter start, end;
        gtk_text_buffer_get_start_iter(buf, &start);
        gtk_text_buffer_get_end_iter(buf, &end);
        char *notes_val = gtk_text_buffer_get_text(buf, &start, &end, FALSE);
        const char *actual_dpass = (strcmp(cipher_val, "NONE") == 0) ? "" : dpass_val;
        const char *alias_val = gtk_entry_get_text(GTK_ENTRY(valias));

        const char *uuid_to_save = NULL;
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ctx.radio_auto)) &&
            ctx.disk_count > 0) {
            const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(ctx.disk_combo));
            if (id) {
                int di = atoi(id);
                if (di >= 0 && di < ctx.disk_count)
                    uuid_to_save = ctx.disks[di].uuid;
            }
        }

        char err_buf[256] = "";
        char *label = db_encode_label(g_app.db, type_val, size_val, tag_val, cipher_val, dsalt_val);

        if (db_add_entry(g_app.db, type_val, size_val, cipher_val, tag_val,
                dsalt_val, tag_str, actual_dpass, notes_val, alias_val,
                uuid_to_save, err_buf, sizeof(err_buf)) == 0) {
            clipboard_copy_secure(label);
            refresh_entry_list();
        } else {
            show_save_error(err_buf);
        }

        free(label);
        g_free(notes_val);
        g_free(type_val);
        g_free(size_val);
        g_free(cipher_val);
    }

    gtk_widget_destroy(dlg);
    free_disk_list(ctx.disks, ctx.disk_count);
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
    gtk_window_set_default_size(GTK_WINDOW(dlg), 460, 360);
    install_dialog_title(GTK_WINDOW(dlg), i18n("edit_entry"));
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
    GtkWidget *vdp = NULL;
    GtkWidget *ph = make_password_field(&vdp);
    if (e->dpass) gtk_entry_set_text(GTK_ENTRY(vdp), e->dpass);
    gtk_grid_attach(GTK_GRID(grid), ph, 1, 2, 1, 1);
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
        if (db_update_entry(g_app.db, e->label, new_dpass, new_notes, new_alias, err_buf, sizeof(err_buf)) != 0) {
            show_save_error(err_buf);
        } else {
            g_app.current_entry_idx = -1;
            refresh_entry_list();
            GtkListBoxRow *new_row = gtk_list_box_get_row_at_index(g_app.listbox, idx);
            if (new_row) gtk_list_box_select_row(g_app.listbox, new_row);
            show_entry_details(idx);
        }
        g_free(new_notes);
    }
    gtk_widget_destroy(dlg);
}

static void on_schema_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("schema_title"), g_app.window, GTK_DIALOG_MODAL, i18n("close"), GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 460, 440);
    install_dialog_title(GTK_WINDOW(dlg), i18n("schema_title"));
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
        char btxt[32]; snprintf(btxt, sizeof(btxt), "%d", i+1);
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

static void on_attach_snapshot_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;
    GtkListBoxRow *row = gtk_list_box_get_selected_row(g_app.listbox);
    if (!row) return;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "entry_idx"));
    if (idx < 0 || idx >= g_app.db->entry_count) return;
    db_entry_t *e = &g_app.db->entries[idx];

    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        i18n("snapshot_title"), g_app.window, GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("scan"), GTK_RESPONSE_OK, NULL);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        gchar *folder = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));

        GtkWidget *wait = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
            GTK_MESSAGE_INFO, GTK_BUTTONS_NONE, "%s", i18n("scanning"));
        gtk_widget_show_all(wait);
        while (gtk_events_pending()) gtk_main_iteration();

        char *files = scan_directory_recursive(folder);
        char *smart_json = collect_smart_data(folder);
        gtk_widget_destroy(wait);

        char err_buf[256] = "";
        if (db_set_entry_snapshot(g_app.db, e->label, files, smart_json, err_buf, sizeof(err_buf)) == 0) {
            char msg[512];
            char health_buf[32] = "";
            if (smart_json) {
                cJSON *s = cJSON_Parse(smart_json);
                if (s) {
                    cJSON *h = cJSON_GetObjectItem(s, "health");
                    if (h && cJSON_IsString(h))
                        snprintf(health_buf, sizeof(health_buf), "%s", h->valuestring);
                    cJSON_Delete(s);
                }
            }
            if (health_buf[0])
                snprintf(msg, sizeof(msg), "%s: %d · SMART %s",
                    i18n("indexed_files"), count_lines(files), health_buf);
            else
                snprintf(msg, sizeof(msg), "%s: %d · %s",
                    i18n("indexed_files"), count_lines(files),
                    i18n("smart_unavailable"));

            if (!e->uuid || !e->uuid[0]) {
                char *detected = get_uuid_for_path(folder);
                if (detected && detected[0]) {
                    free(e->uuid);
                    e->uuid = xstrdup(detected);
                    db_save(g_app.db, err_buf, sizeof(err_buf));
                }
                free(detected);
            }

            GtkWidget *info = gtk_message_dialog_new(g_app.window, GTK_DIALOG_MODAL,
                GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", msg);
            gtk_dialog_run(GTK_DIALOG(info));
            gtk_widget_destroy(info);
        } else {
            show_save_error(err_buf);
        }
        g_free(files);
        g_free(smart_json);
        g_free(folder);
        g_app.current_entry_idx = -1;
        refresh_entry_list();
        GtkListBoxRow *new_row = gtk_list_box_get_row_at_index(g_app.listbox, idx);
        if (new_row) gtk_list_box_select_row(g_app.listbox, new_row);
    }
    gtk_widget_destroy(dlg);
}

static gboolean block_close(GtkWidget *w, GdkEvent *e, gpointer u) {
    (void)w; (void)e; (void)u;
    return TRUE;
}

static void on_batch_reindex_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;

    int total_done = 0;
    int total_skip = 0;
    int total_err = 0;

    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("batch_title"),
        g_app.window, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        i18n("close"), GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 460, 200);
    install_dialog_title(GTK_WINDOW(dlg), i18n("batch_title"));

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 12);

    GtkWidget *prog = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(prog), TRUE);
    gtk_box_pack_start(GTK_BOX(content), prog, FALSE, FALSE, 0);

    GtkWidget *lbl = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_END);
    gtk_box_pack_start(GTK_BOX(content), lbl, FALSE, FALSE, 0);

    gtk_widget_show_all(dlg);

    g_signal_connect(dlg, "delete-event", G_CALLBACK(block_close), NULL);

    int total = 0;
    for (int i = 0; i < g_app.db->entry_count; i++)
        if (g_app.db->entries[i].uuid && g_app.db->entries[i].uuid[0]) total++;

    if (total == 0) {
        gtk_label_set_text(GTK_LABEL(lbl), i18n("no_connected"));
        g_signal_handlers_disconnect_by_func(dlg, block_close, NULL);
        gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
        return;
    }

    g_batch_running = TRUE;
    reset_autolock();

    int nd = 0;
    disk_info_t *disks = list_disks(&nd);

    int step = 0;
    for (int i = 0; i < g_app.db->entry_count; i++) {
        db_entry_t *e = &g_app.db->entries[i];
        if (!e->uuid || !e->uuid[0]) continue;

        step++;
        double frac = (double)(step - 1) / (double)total;
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(prog), frac);
        char pbuf[64];
        snprintf(pbuf, sizeof(pbuf), i18n("batch_progress"), step, total);
        gtk_progress_bar_set_text(GTK_PROGRESS_BAR(prog), pbuf);
        gtk_label_set_text(GTK_LABEL(lbl),
            (e->alias && e->alias[0]) ? e->alias : e->label);
        while (gtk_events_pending()) gtk_main_iteration();
        reset_autolock();

        const char *mp = NULL;
        for (int k = 0; k < nd; k++) {
            if (disks[k].uuid && strcmp(disks[k].uuid, e->uuid) == 0 &&
                disks[k].mountpoint) {
                mp = disks[k].mountpoint;
                break;
            }
        }

        if (!mp) { total_skip++; continue; }

        char *files = scan_directory_recursive(mp);
        char *smart = collect_smart_data(mp);
        char err[256] = "";
        if (db_set_entry_snapshot(g_app.db, e->label, files, smart, err, sizeof(err)) == 0)
            total_done++;
        else
            total_err++;
        g_free(files);
        g_free(smart);
    }

    free_disk_list(disks, nd);
    g_batch_running = FALSE;

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(prog), 1.0);
    char done[128];
    snprintf(done, sizeof(done), i18n("batch_done"), total_done, total_skip, total_err);
    gtk_label_set_text(GTK_LABEL(lbl), done);

    g_app.current_entry_idx = -1;
    refresh_entry_list();

    g_signal_handlers_disconnect_by_func(dlg, block_close, NULL);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static void check_new_disks(void);

static void on_refresh_connections_clicked(GtkButton *b, gpointer u) {
    (void)b; (void)u;
    if (!g_app.db) return;
    int save_idx = g_app.current_entry_idx;
    check_new_disks();
    g_app.current_entry_idx = -1;
    refresh_entry_list();
    if (save_idx >= 0 && save_idx < g_app.db->entry_count) {
        GtkListBoxRow *row = gtk_list_box_get_row_at_index(g_app.listbox, save_idx);
        if (row) gtk_list_box_select_row(g_app.listbox, row);
    }
}

static void on_menu_copy_activate(GtkMenuItem *item, gpointer user_data) {
    (void)user_data;
    const char *text = g_object_get_data(G_OBJECT(item), "text");
    if (text) clipboard_copy_secure(text);
}

static gboolean on_search_file_click(GtkWidget *row, GdkEventButton *ev, gpointer user_data) {
    (void)user_data;
    if (ev->button != 3) return FALSE;
    const char *path = g_object_get_data(G_OBJECT(row), "full_path");
    if (!path) return FALSE;

    GtkWidget *menu = gtk_menu_new();
    GtkWidget *mi1 = gtk_menu_item_new_with_label(i18n("copy_path"));
    g_object_set_data_full(G_OBJECT(mi1), "text", g_strdup(path), g_free);
    g_signal_connect(mi1, "activate", G_CALLBACK(on_menu_copy_activate), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi1);

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    GtkWidget *mi2 = gtk_menu_item_new_with_label(i18n("copy_name"));
    g_object_set_data_full(G_OBJECT(mi2), "text", g_strdup(base), g_free);
    g_signal_connect(mi2, "activate", G_CALLBACK(on_menu_copy_activate), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi2);

    gtk_widget_show_all(menu);
    gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent*)ev);
    return TRUE;
}

static void free_str_list(gpointer p) {
    GList *l = p;
    for (GList *i = l; i; i = i->next) g_free(i->data);
    g_list_free(l);
}

static GHashTable *build_cross_disk_index(db_manager_t *db) {
    GHashTable *h = g_hash_table_new_full(g_str_hash, g_str_equal,
        g_free, free_str_list);
    for (int i = 0; i < db->entry_count; i++) {
        db_entry_t *e = &db->entries[i];
        if (!e->files || !e->files[0]) continue;
        const char *disp = (e->alias && e->alias[0]) ? e->alias : e->label;
        char *copy = strdup(e->files);
        if (!copy) continue;
        char *save = NULL;
        for (char *ln = strtok_r(copy, "\n", &save); ln;
             ln = strtok_r(NULL, "\n", &save)) {
            char *tab = strchr(ln, '\t');
            if (tab) *tab = '\0';
            if (!ln[0]) continue;
            GList *lst = g_hash_table_lookup(h, ln);
            gboolean dup = FALSE;
            for (GList *q = lst; q; q = q->next)
                if (strcmp((char *)q->data, disp) == 0) { dup = TRUE; break; }
            if (dup) continue;
            lst = g_list_append(lst, g_strdup(disp));
            g_hash_table_replace(h, g_strdup(ln), lst);
        }
        free(copy);
    }
    return h;
}

static void on_filter_chip_clicked(GtkToggleButton *btn, gpointer user_data);
static gboolean on_filter_chip_press(GtkWidget *w, GdkEventButton *e, gpointer u);
static void on_filter_add_clicked(GtkButton *b, gpointer u);
static void rebuild_filt_box(GtkBox *fb, GtkSearchEntry *se, db_manager_t *db);

static void on_find_changed(GtkSearchEntry *se, gpointer user_data) {
    (void)user_data;
    GtkListBox *lb = GTK_LIST_BOX(g_object_get_data(G_OBJECT(se), "listbox"));
    db_manager_t *db = g_object_get_data(G_OBJECT(se), "db");
    GtkWidget *status = g_object_get_data(G_OBJECT(se), "status");
    if (!lb || !db) return;

    int fidx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(se), "filter_idx"));
    const char *ext_filter = NULL;
    if (fidx >= 0 && fidx < db->filter_count)
        ext_filter = db->filters[fidx].exts;

    GList *ch = gtk_container_get_children(GTK_CONTAINER(lb));
    for (GList *l = ch; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(ch);

    const char *q = gtk_entry_get_text(GTK_ENTRY(se));
    if (!q[0] && !ext_filter) {
        if (status) {
            int indexed = 0;
            for (int i = 0; i < db->entry_count; i++)
                if (db->entries[i].files && db->entries[i].files[0]) indexed++;
            char buf[128];
            snprintf(buf, sizeof(buf), "%d %s", indexed, i18n("disks_with_index"));
            gtk_label_set_text(GTK_LABEL(status), buf);
        }
        gtk_widget_show_all(GTK_WIDGET(lb));
        return;
    }

    GHashTable *cross_index = NULL;
    if (q[0])
        cross_index = build_cross_disk_index(db);

    char lq[256];
    strncpy(lq, q, sizeof(lq) - 1); lq[sizeof(lq) - 1] = '\0';
    for (char *p = lq; *p; p++) *p = tolower((unsigned char)*p);

    char *exts_lower = NULL;
    if (ext_filter && ext_filter[0])
        exts_lower = g_ascii_strdown(ext_filter, -1);

    int total_files = 0;
    int total_disks = 0;
    const int per_disk_limit = 200;

    for (int i = 0; i < db->entry_count; i++) {
        db_entry_t *e = &db->entries[i];
        if (!e->files || !e->files[0]) continue;

        char *copy = strdup(e->files);
        if (!copy) continue;

        GPtrArray *paths = g_ptr_array_new_with_free_func(g_free);
        GArray *sizes = g_array_new(FALSE, FALSE, sizeof(long long));

        char *save = NULL;
        for (char *line = strtok_r(copy, "\n", &save); line;
             line = strtok_r(NULL, "\n", &save)) {
            if (!line[0]) continue;
            long long sz = -1;
            char *tab = strchr(line, '\t');
            if (tab) { *tab = '\0'; sz = atoll(tab + 1); }
            char low[1024];
            strncpy(low, line, sizeof(low) - 1); low[sizeof(low) - 1] = '\0';
            for (char *p = low; *p; p++) *p = tolower((unsigned char)*p);

            if (lq[0] && !strstr(low, lq)) continue;

            if (exts_lower) {
                const char *dot = strrchr(low, '.');
                if (!dot) continue;
                const char *ext = dot + 1;
                gboolean matched = FALSE;
                char *exts_copy = g_strdup(exts_lower);
                char *save2 = NULL;
                for (char *tok = strtok_r(exts_copy, ",", &save2); tok;
                     tok = strtok_r(NULL, ",", &save2)) {
                    if (strcmp(ext, tok) == 0) { matched = TRUE; break; }
                }
                g_free(exts_copy);
                if (!matched) continue;
            }

            g_ptr_array_add(paths, g_strdup(line));
            g_array_append_val(sizes, sz);
        }
        free(copy);

        if (paths->len == 0) {
            g_ptr_array_free(paths, TRUE);
            g_array_free(sizes, TRUE);
            continue;
        }

        total_disks++;
        total_files += paths->len;

        const char *disp = (e->alias && e->alias[0]) ? e->alias : e->label;

        GtkWidget *hrow = gtk_list_box_row_new();
        gtk_list_box_row_set_selectable(GTK_LIST_BOX_ROW(hrow), FALSE);
        gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(hrow), FALSE);
        gtk_style_context_add_class(gtk_widget_get_style_context(GTK_WIDGET(hrow)), "search-disk-header");

        GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_set_margin_top(hbox, 10);
        gtk_widget_set_margin_bottom(hbox, 6);
        gtk_widget_set_margin_start(hbox, 12);
        gtk_widget_set_margin_end(hbox, 12);

        GtkWidget *hname = gtk_label_new(disp);
        gtk_style_context_add_class(gtk_widget_get_style_context(hname), "disk-header-name");
        gtk_label_set_xalign(GTK_LABEL(hname), 0.0);
        gtk_box_pack_start(GTK_BOX(hbox), hname, FALSE, FALSE, 0);

        char summary[128];
        snprintf(summary, sizeof(summary), "%s · %s · %s",
            e->type ? e->type : "?",
            e->size ? e->size : "?",
            e->cipher ? e->cipher : "?");
        GtkWidget *hsum = gtk_label_new(summary);
        gtk_style_context_add_class(gtk_widget_get_style_context(hsum), "dim-label");
        gtk_label_set_xalign(GTK_LABEL(hsum), 0.0);
        gtk_box_pack_start(GTK_BOX(hbox), hsum, TRUE, TRUE, 0);

        char cntbuf[48];
        snprintf(cntbuf, sizeof(cntbuf), "%d", (int)paths->len);
        GtkWidget *hcnt = gtk_label_new(cntbuf);
        gtk_style_context_add_class(gtk_widget_get_style_context(hcnt), "disk-header-count");
        gtk_box_pack_end(GTK_BOX(hbox), hcnt, FALSE, FALSE, 0);

        gtk_container_add(GTK_CONTAINER(hrow), hbox);
        g_object_set_data(G_OBJECT(hrow), "entry_idx", GINT_TO_POINTER(i));
        gtk_list_box_insert(lb, hrow, -1);

        int show_n = paths->len < per_disk_limit ? (int)paths->len : per_disk_limit;
        for (int k = 0; k < show_n; k++) {
            const char *path = g_ptr_array_index(paths, k);
            long long sz = g_array_index(sizes, long long, k);
            const char *base = strrchr(path, '/');
            base = base ? base + 1 : path;

            GtkWidget *frow = gtk_list_box_row_new();
            gtk_style_context_add_class(gtk_widget_get_style_context(GTK_WIDGET(frow)), "search-file-row");

            GtkWidget *fbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
            gtk_widget_set_margin_top(fbox, 5);
            gtk_widget_set_margin_bottom(fbox, 5);
            gtk_widget_set_margin_start(fbox, 30);
            gtk_widget_set_margin_end(fbox, 12);

            GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
            gtk_widget_set_hexpand(vbox, TRUE);

            GtkWidget *fname = gtk_label_new(base);
            gtk_style_context_add_class(gtk_widget_get_style_context(fname), "file-name");
            gtk_label_set_xalign(GTK_LABEL(fname), 0.0);
            gtk_label_set_ellipsize(GTK_LABEL(fname), PANGO_ELLIPSIZE_END);
            gtk_box_pack_start(GTK_BOX(vbox), fname, FALSE, FALSE, 0);

            char *dirname = g_path_get_dirname(path);
            GtkWidget *fpath = gtk_label_new(dirname);
            gtk_style_context_add_class(gtk_widget_get_style_context(fpath), "file-path");
            gtk_label_set_xalign(GTK_LABEL(fpath), 0.0);
            gtk_label_set_ellipsize(GTK_LABEL(fpath), PANGO_ELLIPSIZE_MIDDLE);
            gtk_box_pack_start(GTK_BOX(vbox), fpath, FALSE, FALSE, 0);
            g_free(dirname);

            if (cross_index) {
                GList *also = g_hash_table_lookup(cross_index, path);
                if (also) {
                    GString *s = g_string_new(i18n("also_on"));
                    g_string_append_c(s, ' ');
                    for (GList *qq = also; qq; qq = qq->next) {
                        if (qq != also) g_string_append(s, ", ");
                        g_string_append(s, (const char *)qq->data);
                    }
                    GtkWidget *ext = gtk_label_new(s->str);
                    g_string_free(s, TRUE);
                    gtk_style_context_add_class(gtk_widget_get_style_context(ext), "also-on");
                    gtk_label_set_xalign(GTK_LABEL(ext), 0.0);
                    gtk_label_set_ellipsize(GTK_LABEL(ext), PANGO_ELLIPSIZE_END);
                    gtk_box_pack_start(GTK_BOX(vbox), ext, FALSE, FALSE, 0);
                }
            }

            gtk_box_pack_start(GTK_BOX(fbox), vbox, TRUE, TRUE, 0);

            char *szstr = format_bytes(sz);
            GtkWidget *fsize = gtk_label_new(szstr);
            gtk_style_context_add_class(gtk_widget_get_style_context(fsize), "file-size");
            gtk_box_pack_end(GTK_BOX(fbox), fsize, FALSE, FALSE, 0);
            g_free(szstr);

            gtk_container_add(GTK_CONTAINER(frow), fbox);

            char *full_path = g_strdup_printf("/%s", path);
            g_object_set_data_full(G_OBJECT(frow), "full_path", full_path, g_free);
            g_object_set_data(G_OBJECT(frow), "entry_idx", GINT_TO_POINTER(i));
            g_signal_connect(frow, "button-press-event", G_CALLBACK(on_search_file_click), NULL);

            gtk_list_box_insert(lb, frow, -1);
        }

        if ((int)paths->len > per_disk_limit) {
            char more[64];
            snprintf(more, sizeof(more), "+ %d...", (int)paths->len - per_disk_limit);
            GtkWidget *mrow = gtk_list_box_row_new();
            gtk_list_box_row_set_selectable(GTK_LIST_BOX_ROW(mrow), FALSE);
            gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(mrow), FALSE);
            GtkWidget *mlbl = gtk_label_new(more);
            gtk_style_context_add_class(gtk_widget_get_style_context(mlbl), "dim-label");
            gtk_widget_set_margin_start(mlbl, 40);
            gtk_widget_set_margin_top(mlbl, 3);
            gtk_widget_set_margin_bottom(mlbl, 6);
            gtk_label_set_xalign(GTK_LABEL(mlbl), 0.0);
            gtk_container_add(GTK_CONTAINER(mrow), mlbl);
            gtk_list_box_insert(lb, mrow, -1);
        }

        g_ptr_array_free(paths, TRUE);
        g_array_free(sizes, TRUE);
    }

    if (exts_lower) g_free(exts_lower);
    if (cross_index) g_hash_table_destroy(cross_index);

    if (status) {
        if (total_files == 0) {
            gtk_label_set_text(GTK_LABEL(status), i18n("no_results"));
        } else {
            char buf[128];
            snprintf(buf, sizeof(buf), "%d %s · %d %s",
                total_files, i18n("files_found"), total_disks, i18n("disks_found"));
            gtk_label_set_text(GTK_LABEL(status), buf);
        }
    }
    gtk_widget_show_all(GTK_WIDGET(lb));
}

static void rebuild_filt_box(GtkBox *filt_box, GtkSearchEntry *se, db_manager_t *db) {
    GList *ch = gtk_container_get_children(GTK_CONTAINER(filt_box));
    for (GList *l = ch; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(ch);

    int active_idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(se), "filter_idx"));

    GtkWidget *star = gtk_toggle_button_new_with_label("*");
    gtk_style_context_add_class(gtk_widget_get_style_context(star), "filter-chip");
    g_object_set_data(G_OBJECT(star), "filter_idx", GINT_TO_POINTER(-1));
    g_signal_connect(star, "clicked", G_CALLBACK(on_filter_chip_clicked), se);
    if (active_idx < 0) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(star), TRUE);
    gtk_box_pack_start(GTK_BOX(filt_box), star, FALSE, FALSE, 0);

    for (int i = 0; i < db->filter_count; i++) {
        GtkWidget *b = gtk_toggle_button_new_with_label(db->filters[i].name);
        gtk_style_context_add_class(gtk_widget_get_style_context(b), "filter-chip");
        g_object_set_data(G_OBJECT(b), "filter_idx", GINT_TO_POINTER(i));
        g_signal_connect(b, "clicked", G_CALLBACK(on_filter_chip_clicked), se);
        g_signal_connect(b, "button-press-event", G_CALLBACK(on_filter_chip_press), se);
        if (i == active_idx) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(b), TRUE);
        gtk_box_pack_start(GTK_BOX(filt_box), b, FALSE, FALSE, 0);
    }

    GtkWidget *add_btn = gtk_button_new_with_label("+");
    gtk_style_context_add_class(gtk_widget_get_style_context(add_btn), "filter-chip");
    g_signal_connect(add_btn, "clicked", G_CALLBACK(on_filter_add_clicked), se);
    gtk_box_pack_start(GTK_BOX(filt_box), add_btn, FALSE, FALSE, 0);

    gtk_widget_show_all(GTK_WIDGET(filt_box));
}

static void on_filter_chip_clicked(GtkToggleButton *btn, gpointer user_data) {
    GtkSearchEntry *se = GTK_SEARCH_ENTRY(user_data);
    GtkWidget *filt_box = g_object_get_data(G_OBJECT(se), "filt_box");

    gboolean want_active = gtk_toggle_button_get_active(btn);

    GList *ch = gtk_container_get_children(GTK_CONTAINER(filt_box));
    for (GList *l = ch; l; l = l->next) {
        GtkWidget *w = l->data;
        if (w == GTK_WIDGET(btn)) continue;
        if (GTK_IS_TOGGLE_BUTTON(w)) {
            g_signal_handlers_block_by_func(w, on_filter_chip_clicked, user_data);
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), FALSE);
            g_signal_handlers_unblock_by_func(w, on_filter_chip_clicked, user_data);
        }
    }
    g_list_free(ch);

    int idx = -1;
    if (want_active)
        idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(btn), "filter_idx"));
    g_object_set_data(G_OBJECT(se), "filter_idx", GINT_TO_POINTER(idx));

    on_find_changed(se, NULL);
}

static void on_filter_delete_activate(GtkMenuItem *mi, gpointer user_data) {
    GtkSearchEntry *se = GTK_SEARCH_ENTRY(user_data);
    db_manager_t *db = g_object_get_data(G_OBJECT(se), "db");
    GtkWidget *filt_box = g_object_get_data(G_OBJECT(se), "filt_box");
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(mi), "filter_idx"));
    if (!db || idx < 0 || idx >= db->filter_count) return;

    free(db->filters[idx].name);
    free(db->filters[idx].exts);
    memmove(&db->filters[idx], &db->filters[idx+1],
        (db->filter_count - idx - 1) * sizeof(search_filter_t));
    db->filter_count--;

    char err_buf[256] = "";
    db_save(db, err_buf, sizeof(err_buf));

    int active = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(se), "filter_idx"));
    if (active == idx) {
        g_object_set_data(G_OBJECT(se), "filter_idx", GINT_TO_POINTER(-1));
    } else if (active > idx) {
        g_object_set_data(G_OBJECT(se), "filter_idx", GINT_TO_POINTER(active - 1));
    }

    rebuild_filt_box(GTK_BOX(filt_box), se, db);
    on_find_changed(se, NULL);
}

static gboolean on_filter_chip_press(GtkWidget *w, GdkEventButton *ev, gpointer user_data) {
    if (ev->button != 3) return FALSE;
    int idx = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(w), "filter_idx"));
    if (idx < 0) return TRUE;

    GtkWidget *menu = gtk_menu_new();
    GtkWidget *mi = gtk_menu_item_new_with_label(i18n("filter_delete"));
    g_object_set_data(G_OBJECT(mi), "filter_idx", GINT_TO_POINTER(idx));
    g_signal_connect(mi, "activate", G_CALLBACK(on_filter_delete_activate), user_data);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);
    gtk_widget_show_all(menu);
    gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent*)ev);
    return TRUE;
}

static void on_filter_add_clicked(GtkButton *b, gpointer user_data) {
    (void)b;
    GtkSearchEntry *se = GTK_SEARCH_ENTRY(user_data);
    db_manager_t *db = g_object_get_data(G_OBJECT(se), "db");
    if (!db) return;

    GtkWidget *top = gtk_widget_get_toplevel(GTK_WIDGET(se));
    GtkWidget *dlg = gtk_dialog_new_with_buttons(i18n("filter_add"),
        GTK_IS_WINDOW(top) ? GTK_WINDOW(top) : NULL,
        GTK_DIALOG_MODAL,
        i18n("cancel"), GTK_RESPONSE_CANCEL,
        i18n("save"), GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 380, 200);
    install_dialog_title(GTK_WINDOW(dlg), i18n("filter_add"));

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 15);
    gtk_box_set_spacing(GTK_BOX(content), 10);

    GtkGrid *g = GTK_GRID(gtk_grid_new());
    gtk_grid_set_column_spacing(g, 10);
    gtk_grid_set_row_spacing(g, 10);

    gtk_grid_attach(g, gtk_label_new(i18n("filter_name")), 0, 0, 1, 1);
    GtkWidget *name_e = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(name_e), "PDF");
    gtk_widget_set_hexpand(name_e, TRUE);
    gtk_grid_attach(g, name_e, 1, 0, 1, 1);

    gtk_grid_attach(g, gtk_label_new(i18n("filter_exts")), 0, 1, 1, 1);
    GtkWidget *exts_e = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(exts_e), "pdf,doc,docx");
    gtk_widget_set_hexpand(exts_e, TRUE);
    gtk_grid_attach(g, exts_e, 1, 1, 1, 1);

    gtk_box_pack_start(GTK_BOX(content), GTK_WIDGET(g), TRUE, TRUE, 0);
    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *nm = gtk_entry_get_text(GTK_ENTRY(name_e));
        const char *ex = gtk_entry_get_text(GTK_ENTRY(exts_e));
        if (nm && nm[0] && ex && ex[0]) {
            if (db->filter_count >= db->filter_cap) {
                db->filter_cap = db->filter_cap ? db->filter_cap * 2 : 8;
                db->filters = realloc(db->filters, db->filter_cap * sizeof(search_filter_t));
            }
            db->filters[db->filter_count].name = xstrdup(nm);
            db->filters[db->filter_count].exts = xstrdup(ex);
            db->filter_count++;
            char err_buf[256] = "";
            db_save(db, err_buf, sizeof(err_buf));

            GtkWidget *filt_box = g_object_get_data(G_OBJECT(se), "filt_box");
            rebuild_filt_box(GTK_BOX(filt_box), se, db);
        }
    }
    gtk_widget_destroy(dlg);
}

static void on_find_file_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn; (void)user_data;
    if (!g_app.db) return;

    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        i18n("find_title"), g_app.window, GTK_DIALOG_MODAL,
        i18n("close"), GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 780, 620);
    install_dialog_title(GTK_WINDOW(dlg), i18n("find_title"));

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(content), 12);
    gtk_box_set_spacing(GTK_BOX(content), 8);

    GtkWidget *se = gtk_search_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(se), i18n("find_hint"));
    gtk_box_pack_start(GTK_BOX(content), se, FALSE, FALSE, 0);

    GtkWidget *filt_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(filt_scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_NEVER);
    gtk_widget_set_size_request(filt_scroll, -1, 38);

    GtkWidget *filt_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_style_context_add_class(gtk_widget_get_style_context(filt_box), "search-filters");
    gtk_container_add(GTK_CONTAINER(filt_scroll), filt_box);
    gtk_box_pack_start(GTK_BOX(content), filt_scroll, FALSE, FALSE, 0);

    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(sw, TRUE);
    GtkWidget *lb = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(lb), GTK_SELECTION_NONE);
    gtk_container_add(GTK_CONTAINER(sw), lb);
    gtk_box_pack_start(GTK_BOX(content), sw, TRUE, TRUE, 0);

    GtkWidget *status_lbl = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(status_lbl), "dim-label");
    gtk_label_set_xalign(GTK_LABEL(status_lbl), 0.0);
    gtk_box_pack_start(GTK_BOX(content), status_lbl, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(se), "listbox", lb);
    g_object_set_data(G_OBJECT(se), "db", g_app.db);
    g_object_set_data(G_OBJECT(se), "status", status_lbl);
    g_object_set_data(G_OBJECT(se), "filt_box", filt_box);
    g_object_set_data(G_OBJECT(se), "filter_idx", GINT_TO_POINTER(-1));
    g_signal_connect(se, "search-changed", G_CALLBACK(on_find_changed), NULL);

    rebuild_filt_box(GTK_BOX(filt_box), GTK_SEARCH_ENTRY(se), g_app.db);

    int indexed = 0;
    for (int i = 0; i < g_app.db->entry_count; i++)
        if (g_app.db->entries[i].files && g_app.db->entries[i].files[0]) indexed++;
    if (indexed == 0) {
        gtk_label_set_text(GTK_LABEL(status_lbl), i18n("empty_index"));
    } else {
        char buf[128];
        snprintf(buf, sizeof(buf), "%d %s", indexed, i18n("disks_with_index"));
        gtk_label_set_text(GTK_LABEL(status_lbl), buf);
    }

    gtk_widget_show_all(dlg);
    gtk_widget_grab_focus(se);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static void on_lang_changed_welcome(GtkComboBoxText *combo, gpointer user_data) {
    (void)user_data;
    gchar *id = (gchar*)gtk_combo_box_get_active_id(GTK_COMBO_BOX(combo));
    if (id && strcmp(id, g_lang) != 0) {
        snprintf(g_lang, sizeof(g_lang), "%s", id);
        if (g_app.lang_combo)
            gtk_combo_box_set_active_id(GTK_COMBO_BOX(g_app.lang_combo), g_lang);
        update_ui_text();
        save_config();
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

static gboolean toast_hide_cb(gpointer u) {
    (void)u;
    if (g_app.toast_revealer)
        gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), FALSE);
    g_toast_timer_id = 0;
    return G_SOURCE_REMOVE;
}

static void show_toast(const char *text, int duration_ms, int entry_idx) {
    if (!g_app.toast_revealer || !g_app.toast_label) return;
    g_app.toast_entry_idx = entry_idx;
    gtk_label_set_text(GTK_LABEL(g_app.toast_label), text);
    gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), TRUE);
    if (g_toast_timer_id) g_source_remove(g_toast_timer_id);
    g_toast_timer_id = g_timeout_add(duration_ms, toast_hide_cb, NULL);
}

static gboolean on_toast_clicked(GtkButton *b, gpointer u) {
    (void)b; (void)u;
    int idx = g_app.toast_entry_idx;
    if (g_app.toast_revealer)
        gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), FALSE);
    if (idx >= 0 && g_app.db && idx < g_app.db->entry_count) {
        GtkListBoxRow *row = gtk_list_box_get_row_at_index(g_app.listbox, idx);
        if (row) {
            gtk_list_box_select_row(g_app.listbox, row);
            gtk_widget_grab_focus(GTK_WIDGET(g_app.listbox));
        }
    }
    return TRUE;
}

static void check_new_disks(void) {
    if (!g_app.db) return;
    int n = 0;
    disk_info_t *disks = list_disks(&n);
    if (!disks) return;

    if (!g_known_uuids)
        g_known_uuids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    for (int i = 0; i < n; i++) {
        if (!disks[i].uuid) continue;
        if (g_hash_table_contains(g_known_uuids, disks[i].uuid)) continue;
        g_hash_table_add(g_known_uuids, g_strdup(disks[i].uuid));

        if (!g_uuids_initialized) continue;

        for (int j = 0; j < g_app.db->entry_count; j++) {
            db_entry_t *e = &g_app.db->entries[j];
            if (e->uuid && strcmp(e->uuid, disks[i].uuid) == 0) {
                char msg[512];
                const char *disp = (e->alias && e->alias[0]) ? e->alias : e->label;
                snprintf(msg, sizeof(msg), "%s — %s  ·  %s",
                    i18n("disk_detected"), disp,
                    disks[i].mountpoint ? disks[i].mountpoint : "?");
                show_toast(msg, 8000, j);
                break;
            }
        }
    }
    free_disk_list(disks, n);
    g_uuids_initialized = TRUE;
}

static gboolean connection_check_cb(gpointer user_data) {
    (void)user_data;
    check_new_disks();
    return G_SOURCE_CONTINUE;
}

static void build_main(void) {
    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_style_context_add_class(gtk_widget_get_style_context(toolbar), "main-toolbar");
    gtk_widget_set_margin_top(toolbar, 4); gtk_widget_set_margin_bottom(toolbar, 4);
    gtk_widget_set_margin_start(toolbar, 6); gtk_widget_set_margin_end(toolbar, 6);

    g_app.btn_lock = gtk_button_new_from_icon_name("changes-prevent-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_lock), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_lock, i18n("lock_db"));
    g_signal_connect(g_app.btn_lock, "clicked", G_CALLBACK(on_lock_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_lock, FALSE, FALSE, 0);

    GtkWidget *sep1 = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
    gtk_widget_set_margin_start(sep1, 4); gtk_widget_set_margin_end(sep1, 4);
    gtk_box_pack_start(GTK_BOX(toolbar), sep1, FALSE, FALSE, 0);

    g_app.btn_add = gtk_button_new_from_icon_name("list-add-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_add), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_add, i18n("add_entry"));
    g_signal_connect(g_app.btn_add, "clicked", G_CALLBACK(on_add_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_add, FALSE, FALSE, 0);

    g_app.btn_edit = gtk_button_new_from_icon_name("document-edit-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_edit), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_edit, i18n("edit_entry"));
    g_signal_connect(g_app.btn_edit, "clicked", G_CALLBACK(on_edit_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_edit, FALSE, FALSE, 0);

    g_app.btn_del = gtk_button_new_from_icon_name("edit-delete-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_del), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_del, i18n("del_entry"));
    g_signal_connect(g_app.btn_del, "clicked", G_CALLBACK(on_delete_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_del, FALSE, FALSE, 0);

    GtkWidget *sep2 = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
    gtk_widget_set_margin_start(sep2, 4); gtk_widget_set_margin_end(sep2, 4);
    gtk_box_pack_start(GTK_BOX(toolbar), sep2, FALSE, FALSE, 0);

    g_app.btn_snapshot = gtk_button_new_from_icon_name("drive-harddisk-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_snapshot), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_snapshot, i18n("snapshot_btn"));
    g_signal_connect(g_app.btn_snapshot, "clicked", G_CALLBACK(on_attach_snapshot_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_snapshot, FALSE, FALSE, 0);

    g_app.btn_find = gtk_button_new_from_icon_name("system-search-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_find), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_find, i18n("find_btn"));
    g_signal_connect(g_app.btn_find, "clicked", G_CALLBACK(on_find_file_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_find, FALSE, FALSE, 0);

    g_app.btn_batch = gtk_button_new_from_icon_name("view-refresh-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_batch), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_batch, i18n("batch_reindex"));
    g_signal_connect(g_app.btn_batch, "clicked", G_CALLBACK(on_batch_reindex_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_batch, FALSE, FALSE, 0);

    g_app.btn_refresh = gtk_button_new_from_icon_name("emblem-synchronizing-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_refresh), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_refresh, i18n("refresh_connections"));
    g_signal_connect(g_app.btn_refresh, "clicked", G_CALLBACK(on_refresh_connections_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.btn_refresh, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(toolbar), gtk_label_new(""), TRUE, TRUE, 0);

    g_app.btn_sch = gtk_button_new_from_icon_name("dialog-information-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_sch), "flat-btn");
    gtk_widget_set_tooltip_text(g_app.btn_sch, i18n("show_schema"));
    g_signal_connect(g_app.btn_sch, "clicked", G_CALLBACK(on_schema_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(toolbar), g_app.btn_sch, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(main_box), toolbar, FALSE, FALSE, 0);

    g_app.toast_revealer = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(g_app.toast_revealer),
        GTK_REVEALER_TRANSITION_TYPE_SLIDE_DOWN);
    gtk_revealer_set_transition_duration(GTK_REVEALER(g_app.toast_revealer), 250);
    gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), FALSE);

    GtkWidget *toast_btn = gtk_button_new();
    gtk_button_set_relief(GTK_BUTTON(toast_btn), GTK_RELIEF_NONE);
    gtk_style_context_add_class(gtk_widget_get_style_context(toast_btn), "toast");

    g_app.toast_label = gtk_label_new("");
    gtk_label_set_ellipsize(GTK_LABEL(g_app.toast_label), PANGO_ELLIPSIZE_END);
    gtk_label_set_xalign(GTK_LABEL(g_app.toast_label), 0.0);
    gtk_widget_set_margin_start(g_app.toast_label, 12);
    gtk_widget_set_margin_end(g_app.toast_label, 12);
    gtk_widget_set_margin_top(g_app.toast_label, 8);
    gtk_widget_set_margin_bottom(g_app.toast_label, 8);
    gtk_container_add(GTK_CONTAINER(toast_btn), g_app.toast_label);

    g_signal_connect(toast_btn, "clicked", G_CALLBACK(on_toast_clicked), NULL);
    gtk_container_add(GTK_CONTAINER(g_app.toast_revealer), toast_btn);

    gtk_box_pack_start(GTK_BOX(main_box), g_app.toast_revealer, FALSE, FALSE, 0);

    g_app.toast_entry_idx = -1;

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(paned), 300);
    gtk_paned_set_wide_handle(GTK_PANED(paned), FALSE);

    GtkWidget *left_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *search_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(search_box), "sidebar");
    gtk_widget_set_margin_top(search_box, 8); gtk_widget_set_margin_bottom(search_box, 8);
    gtk_widget_set_margin_start(search_box, 8); gtk_widget_set_margin_end(search_box, 8);
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
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(detail_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(detail_scroll, TRUE);
    g_app.detail_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(g_app.detail_box, 16); gtk_widget_set_margin_bottom(g_app.detail_box, 16);
    gtk_widget_set_margin_start(g_app.detail_box, 20); gtk_widget_set_margin_end(g_app.detail_box, 20);
    gtk_widget_set_valign(g_app.detail_box, GTK_ALIGN_START);

    GtkWidget *top_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    g_app.lbl_main = gtk_label_new(i18n("select_entry"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.lbl_main), "detail-title");
    gtk_label_set_xalign(GTK_LABEL(g_app.lbl_main), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(g_app.lbl_main), PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_set_hexpand(g_app.lbl_main, TRUE);
    gtk_box_pack_start(GTK_BOX(top_box), g_app.lbl_main, TRUE, TRUE, 0);
    g_app.btn_copy_label = gtk_button_new_with_label(i18n("copy_label"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_copy_label), "flat-btn");
    gtk_widget_set_sensitive(g_app.btn_copy_label, FALSE);
    g_signal_connect(g_app.btn_copy_label, "clicked", G_CALLBACK(on_copy_label_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(top_box), g_app.btn_copy_label, FALSE, FALSE, 0);
    g_app.btn_copy_pass = gtk_button_new_with_label(i18n("copy_pass"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.btn_copy_pass), "flat-btn");
    gtk_widget_set_sensitive(g_app.btn_copy_pass, FALSE);
    g_signal_connect(g_app.btn_copy_pass, "clicked", G_CALLBACK(on_copy_pass_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(top_box), g_app.btn_copy_pass, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), top_box, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(g_app.detail_box),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);

    g_app.grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(g_app.grid), 16);
    gtk_grid_set_row_spacing(GTK_GRID(g_app.grid), 6);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.grid, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(g_app.detail_box),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);

    GtkWidget *tree_header_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    g_app.tree_summary = gtk_label_new(i18n("no_index_yet"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.tree_summary), "tree-header");
    gtk_label_set_xalign(GTK_LABEL(g_app.tree_summary), 0.0);
    gtk_widget_set_hexpand(g_app.tree_summary, TRUE);
    gtk_box_pack_start(GTK_BOX(tree_header_box), g_app.tree_summary, TRUE, TRUE, 0);

    g_app.tree_expand_btn = gtk_button_new_from_icon_name("zoom-in-symbolic", GTK_ICON_SIZE_MENU);
    gtk_widget_set_tooltip_text(g_app.tree_expand_btn, "Expand");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.tree_expand_btn), "flat-btn");
    g_signal_connect(g_app.tree_expand_btn, "clicked", G_CALLBACK(on_tree_expand_all), NULL);
    gtk_box_pack_end(GTK_BOX(tree_header_box), g_app.tree_expand_btn, FALSE, FALSE, 0);

    g_app.tree_collapse_btn = gtk_button_new_from_icon_name("zoom-out-symbolic", GTK_ICON_SIZE_MENU);
    gtk_widget_set_tooltip_text(g_app.tree_collapse_btn, "Collapse");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.tree_collapse_btn), "flat-btn");
    g_signal_connect(g_app.tree_collapse_btn, "clicked", G_CALLBACK(on_tree_collapse_all), NULL);
    gtk_box_pack_end(GTK_BOX(tree_header_box), g_app.tree_collapse_btn, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(g_app.detail_box), tree_header_box, FALSE, FALSE, 0);

    g_app.tree_filter = gtk_search_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(g_app.tree_filter), i18n("search"));
    g_signal_connect(g_app.tree_filter, "search-changed", G_CALLBACK(on_tree_filter_changed), NULL);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.tree_filter, FALSE, FALSE, 0);

    g_app.tree_store = gtk_tree_store_new(3, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_STRING);
    GtkTreeModel *filter_model = gtk_tree_model_filter_new(GTK_TREE_MODEL(g_app.tree_store), NULL);
    gtk_tree_model_filter_set_visible_func(GTK_TREE_MODEL_FILTER(filter_model),
        tree_filter_func, NULL, NULL);

    g_app.tree_view = gtk_tree_view_new_with_model(filter_model);
    g_object_unref(filter_model);
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(g_app.tree_view), FALSE);
    gtk_tree_view_set_enable_tree_lines(GTK_TREE_VIEW(g_app.tree_view), TRUE);
    gtk_tree_view_set_show_expanders(GTK_TREE_VIEW(g_app.tree_view), TRUE);
    gtk_tree_view_set_level_indentation(GTK_TREE_VIEW(g_app.tree_view), 18);
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.tree_view), "file-tree");

    GtkTreeViewColumn *col = gtk_tree_view_column_new();
    GtkCellRenderer *pix = gtk_cell_renderer_pixbuf_new();
    g_object_set(pix, "stock-size", GTK_ICON_SIZE_MENU, NULL);
    gtk_tree_view_column_pack_start(col, pix, FALSE);
    gtk_tree_view_column_set_cell_data_func(col, pix, tree_icon_func, NULL, NULL);
    GtkCellRenderer *txt = gtk_cell_renderer_text_new();
    g_object_set(txt, "ellipsize", PANGO_ELLIPSIZE_END, NULL);
    gtk_tree_view_column_pack_start(col, txt, TRUE);
    gtk_tree_view_column_add_attribute(col, txt, "text", 0);
    gtk_tree_view_column_set_expand(col, TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(g_app.tree_view), col);

    GtkCellRenderer *szr = gtk_cell_renderer_text_new();
    g_object_set(szr, "xalign", 1.0f, NULL);
    GtkTreeViewColumn *szcol = gtk_tree_view_column_new_with_attributes("size", szr, "text", 2, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(g_app.tree_view), szcol);
    gtk_tree_view_column_set_alignment(szcol, 1.0f);

    g_signal_connect(g_app.tree_view, "row-activated", G_CALLBACK(on_tree_row_activated), NULL);
    g_signal_connect(g_app.tree_view, "button-press-event", G_CALLBACK(on_tree_button_press), NULL);

    g_app.tree_sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(g_app.tree_sw, -1, 380);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(g_app.tree_sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_hexpand(g_app.tree_sw, TRUE);
    gtk_container_add(GTK_CONTAINER(g_app.tree_sw), g_app.tree_view);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.tree_sw, TRUE, TRUE, 0);

    gtk_widget_hide(g_app.tree_summary);
    gtk_widget_hide(g_app.tree_filter);
    gtk_widget_hide(g_app.tree_expand_btn);
    gtk_widget_hide(g_app.tree_collapse_btn);
    gtk_widget_hide(g_app.tree_sw);

    g_app.notes_sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.notes_sep, FALSE, FALSE, 0);

    g_app.notes_lbl = gtk_label_new(i18n("notes"));
    gtk_style_context_add_class(gtk_widget_get_style_context(g_app.notes_lbl), "dim-label");
    gtk_label_set_xalign(GTK_LABEL(g_app.notes_lbl), 0.0);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.notes_lbl, FALSE, FALSE, 0);

    g_app.notes_text = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(g_app.notes_text), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(g_app.notes_text), TRUE);
    g_object_set(g_app.notes_text, "hexpand", TRUE, "max-width-chars", 60, NULL);
    gtk_box_pack_start(GTK_BOX(g_app.detail_box), g_app.notes_text, FALSE, FALSE, 0);

    gtk_widget_hide(g_app.notes_sep);
    gtk_widget_hide(g_app.notes_lbl);
    gtk_widget_hide(g_app.notes_text);

    gtk_container_add(GTK_CONTAINER(detail_scroll), g_app.detail_box);
    gtk_paned_pack2(GTK_PANED(paned), detail_scroll, TRUE, FALSE);
    gtk_box_pack_start(GTK_BOX(main_box), paned, TRUE, TRUE, 0);

    gtk_stack_add_named(g_app.stack, main_box, "main");
}

static void load_css(void) {
    static const char css[] =
        "* { font-family: 'Inter','SF Pro Text','Segoe UI',system-ui,-apple-system,sans-serif; }"
        "window, .background { background-color: #171717; color: #e8e8e8; }"
        "headerbar { min-height: 42px; padding: 0 8px;"
        "  background-image: none; background-color: #111111;"
        "  border-bottom: 1px solid #2a2a2a; box-shadow: none; }"
        "headerbar .title { font-size: 13px; font-weight: 500;"
        "  letter-spacing: 0; color: #b0b0b0; padding: 0 8px; }"
        "headerbar label.title { color: #b0b0b0; }"
        "headerbar button { min-height: 26px; min-width: 26px; padding: 0 6px;"
        "  border: none; background: transparent; color: #999999;"
        "  border-radius: 4px; box-shadow: none; }"
        "headerbar button:hover { background-color: #222222; color: #ffffff; }"
        "label { color: #e8e8e8; }"
        ".welcome-title { font-size: 22px; font-weight: 300; letter-spacing: 4px; color: #f0f0f0; }"
        ".detail-title  { font-size: 15px; font-weight: 500; letter-spacing: 0.2px; color: #f0f0f0; }"
        ".row-title     { font-size: 13px; font-weight: 500; color: #e8e8e8; }"
        ".row-count {"
        "  font-size: 10px; font-weight: 500;"
        "  color: #b0b0b0; background-color: #2a2a2a;"
        "  padding: 1px 6px; border-radius: 8px; }"
        ".dim-label  { color: #888888; font-weight: 400; }"
        ".error      { color: #ff6b6b; font-weight: 500; }"
        ".tree-header { font-size: 12px; font-weight: 500; color: #b0b0b0; padding: 4px 0; }"
        ".sidebar { background-color: #121212; border-right: 1px solid #2a2a2a; }"
        ".main-toolbar {"
        "  background-color: #171717;"
        "  border-bottom: 1px solid #2a2a2a;"
        "  padding: 4px 0; }"
        "row { border: none; border-bottom: 1px solid #222222; padding: 0; }"
        "row:hover { background-color: #1f1f1f; }"
        "row:selected {"
        "  background-color: #262626;"
        "  color: #ffffff;"
        "  box-shadow: inset 3px 0 0 0 #4ec9b0; }"
        "row:selected .row-title { color: #ffffff; }"
        "row:selected .dim-label { color: #a0a0a0; }"
        "row:selected .row-count { background-color: #3a3a3a; color: #e8e8e8; }"
        "button {"
        "  border-radius: 4px;"
        "  border: 1px solid transparent;"
        "  background-image: none;"
        "  background-color: transparent;"
        "  color: #e0e0e0;"
        "  box-shadow: none;"
        "  padding: 5px 10px;"
        "  min-height: 24px; }"
        "button:hover { background-color: #262626; color: #ffffff; }"
        "button:active, button:checked { background-color: #303030; }"
        ".suggested-action {"
        "  background-color: #2a2a2a;"
        "  color: #ffffff;"
        "  border-color: #3a3a3a; }"
        ".suggested-action:hover { background-color: #353535; color: #ffffff; }"
        ".flat-btn {"
        "  border: none; background: transparent;"
        "  padding: 3px 6px;"
        "  color: #a0a0a0;"
        "  font-size: 11px; }"
        ".flat-btn:hover { background-color: #262626; color: #ffffff; }"
        ".flat-btn:disabled { color: #4a4a4a; }"
        "entry, combobox, combobox button, spinbutton {"
        "  border-radius: 4px;"
        "  border: 1px solid #333333;"
        "  background-image: none;"
        "  background-color: #1e1e1e;"
        "  color: #e8e8e8;"
        "  box-shadow: none;"
        "  padding: 5px 8px;"
        "  min-height: 22px; }"
        "entry:focus, combobox:focus-within { border-color: #4ec9b0; }"
        "entry selection { background-color: #4ec9b0; color: #0d0d0d; }"
        "combobox button { background-color: transparent; }"
        "separator { background-color: #2a2a2a; min-height: 1px; min-width: 1px; }"
        ".schema-val {"
        "  background-color: #f0f0f0; color: #0d0d0d;"
        "  font-family: ui-monospace, monospace;"
        "  font-weight: 700; font-size: 15px;"
        "  padding: 6px 8px;"
        "  border-radius: 3px 0 0 3px; }"
        ".schema-salt {"
        "  background-color: #6a6a6a; color: #ffffff;"
        "  font-family: ui-monospace, monospace;"
        "  font-weight: 700; font-size: 15px;"
        "  padding: 6px 8px;"
        "  border-radius: 0 3px 3px 0; }"
        ".schema-dash {"
        "  font-family: ui-monospace, monospace;"
        "  font-weight: 700; font-size: 15px;"
        "  padding: 6px 0; color: #4a4a4a; }"
        ".vlabel-val {"
        "  background-color: #f0f0f0; color: #0d0d0d;"
        "  font-family: ui-monospace, monospace;"
        "  font-weight: 700; font-size: 13px;"
        "  padding: 3px 6px;"
        "  border-radius: 3px 0 0 3px; }"
        ".vlabel-salt {"
        "  background-color: #6a6a6a; color: #ffffff;"
        "  font-family: ui-monospace, monospace;"
        "  font-weight: 700; font-size: 13px;"
        "  padding: 3px 6px;"
        "  border-radius: 0 3px 3px 0; }"
        "treeview {"
        "  background-color: #1a1a1a;"
        "  color: #e0e0e0;"
        "  border: 1px solid #2a2a2a;"
        "  border-radius: 4px;"
        "  font-size: 12px; }"
        "treeview:selected { background-color: #2a2a2a; color: #ffffff; }"
        "treeview:hover    { background-color: #202020; }"
        "treeview.view     { background-color: #1a1a1a; color: #e0e0e0; }"
        "treeview .cell    { color: #e0e0e0; }"
        "treeview expander {"
        "  color: #808080;"
        "  min-width: 14px; min-height: 14px; }"
        "treeview expander:hover { color: #ffffff; }"
        ".search-disk-header {"
        "  background-color: #1e1e1e;"
        "  border-top: 1px solid #2a2a2a;"
        "  border-bottom: 1px solid #2a2a2a; }"
        ".disk-header-name  { font-size: 12px; font-weight: 600; color: #f0f0f0; }"
        ".disk-header-count {"
        "  font-size: 10px; font-weight: 500;"
        "  color: #e0e0e0; background-color: #2a2a2a;"
        "  padding: 1px 7px; border-radius: 8px; }"
        ".file-name { font-size: 12px; font-weight: 500; color: #e0e0e0; }"
        ".file-path { font-size: 11px; font-family: ui-monospace, monospace; color: #808080; }"
        ".file-size { font-size: 11px; font-family: ui-monospace, monospace; color: #a0a0a0; }"
        "scrollbar { background: transparent; border: none; }"
        "scrollbar slider {"
        "  background-color: #3a3a3a;"
        "  border-radius: 4px;"
        "  min-width: 6px; min-height: 6px; }"
        "scrollbar slider:hover { background-color: #4ec9b0; }"
        "tooltip {"
        "  background-color: #0d0d0d;"
        "  color: #e8e8e8;"
        "  border: 1px solid #3a3a3a;"
        "  border-radius: 4px;"
        "  padding: 5px 9px;"
        "  font-size: 11px; }"
        "menu {"
        "  background-color: #1e1e1e;"
        "  border: 1px solid #2a2a2a;"
        "  padding: 4px;"
        "  border-radius: 4px; }"
        "menuitem { padding: 5px 10px; border-radius: 3px; color: #e8e8e8; }"
        "menuitem:hover { background-color: #2a2a2a; color: #ffffff; }"
        "label:disabled { color: #555555; }"
        "cellview { color: #e0e0e0; background-color: #1a1a1a; }"
        ".search-filters { padding: 2px 0; }"
        ".filter-chip {"
        "  font-size: 10px;"
        "  min-height: 20px;"
        "  padding: 2px 10px;"
        "  border-radius: 10px;"
        "  border: 1px solid #333333;"
        "  background-color: #1e1e1e;"
        "  color: #a0a0a0;"
        "  min-width: 0; }"
        ".filter-chip:hover { background-color: #262626; color: #ffffff; }"
        ".filter-chip:checked { background-color: #4ec9b0; color: #0d0d0d;"
        "  border-color: #4ec9b0; }"
        ".smart-ok { color: #4ec9b0; font-weight: 600; }"
        ".smart-bad { color: #ff6b6b; font-weight: 600; }"
        ".connected-dot { color: #4ec9b0; font-weight: 700; }"
        ".disconnected-dot { color: #555555; font-weight: 700; }"
        ".toast {"
        "  background-color: #1e1e1e;"
        "  border-bottom: 1px solid #4ec9b0;"
        "  border-radius: 0; }"
        ".toast label { color: #e8e8e8; font-size: 12px; }"
        ".toast:hover { background-color: #262626; }"
        ".also-on { font-size: 10px; color: #4ec9b0; padding-top: 1px; }";

    GtkCssProvider *provider = gtk_css_provider_new();
    GError *error = NULL;
    gtk_css_provider_load_from_data(provider, css, -1, &error);
    if (error) g_error_free(error);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

static gboolean shutdown_idle(gpointer user_data) {
    (void)user_data;
    if (g_app.clipboard_timer_id) {
        g_source_remove(g_app.clipboard_timer_id);
        g_app.clipboard_timer_id = 0;
    }
    if (g_app.autolock_timer_id) {
        g_source_remove(g_app.autolock_timer_id);
        g_app.autolock_timer_id = 0;
    }
    if (g_app.connection_timer_id) {
        g_source_remove(g_app.connection_timer_id);
        g_app.connection_timer_id = 0;
    }
    if (g_toast_timer_id) {
        g_source_remove(g_toast_timer_id);
        g_toast_timer_id = 0;
    }
    if (g_known_uuids) {
        g_hash_table_destroy(g_known_uuids);
        g_known_uuids = NULL;
    }
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); g_app.db = NULL; }
    free(g_app.current_file); g_app.current_file = NULL;
    free(g_app.expected_fp); g_app.expected_fp = NULL;
    free(g_tree_filter_needle); g_tree_filter_needle = NULL;
    gtk_main_quit();
    return G_SOURCE_REMOVE;
}

static void graceful_shutdown(int sig) {
    (void)sig;
    if (g_shutdown_requested) return;
    g_shutdown_requested = 1;
    g_idle_add(shutdown_idle, NULL);
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
    gtk_widget_add_accelerator(g_app.btn_snapshot, "clicked", accel,
        GDK_KEY_i, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_find, "clicked", accel,
        GDK_KEY_g, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(g_app.btn_batch, "clicked", accel,
        GDK_KEY_r, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
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
    signal(SIGINT, graceful_shutdown);
    signal(SIGTERM, graceful_shutdown);
    gtk_init(&argc, &argv);
    load_config();
    load_css();
    memset(&g_app, 0, sizeof(g_app));
    g_app.current_entry_idx = -1;
    g_app.toast_entry_idx = -1;
    char *icon_path = find_icon_path();
    if (icon_path) {
        icon_pb = gdk_pixbuf_new_from_file_at_size(icon_path, 256, 256, NULL);
        g_free(icon_path);
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "DiskPass");
    gtk_window_set_default_size(GTK_WINDOW(win), 1000, 660);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    if (icon_pb) gtk_window_set_icon(GTK_WINDOW(win), icon_pb);

    GtkWidget *hb = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), FALSE);
    gtk_header_bar_set_has_subtitle(GTK_HEADER_BAR(hb), FALSE);

    GtkWidget *title_lbl = gtk_label_new("DiskPass");
    gtk_widget_set_size_request(title_lbl, 160, -1);
    gtk_style_context_add_class(gtk_widget_get_style_context(title_lbl), "title");
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(hb), title_lbl);

    GtkWidget *hb_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

    GtkWidget *btn_min = gtk_button_new_with_label("–");
    gtk_widget_set_tooltip_text(btn_min, "Minimize");
    g_signal_connect(btn_min, "clicked", G_CALLBACK(on_minimize_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(hb_box), btn_min, FALSE, FALSE, 0);

    GtkWidget *btn_max = gtk_button_new_with_label("□");
    gtk_widget_set_tooltip_text(btn_max, "Maximize");
    g_signal_connect(btn_max, "clicked", G_CALLBACK(on_maximize_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(hb_box), btn_max, FALSE, FALSE, 0);

    GtkWidget *btn_close = gtk_button_new_with_label("×");
    gtk_widget_set_tooltip_text(btn_close, "Close");
    g_signal_connect(btn_close, "clicked", G_CALLBACK(on_close_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(hb_box), btn_close, FALSE, FALSE, 0);

    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), hb_box);
    gtk_window_set_titlebar(GTK_WINDOW(win), hb);

    g_signal_connect(win, "window-state-event",
        G_CALLBACK(on_window_state_changed), btn_max);

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
    gtk_widget_add_events(win,
        GDK_KEY_PRESS_MASK | GDK_POINTER_MOTION_MASK |
        GDK_BUTTON_PRESS_MASK | GDK_SCROLL_MASK);
    g_signal_connect(win, "key-press-event", G_CALLBACK(on_user_activity), NULL);
    g_signal_connect(win, "motion-notify-event", G_CALLBACK(on_user_activity), NULL);
    g_signal_connect(win, "button-press-event", G_CALLBACK(on_user_activity), NULL);
    g_signal_connect(win, "scroll-event", G_CALLBACK(on_user_activity), NULL);
    g_signal_connect(win, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_widget_show_all(win);
    set_tree_visible(FALSE);
    set_notes_visible(FALSE);
    gtk_revealer_set_reveal_child(GTK_REVEALER(g_app.toast_revealer), FALSE);
    g_app.connection_timer_id = g_timeout_add_seconds(5, connection_check_cb, NULL);
    gtk_main();
    if (g_app.clipboard_timer_id) g_source_remove(g_app.clipboard_timer_id);
    if (g_app.autolock_timer_id) g_source_remove(g_app.autolock_timer_id);
    if (g_app.connection_timer_id) g_source_remove(g_app.connection_timer_id);
    if (g_toast_timer_id) g_source_remove(g_toast_timer_id);
    if (g_known_uuids) g_hash_table_destroy(g_known_uuids);
    if (g_app.db) { db_manager_clear(g_app.db); free(g_app.db); }
    free(g_app.current_file);
    free(g_app.expected_fp);
    free(g_tree_filter_needle);
    g_tree_filter_needle = NULL;
    if (g_app.tree_store) g_object_unref(g_app.tree_store);
    if (icon_pb) g_object_unref(icon_pb);
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, "", 0);
    GtkClipboard *primary = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(primary, "", 0);
    return 0;
}
