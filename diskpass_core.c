#include "diskpass.h"

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
#define DB_MAX_FILE_BYTES (512ULL * 1024ULL * 1024ULL)
#define DB_MAX_JSON_BYTES (256ULL * 1024ULL * 1024ULL)
#define DB_MAX_ENTRIES 100000
#define DB_MAX_FILTERS 256
#define DB_MAX_INDEX_BYTES (128ULL * 1024ULL * 1024ULL)
#define DB_MAX_INDEX_FILES 2000000ULL
#define DB_MAX_INDEX_QUEUED_DIRS 100000ULL
#define DB_MAX_INDEX_DIRS 1000000ULL

static const char ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
static const size_t ALPHABET_LEN = 32;
static const char *SCHEMA_PARTS[] = {"type","size","content_tag","cipher","dsalt"};
enum { SCHEMA_COUNT = 5 };
static const int PART_LENGTHS[] = {1, 2, 2, 1, 2};
static const int FULL_PART_LENGTHS[] = {2, 3, 3, 2, 3};

typedef struct { const char *name; const char *code; } map_entry_t;

static const map_entry_t TYPE_MAP[] = {
    {"HDD","H"},{"SSD","S"},{"USB","U"},{"M.2","M"},{"SD","D"},{"CF","C"},
    {"OPTICAL","O"},{"OTHER","X"},
    {"LTO1","1"},{"LTO2","2"},{"LTO3","3"},{"LTO4","4"},
    {"LTO5","5"},{"LTO6","6"},{"LTO7","7"},{"LTO8","8"},{"LTO9","9"},
    {"LTO10","0"},{"LTO11","A"},{"LTO12","B"},{"LTO13","E"},{"LTO14","F"},
    {"microSD","G"},{"CFast","I"},{"XQD","J"},{"CFexpress","K"},{"NVMe","L"},
    {"HDD_External","N"},{"MMC","P"},{"MemoryStick","Q"},{"SD_Express","R"},
    {"UFS","T"},{"HVD","V"},{"DAT","W"},{"AIT","Y"},{"Floppy","Z"}
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
    {"24TB","TM"},{"30TB","TN"},{"36TB","TP"},{"45TB","TQ"},
    {"512MB","W1"},{"640MB","W2"},{"9.4GB","W3"},{"5TB","W4"},{"28TB","W5"},
    {"32TB","W6"},{"34TB","W7"},{"44TB","W8"},{"15.36TB","W9"},{"30.72TB","WA"},
    {"61.44TB","WB"},{"122.88TB","WC"},{"3.9TB","WD"},
    {"1MB","WE"},{"2MB","WF"},{"4MB","WG"},{"8MB","WH"},{"16MB","WJ"},{"32MB","WK"},
    {"64MB","WM"},{"128MB","WN"},{"256MB","WP"},
    {"360KB","WQ"},{"720KB","WR"},{"1.2MB","WS"},{"1.44MB","WT"},{"2.88MB","WV"},
    {"100MB","WW"},{"250MB","WX"},{"750MB","WY"},{"1.3GB","WZ"},
    {"2.6GB","V0"},{"5.2GB","V1"},{"9.1GB","V2"},
    {"40MB","V3"},{"80MB","V4"},{"120MB","V5"},{"125MB","V6"},{"200MB","V7"},
    {"340MB","V8"},{"400MB","V9"},{"680MB","VA"},
    {"1.1GB","VB"},{"1.6GB","VC"},{"2.2GB","VD"},{"2.5GB","VE"},{"5GB","VF"},
    {"15GB","VG"},{"20GB","VH"},{"35GB","VJ"},{"38GB","VK"},
    {"70GB","VM"},{"75GB","VN"},{"80GB","VP"},{"110GB","VQ"},{"140GB","VR"},
    {"160GB","VS"},{"175GB","VT"},{"220GB","VV"},{"260GB","VW"},{"300GB","VX"},
    {"365TB","VY"},{"520GB","VZ"},{"525TB","U1"},{"600GB","U2"},{"913TB","U3"},
    {"1Mb","U4"},{"4Mb","U5"},{"8Mb","U6"},{"16Mb","U7"},{"32Mb","U8"},
    {"64Mb","U9"},{"128Mb","UA"},{"256Mb","UB"},{"1Gb","UC"},{"2Gb","UD"},{"4Gb","UE"},
    {"4KB","UF"},{"16KB","UG"},{"64KB","UH"},{"256KB","UJ"},
    {"40TB","X0"},{"75TB","X1"},{"100TB","X2"},{"70TB","X3"},
    {"175TB","X4"},{"120TB","X5"},{"300TB","X6"},{"210TB","X7"},
    {"12GB","X8"},{"40GB","X9"},{"1.3TB","XA"}
};
static const int SIZE_MAP_N = ARRAY_SIZE(SIZE_MAP);

static const map_entry_t CIPHER_MAP[] = {
    {"LUKS","L"},{"VERACRYPT","V"},{"BITLOCKER","B"},
    {"7ZIP","7"},{"AGE","A"},{"GPG","G"},{"NONE","N"}
};
static const int CIPHER_MAP_N = ARRAY_SIZE(CIPHER_MAP);

static const char *SIZE_FOR_USB[] = {"1GB","2GB","4GB","8GB","16GB","32GB","64GB","128GB","256GB","512GB","1TB","2TB",NULL};
static const char *SIZE_FOR_SD[] = {"4GB","8GB","16GB","32GB","64GB","128GB","256GB","512GB","1TB","2TB",NULL};
static const char *SIZE_FOR_MICROSD[] = {"512MB","1GB","2GB","4GB","8GB","16GB","32GB","64GB","128GB","256GB","512GB","1TB",NULL};
static const char *SIZE_FOR_CF[] = {"512MB","1GB","2GB","4GB","8GB","16GB","32GB","64GB","128GB","256GB",NULL};
static const char *SIZE_FOR_CFAST[] = {"8GB","16GB","32GB","64GB","128GB","256GB","512GB","1TB",NULL};
static const char *SIZE_FOR_XQD[] = {"32GB","64GB","120GB","128GB","240GB","256GB",NULL};
static const char *SIZE_FOR_CFEXPRESS[] = {"128GB","256GB","400GB","512GB","1TB","2TB","4TB",NULL};
static const char *SIZE_FOR_SDEXPRESS[] = {"128GB","256GB","512GB","1TB",NULL};
static const char *SIZE_FOR_UFS[] = {"128GB","256GB","512GB","1TB",NULL};
static const char *SIZE_FOR_MEMORYSTICK[] = {"4MB","8MB","16MB","32MB","64MB","128MB","256MB","512MB","1GB","2GB","4GB","8GB","16GB","32GB",NULL};
static const char *SIZE_FOR_MMC[] = {"8MB","16MB","32MB","64MB","128MB","256MB","512MB","1GB","2GB","4GB","8GB","16GB",NULL};
static const char *SIZE_FOR_HDD[] = {"250GB","320GB","500GB","1TB","2TB","3TB","4TB","5TB","6TB","8TB","10TB","12TB","14TB","16TB","18TB","20TB","22TB","24TB","28TB","30TB","32TB","34TB","44TB",NULL};
static const char *SIZE_FOR_HDD_EXT[] = {"500GB","1TB","2TB","4TB","6TB","8TB","10TB","12TB","14TB","16TB","18TB","20TB","24TB","30TB",NULL};
static const char *SIZE_FOR_SSD[] = {"120GB","128GB","240GB","250GB","256GB","480GB","500GB","512GB","1TB","2TB","4TB","8TB","16TB",NULL};
static const char *SIZE_FOR_M2[] = {"128GB","250GB","256GB","500GB","512GB","1TB","2TB","4TB","8TB","16TB",NULL};
static const char *SIZE_FOR_NVME[] = {"256GB","512GB","1TB","2TB","4TB","8TB","15.36TB","30.72TB","61.44TB","122.88TB",NULL};
static const char *SIZE_FOR_OPT[] = {"640MB","700MB","4.7GB","8.5GB","9.4GB","25GB","50GB","100GB","128GB",NULL};
static const char *SIZE_FOR_HVD[] = {"100GB","1TB","3.9TB",NULL};
static const char *SIZE_FOR_LTO1[] = {"100GB","200GB",NULL};
static const char *SIZE_FOR_LTO2[] = {"200GB","400GB",NULL};
static const char *SIZE_FOR_LTO3[] = {"400GB","800GB",NULL};
static const char *SIZE_FOR_LTO4[] = {"800GB","1.6TB",NULL};
static const char *SIZE_FOR_LTO5[] = {"1.5TB","3.0TB",NULL};
static const char *SIZE_FOR_LTO6[] = {"2.5TB","6.25TB",NULL};
static const char *SIZE_FOR_LTO7[] = {"6TB","15TB",NULL};
static const char *SIZE_FOR_LTO8[] = {"12TB","30TB",NULL};
static const char *SIZE_FOR_LTO9[] = {"18TB","45TB",NULL};
static const char *SIZE_FOR_LTO10[] = {"30TB","40TB","75TB","100TB",NULL};
static const char *SIZE_FOR_LTO11[] = {"70TB","175TB",NULL};
static const char *SIZE_FOR_LTO12[] = {"120TB","300TB",NULL};
static const char *SIZE_FOR_LTO13[] = {"210TB","525TB",NULL};
static const char *SIZE_FOR_LTO14[] = {"365TB","913TB",NULL};
static const char *SIZE_FOR_DAT[] = {"1.3GB","2GB","4GB","8GB","12GB","20GB","40GB","80GB","160GB",NULL};
static const char *SIZE_FOR_AIT[] = {"25GB","35GB","50GB","100GB","200GB","260GB","520GB","1TB","1.3TB","2TB",NULL};
static const char *SIZE_FOR_FLOPPY[] = {"360KB","720KB","1.2MB","1.44MB","2.88MB",NULL};
static const char *SIZE_FOR_OTHER[] = {
    "360KB","512MB","640MB","700MB","1MB","2MB","4MB","8MB","16MB","32MB","64MB","128MB","256MB",
    "1GB","2GB","4GB","8GB","16GB","32GB","64GB","128GB","256GB","512GB",
    "4.7GB","8.5GB","9.4GB","25GB","50GB","100GB",
    "120GB","240GB","250GB","320GB","400GB","480GB","500GB","800GB",
    "1TB","1.5TB","1.6TB","2TB","2.5TB","3TB","3.0TB",
    "4TB","5TB","6TB","6.25TB","8TB","10TB","12TB","14TB","15TB",
    "16TB","18TB","20TB","22TB","24TB","28TB","30TB","32TB","34TB","36TB","44TB","45TB",
    "15.36TB","30.72TB","61.44TB","122.88TB",
    "1.3GB","2.6GB","5.2GB","9.1GB","3.9TB",
    "100MB","250MB","750MB","40MB","80MB","120MB","125MB","200MB","340MB","680MB",
    "1.1GB","2.2GB","2.5GB","5GB","15GB","35GB","38GB","70GB","75GB","80GB",
    "110GB","140GB","160GB","175GB","220GB","260GB","300GB","365TB","520GB","525TB","600GB","913TB",
    "1Mb","4Mb","8Mb","16Mb","32Mb","64Mb","128Mb","256Mb","1Gb","2Gb","4Gb",
    "4KB","16KB","64KB","256KB",
    NULL
};

typedef struct { const char *type; const char **sizes; } type_size_assoc_t;
static const type_size_assoc_t TYPE_SIZE_MAP[] = {
    {"USB",SIZE_FOR_USB},{"SD",SIZE_FOR_SD},{"microSD",SIZE_FOR_MICROSD},
    {"CF",SIZE_FOR_CF},{"CFast",SIZE_FOR_CFAST},{"XQD",SIZE_FOR_XQD},
    {"CFexpress",SIZE_FOR_CFEXPRESS},{"SD_Express",SIZE_FOR_SDEXPRESS},
    {"UFS",SIZE_FOR_UFS},{"MemoryStick",SIZE_FOR_MEMORYSTICK},{"MMC",SIZE_FOR_MMC},
    {"HDD",SIZE_FOR_HDD},{"HDD_External",SIZE_FOR_HDD_EXT},
    {"SSD",SIZE_FOR_SSD},{"M.2",SIZE_FOR_M2},{"NVMe",SIZE_FOR_NVME},
    {"OPTICAL",SIZE_FOR_OPT},{"HVD",SIZE_FOR_HVD},
    {"LTO1",SIZE_FOR_LTO1},{"LTO2",SIZE_FOR_LTO2},{"LTO3",SIZE_FOR_LTO3},
    {"LTO4",SIZE_FOR_LTO4},{"LTO5",SIZE_FOR_LTO5},{"LTO6",SIZE_FOR_LTO6},
    {"LTO7",SIZE_FOR_LTO7},{"LTO8",SIZE_FOR_LTO8},{"LTO9",SIZE_FOR_LTO9},
    {"LTO10",SIZE_FOR_LTO10},{"LTO11",SIZE_FOR_LTO11},{"LTO12",SIZE_FOR_LTO12},
    {"LTO13",SIZE_FOR_LTO13},{"LTO14",SIZE_FOR_LTO14},
    {"DAT",SIZE_FOR_DAT},{"AIT",SIZE_FOR_AIT},
    {"Floppy",SIZE_FOR_FLOPPY},
    {"OTHER",SIZE_FOR_OTHER}
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
    size_t len = strlen(*s) + 1;
    sodium_memzero(*s, len);
    free(*s);
    *s = NULL;
}

static void secure_g_free_string(char **s) {
    if (!s || !*s) return;
    sodium_memzero(*s, strlen(*s) + 1);
    g_free(*s);
    *s = NULL;
}

static void secure_g_free_cb(gpointer p) {
    if (!p) return;
    sodium_memzero(p, strlen((const char *)p) + 1);
    g_free(p);
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

static void db_json_zero_strings(cJSON *node) {
    for (cJSON *cur = node; cur; cur = cur->next) {
        if (cJSON_IsString(cur) && cur->valuestring)
            sodium_memzero(cur->valuestring, strlen(cur->valuestring));
        if (cur->child) db_json_zero_strings(cur->child);
    }
}

static gboolean db_json_preflight(const char *json, size_t len) {
    if (!json) return FALSE;
    size_t depth = 0;
    gboolean in_string = FALSE, escaped = FALSE;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)json[i];
        if (in_string) {
            if (escaped) escaped = FALSE;
            else if (c == '\\') escaped = TRUE;
            else if (c == '"') in_string = FALSE;
            continue;
        }
        if (c == '"') { in_string = TRUE; continue; }
        if (c == '{' || c == '[') {
            if (++depth > 64) return FALSE;
        } else if (c == '}' || c == ']') {
            if (depth == 0) return FALSE;
            depth--;
        }
    }
    return !in_string && !escaped && depth == 0;
}

static gboolean db_json_has_duplicate_keys(cJSON *node) {
    for (cJSON *cur = node; cur; cur = cur->next) {
        if (cJSON_IsObject(cur)) {
            size_t members = 0;
            for (cJSON *a = cur->child; a; a = a->next) {
                if (++members > 128) return TRUE;
                if (!a->string) continue;
                for (cJSON *b = a->next; b; b = b->next) {
                    if (b->string && strcmp(a->string, b->string) == 0)
                        return TRUE;
                }
            }
        }
        if (cur->child && db_json_has_duplicate_keys(cur->child))
            return TRUE;
    }
    return FALSE;
}

static gboolean db_json_has_unicode_nul_escape(const char *json) {
    if (!json) return TRUE;
    const char *end = json + strlen(json);
    const char *p = json;
    while (p < end) {
        if (*p != '\\') { p++; continue; }
        const char *run = p;
        while (p < end && *p == '\\') p++;
        size_t slashes = (size_t)(p - run);
        if ((slashes & 1U) && (size_t)(end - p) >= 5 && p[0] == 'u' && p[1] == '0' &&
            p[2] == '0' && p[3] == '0' && p[4] == '0')
            return TRUE;
        if (p < end) p++;
    }
    return FALSE;
}

static gboolean db_json_string_field_valid(cJSON *obj, const char *key,
        gboolean required, size_t max_len) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!v) return !required;
    return cJSON_IsString(v) && v->valuestring && strlen(v->valuestring) <= max_len;
}

static const char *db_json_string(cJSON *obj, const char *key) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    return (v && cJSON_IsString(v)) ? v->valuestring : NULL;
}

static gboolean db_valid_schema_array(cJSON *arr, char *order[SCHEMA_COUNT]) {
    if (!arr || !cJSON_IsArray(arr) || cJSON_GetArraySize(arr) != SCHEMA_COUNT)
        return FALSE;
    gboolean seen[SCHEMA_COUNT] = { FALSE, FALSE, FALSE, FALSE, FALSE };
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        cJSON *item = cJSON_GetArrayItem(arr, i);
        if (!item || !cJSON_IsString(item) || !item->valuestring) return FALSE;
        int found = -1;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (strcmp(item->valuestring, SCHEMA_PARTS[j]) == 0) { found = j; break; }
        if (found < 0 || seen[found]) return FALSE;
        seen[found] = TRUE;
        order[i] = xstrdup(item->valuestring);
    }
    return TRUE;
}

static int write_all_fd(int fd, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static gboolean db_parent_directory_is_safe(const char *path, char *err_msg, size_t err_msg_sz) {
    if (!path || !path[0]) {
        snprintf(err_msg, err_msg_sz, "Invalid database path");
        return FALSE;
    }
    gchar *dir = g_path_get_dirname(path);
    if (!dir) {
        snprintf(err_msg, err_msg_sz, "Cannot determine database directory");
        return FALSE;
    }
    struct stat st;
    if (g_lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        snprintf(err_msg, err_msg_sz, "Database parent must be an actual directory");
        g_free(dir);
        return FALSE;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) && !(st.st_mode & S_ISVTX)) {
        snprintf(err_msg, err_msg_sz,
            "Refusing to save in a group/world-writable directory without the sticky bit");
        g_free(dir);
        return FALSE;
    }
    g_free(dir);
    return TRUE;
}

static int db_backup_existing_file(const char *path, char *err_msg, size_t err_msg_sz) {
    int src = -1, dst = -1;
    char *bak = NULL, *tmp = NULL;
    int rc = -1;
    src = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (src < 0) {
        if (errno == ENOENT) return 0;
        snprintf(err_msg, err_msg_sz, "Cannot open existing database for backup: %s", strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(src, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > (uint64_t)DB_MAX_FILE_BYTES) {
        snprintf(err_msg, err_msg_sz, "Existing database is not a valid regular file for backup");
        goto cleanup;
    }
    size_t bak_len = strlen(path) + sizeof(".bak");
    bak = malloc(bak_len);
    if (!bak) {
        snprintf(err_msg, err_msg_sz, "Backup path allocation failed");
        goto cleanup;
    }
    snprintf(bak, bak_len, "%s.bak", path);
    size_t tmp_len = strlen(bak) + sizeof(".tmp.XXXXXX");
    tmp = malloc(tmp_len);
    if (!tmp) {
        snprintf(err_msg, err_msg_sz, "Backup temporary path allocation failed");
        goto cleanup;
    }
    snprintf(tmp, tmp_len, "%s.tmp.XXXXXX", bak);
    dst = g_mkstemp_full(tmp, O_WRONLY | O_CLOEXEC, 0600);
    if (dst < 0 || fchmod(dst, 0600) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot create private database backup: %s", strerror(errno));
        goto cleanup;
    }
    unsigned char buf[64 * 1024];
    for (;;) {
        ssize_t n = read(src, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            sodium_memzero(buf, sizeof(buf));
            snprintf(err_msg, err_msg_sz, "Cannot read existing database for backup: %s", strerror(errno));
            goto cleanup;
        }
        if (n == 0) break;
        if (write_all_fd(dst, buf, (size_t)n) != 0) {
            sodium_memzero(buf, sizeof(buf));
            snprintf(err_msg, err_msg_sz, "Cannot write database backup: %s", strerror(errno));
            goto cleanup;
        }
    }
    sodium_memzero(buf, sizeof(buf));
    if (fsync(dst) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot sync database backup: %s", strerror(errno));
        goto cleanup;
    }
    if (close(dst) != 0) {
        dst = -1;
        snprintf(err_msg, err_msg_sz, "Cannot close database backup: %s", strerror(errno));
        goto cleanup;
    }
    dst = -1;
    if (rename(tmp, bak) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot atomically install database backup: %s", strerror(errno));
        goto cleanup;
    }
    rc = 0;
cleanup:
    if (src >= 0) close(src);
    if (dst >= 0) close(dst);
    if (rc != 0 && tmp) unlink(tmp);
    free(tmp);
    free(bak);
    return rc;
}

static const char **get_sizes_for_type(const char *type_name) {
    for (int i = 0; i < TYPE_SIZE_MAP_N; i++)
        if (strcmp(TYPE_SIZE_MAP[i].type, type_name) == 0)
            return (const char **)TYPE_SIZE_MAP[i].sizes;
    return (const char **)SIZE_FOR_OTHER;
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
    char lang[32];
    db_entry_t *entries;
    int entry_count, entry_cap;
    search_filter_t *filters;
    int filter_count, filter_cap;
    gpgme_ctx_t gpg_ctx;
    gboolean is_signed;
    gboolean is_pqc_encrypted;
} db_manager_t;

static gboolean map_has_name(const map_entry_t *tbl, int n, const char *value);
static gboolean valid_ascii_tag_char(unsigned char c);
static gboolean valid_alphabet_string(const char *s, size_t expected_len);
static void secure_shuffle(const char **arr, int n);
static int db_init_gpg(db_manager_t *m, char *err_msg, size_t err_msg_sz);
static int db_read_file(const char *path, char **out_recipient, char **out_enc_data, char *err_msg, size_t err_msg_sz);
static char *db_gpg_decrypt(db_manager_t *m, const char *enc_data, size_t enc_len, char *err_msg, size_t err_msg_sz);
static gboolean db_recipient_has_pqc(db_manager_t *m);
static char *db_gpg_encrypt(db_manager_t *m, const char *plaintext, size_t pt_len, char *err_msg, size_t err_msg_sz);
static char *db_gpg_encrypt_legacy(db_manager_t *m, const char *plaintext, size_t pt_len, char *err_msg, size_t err_msg_sz);
static char *hex_encode(const uint8_t *data, size_t len);
static uint8_t *hex_decode(const char *hex, size_t *out_len);
static char *db_encode_label(db_manager_t *m, const char *type, const char *size, const char *content_tag, const char *cipher, const char *dsalt);

static void db_manager_init(db_manager_t *m) { memset(m, 0, sizeof(*m)); g_strlcpy(m->lang, "ru", sizeof(m->lang)); }

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
    m->filters = calloc((size_t)m->filter_cap, sizeof(search_filter_t));
    m->filter_count = 0;
    if (!m->filters) { m->filter_cap = 0; return; }
    for (size_t i = 0; i < ARRAY_SIZE(defs); i++) {
        m->filters[m->filter_count].name = xstrdup(defs[i].n);
        m->filters[m->filter_count].exts = xstrdup(defs[i].e);
        m->filter_count++;
    }
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
    if (m->noise_key) { sec_free(m->noise_key, m->noise_key_len); m->noise_key = NULL; m->noise_key_len = 0; }
    for (int i = 0; i < SCHEMA_COUNT; i++) { secure_free_string(&m->schema_order[i]); }
    for (int i = 0; i < m->entry_count; i++) db_entry_clear(&m->entries[i]);
    free(m->entries); m->entries = NULL; m->entry_count = 0; m->entry_cap = 0;
    if (m->gpg_ctx) { gpgme_release(m->gpg_ctx); m->gpg_ctx = NULL; }
}

static int db_load_json(db_manager_t *m, const char *json_str, char *err_msg, size_t err_msg_sz) {
    cJSON *root = NULL;
    int rc = -1;
    if (!m || !json_str) {
        snprintf(err_msg, err_msg_sz, "Invalid JSON input");
        return -1;
    }
    size_t json_len = strnlen(json_str, (size_t)DB_MAX_JSON_BYTES + 1);
    if (json_len == 0 || json_len > DB_MAX_JSON_BYTES) {
        snprintf(err_msg, err_msg_sz, "Database JSON exceeds size limit or is empty");
        return -1;
    }
    if (!db_json_preflight(json_str, json_len)) {
        snprintf(err_msg, err_msg_sz, "Database JSON nesting or syntax preflight limit exceeded");
        return -1;
    }
    if (db_json_has_unicode_nul_escape(json_str)) {
        snprintf(err_msg, err_msg_sz, "Database JSON contains a forbidden embedded NUL escape");
        return -1;
    }
    root = cJSON_ParseWithOpts(json_str, NULL, TRUE);
    if (!root || !cJSON_IsObject(root)) {
        snprintf(err_msg, err_msg_sz, "JSON root must be an object");
        goto cleanup;
    }
    if (db_json_has_duplicate_keys(root)) {
        snprintf(err_msg, err_msg_sz, "Database JSON contains duplicate keys or an oversized object");
        goto cleanup;
    }

    cJSON *j_version = cJSON_GetObjectItemCaseSensitive(root, "version");
    if (!j_version || !cJSON_IsNumber(j_version) || j_version->valuedouble != DB_VERSION) {
        snprintf(err_msg, err_msg_sz, "Unsupported or missing database version");
        goto cleanup;
    }

    cJSON *j_salt = cJSON_GetObjectItemCaseSensitive(root, "salt");
    cJSON *j_noise = cJSON_GetObjectItemCaseSensitive(root, "noise_key");
    size_t slen = 0, nlen = 0;
    uint8_t *salt = NULL, *noise = NULL;
    if (!j_salt || !cJSON_IsString(j_salt) || !j_salt->valuestring || strlen(j_salt->valuestring) != 64 ||
        !j_noise || !cJSON_IsString(j_noise) || !j_noise->valuestring || strlen(j_noise->valuestring) != 64) {
        snprintf(err_msg, err_msg_sz, "Missing or invalid database salt/key");
        goto cleanup;
    }
    salt = hex_decode(j_salt->valuestring, &slen);
    noise = hex_decode(j_noise->valuestring, &nlen);
    if (!salt || !noise || slen != 32 || nlen != 32) {
        if (salt) { sodium_memzero(salt, slen); free(salt); }
        if (noise) { sodium_memzero(noise, nlen); free(noise); }
        snprintf(err_msg, err_msg_sz, "Database salt/key must be 32-byte hexadecimal values");
        goto cleanup;
    }
    uint8_t *secure_noise = sodium_malloc(nlen);
    if (!secure_noise) {
        sodium_memzero(salt, slen); free(salt);
        sodium_memzero(noise, nlen); free(noise);
        snprintf(err_msg, err_msg_sz, "Cannot allocate protected memory for database key");
        goto cleanup;
    }
    memcpy(secure_noise, noise, nlen);
    sodium_memzero(noise, nlen);
    free(noise);
    m->salt = salt; m->salt_len = slen;
    m->noise_key = secure_noise; m->noise_key_len = nlen;

    cJSON *j_schema = cJSON_GetObjectItemCaseSensitive(root, "schema");
    if (!db_valid_schema_array(j_schema, m->schema_order)) {
        for (int i = 0; i < SCHEMA_COUNT; i++) secure_free_string(&m->schema_order[i]);
        snprintf(err_msg, err_msg_sz, "Schema must contain each supported tag field exactly once");
        goto cleanup;
    }

    cJSON *j_lang = cJSON_GetObjectItemCaseSensitive(root, "lang");
    if (j_lang) {
        if (!cJSON_IsString(j_lang) || !j_lang->valuestring ||
            !i18n_language_code_valid(j_lang->valuestring)) {
            snprintf(err_msg, err_msg_sz, "Invalid language setting");
            goto cleanup;
        }
        snprintf(m->lang, sizeof(m->lang), "%s", j_lang->valuestring);
    }

    cJSON *j_entries = cJSON_GetObjectItemCaseSensitive(root, "entries");
    if (!j_entries || !cJSON_IsArray(j_entries)) {
        snprintf(err_msg, err_msg_sz, "Entries must be an array");
        goto cleanup;
    }
    int n = cJSON_GetArraySize(j_entries);
    if (n < 0 || n > DB_MAX_ENTRIES) {
        snprintf(err_msg, err_msg_sz, "Database contains too many entries");
        goto cleanup;
    }
    m->entry_cap = n > 0 ? n : 16;
    m->entries = calloc((size_t)m->entry_cap, sizeof(db_entry_t));
    if (!m->entries) {
        snprintf(err_msg, err_msg_sz, "Out of memory while loading entries");
        goto cleanup;
    }
    for (int i = 0; i < n; i++) {
        cJSON *je = cJSON_GetArrayItem(j_entries, i);
        if (!je || !cJSON_IsObject(je)) {
            snprintf(err_msg, err_msg_sz, "Entry %d is not an object", i + 1);
            goto cleanup;
        }
        if (!db_json_string_field_valid(je, "label", TRUE, 127) ||
            !db_json_string_field_valid(je, "type", TRUE, 32) ||
            !db_json_string_field_valid(je, "size", TRUE, 32) ||
            !db_json_string_field_valid(je, "cipher", TRUE, 32) ||
            !db_json_string_field_valid(je, "content_tag", TRUE, 2) ||
            !db_json_string_field_valid(je, "dsalt", TRUE, 2) ||
            !db_json_string_field_valid(je, "tag_full", FALSE, 4096) ||
            !db_json_string_field_valid(je, "dpass", FALSE, 16384) ||
            !db_json_string_field_valid(je, "notes", FALSE, 1024 * 1024) ||
            !db_json_string_field_valid(je, "alias", FALSE, 4096) ||
            !db_json_string_field_valid(je, "files", FALSE, DB_MAX_INDEX_BYTES) ||
            !db_json_string_field_valid(je, "smart", FALSE, 2 * 1024 * 1024) ||
            !db_json_string_field_valid(je, "uuid", FALSE, 256)) {
            snprintf(err_msg, err_msg_sz, "Entry %d contains missing, oversized or mistyped fields", i + 1);
            goto cleanup;
        }

        const char *type = db_json_string(je, "type");
        const char *size = db_json_string(je, "size");
        const char *cipher = db_json_string(je, "cipher");
        const char *content_tag = db_json_string(je, "content_tag");
        const char *dsalt = db_json_string(je, "dsalt");
        if (!map_has_name(TYPE_MAP, TYPE_MAP_N, type) ||
            !map_has_name(SIZE_MAP, SIZE_MAP_N, size) ||
            !map_has_name(CIPHER_MAP, CIPHER_MAP_N, cipher) ||
            strlen(content_tag) != 2 || !valid_ascii_tag_char((unsigned char)content_tag[0]) ||
            !valid_ascii_tag_char((unsigned char)content_tag[1]) ||
            !valid_alphabet_string(dsalt, 2)) {
            snprintf(err_msg, err_msg_sz, "Entry %d contains invalid tag components", i + 1);
            goto cleanup;
        }
        cJSON *j_last = cJSON_GetObjectItemCaseSensitive(je, "last_snapshot");
        if (j_last && (!cJSON_IsNumber(j_last) || !isfinite(j_last->valuedouble) ||
            j_last->valuedouble < 0 || j_last->valuedouble >= (double)LLONG_MAX)) {
            snprintf(err_msg, err_msg_sz, "Entry %d contains invalid snapshot timestamp", i + 1);
            goto cleanup;
        }

        db_entry_init(&m->entries[i]);
        m->entry_count = i + 1;
        db_entry_t *e = &m->entries[i];
        e->label = xstrdup(db_json_string(je, "label"));
        e->type = xstrdup(type);
        e->size = xstrdup(size);
        e->cipher = xstrdup(cipher);
        e->content_tag = xstrdup(content_tag);
        e->dsalt = xstrdup(dsalt);
        const char *value;
        value = db_json_string(je, "tag_full"); if (value) e->tag_full = xstrdup(value);
        value = db_json_string(je, "dpass"); if (value && value[0]) e->dpass = sec_strdup(value);
        value = db_json_string(je, "notes"); if (value) e->notes = xstrdup(value);
        value = db_json_string(je, "alias"); if (value && value[0]) e->alias = xstrdup(value);
        value = db_json_string(je, "files"); if (value && value[0]) e->files = xstrdup(value);
        value = db_json_string(je, "smart"); if (value && value[0]) e->smart = xstrdup(value);
        value = db_json_string(je, "uuid"); if (value && value[0]) e->uuid = xstrdup(value);
        if (j_last) e->last_snapshot = (long long)j_last->valuedouble;

        char *canonical = db_encode_label(m, e->type, e->size, e->content_tag, e->cipher, e->dsalt);
        if (!canonical || strcmp(canonical, e->label) != 0) {
            free(canonical);
            snprintf(err_msg, err_msg_sz, "Entry %d label does not match its authenticated fields", i + 1);
            goto cleanup;
        }
        free(canonical);
    }

    cJSON *j_filters = cJSON_GetObjectItemCaseSensitive(root, "filters");
    if (j_filters && !cJSON_IsArray(j_filters)) {
        snprintf(err_msg, err_msg_sz, "Filters must be an array");
        goto cleanup;
    }
    if (j_filters) {
        int nf = cJSON_GetArraySize(j_filters);
        if (nf < 0 || nf > DB_MAX_FILTERS) {
            snprintf(err_msg, err_msg_sz, "Database contains too many filters");
            goto cleanup;
        }
        m->filter_cap = nf > 0 ? nf : 4;
        m->filters = calloc((size_t)m->filter_cap, sizeof(search_filter_t));
        if (!m->filters) {
            snprintf(err_msg, err_msg_sz, "Out of memory while loading filters");
            goto cleanup;
        }
        for (int i = 0; i < nf; i++) {
            cJSON *jf = cJSON_GetArrayItem(j_filters, i);
            if (!jf || !cJSON_IsObject(jf) ||
                !db_json_string_field_valid(jf, "name", TRUE, 256) ||
                !db_json_string_field_valid(jf, "exts", TRUE, 4096)) {
                snprintf(err_msg, err_msg_sz, "Filter %d is malformed", i + 1);
                goto cleanup;
            }
            m->filters[i].name = xstrdup(db_json_string(jf, "name"));
            m->filters[i].exts = xstrdup(db_json_string(jf, "exts"));
            m->filter_count++;
        }
    } else {
        db_init_default_filters(m);
    }

    rc = 0;
cleanup:
    if (root) {
        db_json_zero_strings(root);
        cJSON_Delete(root);
    }
    return rc;
}

static gboolean db_json_add_string(cJSON *obj, const char *key, const char *value) {
    return obj && key && value && cJSON_AddStringToObject(obj, key, value) != NULL;
}

static gboolean db_json_add_number(cJSON *obj, const char *key, double value) {
    return obj && key && cJSON_AddNumberToObject(obj, key, value) != NULL;
}

static gboolean db_json_add_array_item(cJSON *arr, cJSON *item) {
    if (!arr || !item) {
        if (item) cJSON_Delete(item);
        return FALSE;
    }
    if (!cJSON_AddItemToArray(arr, item)) {
        cJSON_Delete(item);
        return FALSE;
    }
    return TRUE;
}

static int db_save(db_manager_t *m, char *err_msg, size_t err_msg_sz) {
    cJSON *root = NULL, *j_schema = NULL, *j_entries = NULL, *j_filters = NULL;
    char *json_str = NULL, *enc = NULL, *tmp_path = NULL;
    int fd = -1;
    gboolean write_ok = FALSE;
    int rc = -1;
    gboolean save_with_pqc = FALSE;

    if (!m || !m->file_path || !m->recipient || !m->salt || m->salt_len != 32 ||
        !m->noise_key || m->noise_key_len != 32) {
        snprintf(err_msg, err_msg_sz, "Database state is incomplete");
        return -1;
    }
    save_with_pqc = db_recipient_has_pqc(m);
    if (m->entry_count < 0 || m->entry_count > DB_MAX_ENTRIES ||
        m->filter_count < 0 || m->filter_count > DB_MAX_FILTERS) {
        snprintf(err_msg, err_msg_sz, "Database exceeds configured resource limits");
        return -1;
    }
    if (!db_parent_directory_is_safe(m->file_path, err_msg, err_msg_sz))
        return -1;

    if (!i18n_language_code_valid(m->lang)) {
        snprintf(err_msg, err_msg_sz, "Invalid database language setting");
        return -1;
    }
    root = cJSON_CreateObject();
    j_schema = cJSON_CreateArray();
    j_entries = cJSON_CreateArray();
    j_filters = cJSON_CreateArray();
    if (!root || !j_schema || !j_entries || !j_filters) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed");
        goto cleanup;
    }
    if (!db_json_add_number(root, "version", DB_VERSION)) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed for database version");
        goto cleanup;
    }
    char *hex_salt = hex_encode(m->salt, m->salt_len);
    char *hex_noise = hex_encode(m->noise_key, m->noise_key_len);
    if (!hex_salt || !hex_noise) {
        free(hex_salt); free(hex_noise);
        snprintf(err_msg, err_msg_sz, "Hex encoding allocation failed");
        goto cleanup;
    }
    gboolean secrets_added = db_json_add_string(root, "salt", hex_salt) &&
        db_json_add_string(root, "noise_key", hex_noise);
    sodium_memzero(hex_salt, strlen(hex_salt)); free(hex_salt);
    sodium_memzero(hex_noise, strlen(hex_noise)); free(hex_noise);
    if (!secrets_added) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed for database secrets");
        goto cleanup;
    }
    gboolean seen_schema[SCHEMA_COUNT] = { FALSE, FALSE, FALSE, FALSE, FALSE };
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        int schema_idx = -1;
        if (m->schema_order[i]) {
            for (int j = 0; j < SCHEMA_COUNT; j++)
                if (strcmp(m->schema_order[i], SCHEMA_PARTS[j]) == 0) { schema_idx = j; break; }
        }
        if (schema_idx < 0 || seen_schema[schema_idx]) {
            snprintf(err_msg, err_msg_sz, "Database schema is invalid");
            goto cleanup;
        }
        seen_schema[schema_idx] = TRUE;
        cJSON *schema_item = cJSON_CreateString(m->schema_order[i]);
        if (!db_json_add_array_item(j_schema, schema_item)) {
            snprintf(err_msg, err_msg_sz, "JSON allocation failed for tag schema");
            goto cleanup;
        }
    }
    if (!cJSON_AddItemToObject(root, "schema", j_schema)) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed for tag schema");
        goto cleanup;
    }
    j_schema = NULL;
    if (!db_json_add_string(root, "lang", m->lang)) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed for language setting");
        goto cleanup;
    }

    for (int i = 0; i < m->entry_count; i++) {
        db_entry_t *e = &m->entries[i];
        if (!e->label || !e->type || !e->size || !e->cipher || !e->content_tag || !e->dsalt) {
            snprintf(err_msg, err_msg_sz, "Entry %d is incomplete", i + 1);
            goto cleanup;
        }
        if (strlen(e->label) > 127 || strlen(e->type) > 32 || strlen(e->size) > 32 ||
            strlen(e->cipher) > 32 || strlen(e->content_tag) != 2 || strlen(e->dsalt) != 2 ||
            (e->tag_full && strlen(e->tag_full) > 4096) ||
            (e->dpass && strlen(e->dpass) > 16384) ||
            (e->notes && strlen(e->notes) > 1024 * 1024) ||
            (e->alias && strlen(e->alias) > 4096) ||
            (e->files && strlen(e->files) > DB_MAX_INDEX_BYTES) ||
            (e->smart && strlen(e->smart) > 2 * 1024 * 1024) ||
            (e->uuid && strlen(e->uuid) > 256)) {
            snprintf(err_msg, err_msg_sz, "Entry %d exceeds a field safety limit", i + 1);
            goto cleanup;
        }
        char *canonical = db_encode_label(m, e->type, e->size, e->content_tag, e->cipher, e->dsalt);
        if (!canonical || strcmp(canonical, e->label) != 0) {
            free(canonical);
            snprintf(err_msg, err_msg_sz, "Entry %d label does not match its fields", i + 1);
            goto cleanup;
        }
        free(canonical);
        cJSON *je = cJSON_CreateObject();
        if (!je) { snprintf(err_msg, err_msg_sz, "JSON allocation failed"); goto cleanup; }
#define ADD_STRING_IF(field) do { \
            if (e->field && !db_json_add_string(je, #field, e->field)) { \
                cJSON_Delete(je); \
                snprintf(err_msg, err_msg_sz, "JSON allocation failed for entry %d", i + 1); \
                goto cleanup; \
            } \
        } while (0)
        ADD_STRING_IF(label); ADD_STRING_IF(type); ADD_STRING_IF(size); ADD_STRING_IF(cipher);
        ADD_STRING_IF(content_tag); ADD_STRING_IF(dsalt); ADD_STRING_IF(tag_full); ADD_STRING_IF(dpass);
        ADD_STRING_IF(notes); ADD_STRING_IF(alias);
        if ((e->files && e->files[0] && !db_json_add_string(je, "files", e->files)) ||
            (e->smart && e->smart[0] && !db_json_add_string(je, "smart", e->smart)) ||
            (e->uuid && e->uuid[0] && !db_json_add_string(je, "uuid", e->uuid)) ||
            (e->last_snapshot > 0 && !db_json_add_number(je, "last_snapshot", (double)e->last_snapshot))) {
            cJSON_Delete(je);
            snprintf(err_msg, err_msg_sz, "JSON allocation failed for entry %d", i + 1);
            goto cleanup;
        }
#undef ADD_STRING_IF
        if (!cJSON_AddItemToArray(j_entries, je)) {
            cJSON_Delete(je);
            snprintf(err_msg, err_msg_sz, "JSON allocation failed for entries array");
            goto cleanup;
        }
    }
    if (!cJSON_AddItemToObject(root, "entries", j_entries)) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed for entries array");
        goto cleanup;
    }
    j_entries = NULL;
    for (int i = 0; i < m->filter_count; i++) {
        if (!m->filters[i].name || !m->filters[i].exts ||
            strlen(m->filters[i].name) > 256 || strlen(m->filters[i].exts) > 4096) {
            snprintf(err_msg, err_msg_sz, "Filter %d is incomplete or exceeds a field limit", i + 1);
            goto cleanup;
        }
        cJSON *jf = cJSON_CreateObject();
        if (!jf) { snprintf(err_msg, err_msg_sz, "JSON allocation failed"); goto cleanup; }
        if (!db_json_add_string(jf, "name", m->filters[i].name) ||
            !db_json_add_string(jf, "exts", m->filters[i].exts)) {
            cJSON_Delete(jf);
            snprintf(err_msg, err_msg_sz, "JSON allocation failed for filter %d", i + 1);
            goto cleanup;
        }
        if (!cJSON_AddItemToArray(j_filters, jf)) {
            cJSON_Delete(jf);
            snprintf(err_msg, err_msg_sz, "JSON allocation failed for filters array");
            goto cleanup;
        }
    }
    if (!cJSON_AddItemToObject(root, "filters", j_filters)) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed for filters array");
        goto cleanup;
    }
    j_filters = NULL;
    json_str = cJSON_PrintUnformatted(root);
    if (!json_str) { snprintf(err_msg, err_msg_sz, "JSON print failed"); goto cleanup; }
    if (strlen(json_str) > DB_MAX_JSON_BYTES) {
        snprintf(err_msg, err_msg_sz, "Database JSON exceeds size limit");
        goto cleanup;
    }
    db_json_zero_strings(root);
    cJSON_Delete(root); root = NULL;

    enc = save_with_pqc
        ? db_gpg_encrypt(m, json_str, strlen(json_str), err_msg, err_msg_sz)
        : db_gpg_encrypt_legacy(m, json_str, strlen(json_str), err_msg, err_msg_sz);
    sodium_memzero(json_str, strlen(json_str));
    free(json_str); json_str = NULL;
    if (!enc) goto cleanup;

    size_t tmp_len = strlen(m->file_path) + sizeof(".tmp.XXXXXX");
    tmp_path = malloc(tmp_len);
    if (!tmp_path) { snprintf(err_msg, err_msg_sz, "Temporary path allocation failed"); goto cleanup; }
    snprintf(tmp_path, tmp_len, "%s.tmp.XXXXXX", m->file_path);
    fd = g_mkstemp_full(tmp_path, O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        snprintf(err_msg, err_msg_sz, "Cannot create safe temporary file: %s", strerror(errno));
        goto cleanup;
    }
    if (fchmod(fd, 0600) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot restrict temporary file permissions: %s", strerror(errno));
        goto cleanup;
    }

    size_t fp_len = strlen(m->recipient);
    size_t enc_len = strlen(enc);
    if (write_all_fd(fd, m->recipient, fp_len) != 0 ||
        write_all_fd(fd, "\n", 1) != 0 || write_all_fd(fd, enc, enc_len) != 0 ||
        fsync(fd) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot write database safely: %s", strerror(errno));
        goto cleanup;
    }
    if (close(fd) != 0) {
        fd = -1;
        snprintf(err_msg, err_msg_sz, "Cannot close temporary database: %s", strerror(errno));
        goto cleanup;
    }
    fd = -1;
    if (db_backup_existing_file(m->file_path, err_msg, err_msg_sz) != 0)
        goto cleanup;
    if (rename(tmp_path, m->file_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot atomically replace database: %s", strerror(errno));
        goto cleanup;
    }
    write_ok = TRUE;


    char *dir_copy = xstrdup(m->file_path);
    char *slash = strrchr(dir_copy, '/');
    const char *dir_name = ".";
    if (slash) {
        if (slash == dir_copy) { slash[1] = '\0'; dir_name = dir_copy; }
        else { *slash = '\0'; dir_name = dir_copy; }
    }
    int dfd = open(dir_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) { (void)fsync(dfd); close(dfd); }
    free(dir_copy);
    m->is_pqc_encrypted = save_with_pqc;
    rc = 0;
cleanup:
    if (fd >= 0) close(fd);
    if (!write_ok && tmp_path) unlink(tmp_path);
    if (root) { db_json_zero_strings(root); cJSON_Delete(root); }
    if (j_schema) { db_json_zero_strings(j_schema); cJSON_Delete(j_schema); }
    if (j_entries) { db_json_zero_strings(j_entries); cJSON_Delete(j_entries); }
    if (j_filters) { db_json_zero_strings(j_filters); cJSON_Delete(j_filters); }
    if (json_str) { sodium_memzero(json_str, strlen(json_str)); free(json_str); }
    if (enc) { sodium_memzero(enc, strlen(enc)); free(enc); }
    free(tmp_path);
    return rc;
}

static db_manager_t *db_manager_open(const char *path, const char *forced_key,
    char *err_msg, size_t err_msg_sz) {
    if (!path || !path[0]) {
        snprintf(err_msg, err_msg_sz, "Invalid database path");
        return NULL;
    }
    db_manager_t *m = calloc(1, sizeof(db_manager_t));
    if (!m) { snprintf(err_msg, err_msg_sz, "alloc failed"); return NULL; }
    db_manager_init(m);
    if (db_init_gpg(m, err_msg, err_msg_sz) != 0) { db_manager_clear(m); free(m); return NULL; }
    m->file_path = xstrdup(path);
    char *enc_data = NULL;
    if (db_read_file(path, &m->recipient, &enc_data, err_msg, err_msg_sz) != 0) { db_manager_clear(m); free(m); return NULL; }
    if (forced_key && g_ascii_strcasecmp(forced_key, m->recipient) != 0) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("key_mismatch"));
        free(enc_data); db_manager_clear(m); free(m); return NULL;
    }
    char *json_str = db_gpg_decrypt(m, enc_data, enc_data ? strlen(enc_data) : 0, err_msg, err_msg_sz);
    free(enc_data);
    if (!json_str) { db_manager_clear(m); free(m); return NULL; }
    int rc = db_load_json(m, json_str, err_msg, err_msg_sz);
    sec_strfree(json_str);
    if (rc != 0) { db_manager_clear(m); free(m); return NULL; }
    return m;
}

static db_manager_t *db_manager_create(const char *path, const char *recipient,
    const char *lang, char *err_msg, size_t err_msg_sz) {
    if (!path || !path[0]) {
        snprintf(err_msg, err_msg_sz, "Invalid database path");
        return NULL;
    }
    db_manager_t *m = calloc(1, sizeof(db_manager_t));
    if (!m) { snprintf(err_msg, err_msg_sz, "alloc failed"); return NULL; }
    db_manager_init(m);
    if (!recipient) { snprintf(err_msg, err_msg_sz, "%s", i18n("no_recipient")); db_manager_clear(m); free(m); return NULL; }
    if (db_init_gpg(m, err_msg, err_msg_sz) != 0) { db_manager_clear(m); free(m); return NULL; }
    m->file_path = xstrdup(path);
    m->recipient = xstrdup(recipient);
    m->salt = malloc(32); m->noise_key = sodium_malloc(32);
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
        if (slash == dir) slash[1] = '\0';
        else *slash = '\0';

        if (g_mkdir_with_parents(dir, 0700) != 0) {
            snprintf(err_msg, err_msg_sz, "Cannot create database directory: %s", g_strerror(errno));
            free(dir); db_manager_clear(m); free(m); return NULL;
        }
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

typedef struct {
    char part_name[32], block[8], val[8], decoded[64];
    char schar, expected_schar;
} parsed_block_t;

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
    secure_g_free_string(&n->name);
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

    size_t copy_len = strlen(files) + 1;
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
                cur->children = g_list_prepend(cur->children, child);
                g_hash_table_insert(cur->children_index, child->name, child);
            }
            if (is_last) child->size = sz;
            cur = child;
        }
        g_strfreev(parts);
    }
    sodium_memzero(copy, copy_len);
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
    if (!root || !root[0]) return NULL;

    GString *s = g_string_sized_new(256 * 1024);
    GQueue *queue = g_queue_new();
    if (!s || !queue) {
        if (s) g_string_free(s, TRUE);
        if (queue) g_queue_free(queue);
        return NULL;
    }

    char *root_copy = g_strdup(root);
    if (!root_copy) {
        g_string_free(s, TRUE);
        g_queue_free(queue);
        return NULL;
    }
    g_queue_push_tail(queue, root_copy);

    size_t root_len = strlen(root);
    size_t files_count = 0;
    size_t dirs_count = 0;
    gboolean exceeded = FALSE;

    static const char *skip_names[] = {
        "node_modules", ".cache", ".git", ".svn", ".hg",
        "proc", "sys", "dev", "run",
        "__pycache__", ".npm", ".cargo", ".rustup", ".gradle",
        ".thumbnails", "lost+found",
        NULL
    };

    while (!g_queue_is_empty(queue) && !exceeded) {
        char *dir = g_queue_pop_head(queue);
        if (++dirs_count > DB_MAX_INDEX_DIRS) {
            secure_g_free_string(&dir);
            exceeded = TRUE;
            break;
        }

        GError *dir_err = NULL;
        GDir *d = g_dir_open(dir, 0, &dir_err);
        if (!d) {
            if (dir_err) g_error_free(dir_err);
            secure_g_free_string(&dir);
            continue;
        }

        const char *name;
        while ((name = g_dir_read_name(d))) {
            gboolean skip = FALSE;
            for (int i = 0; skip_names[i]; i++) {
                if (strcmp(name, skip_names[i]) == 0) { skip = TRUE; break; }
            }
            if (skip) continue;

            char *full = g_build_filename(dir, name, NULL);
            struct stat st;
            if (!full || lstat(full, &st) != 0) {
                secure_g_free_string(&full);
                continue;
            }

            if (S_ISDIR(st.st_mode)) {
                if (g_queue_get_length(queue) >= DB_MAX_INDEX_QUEUED_DIRS) {
                    secure_g_free_string(&full);
                    exceeded = TRUE;
                    break;
                }
                g_queue_push_tail(queue, full);
            } else if (S_ISREG(st.st_mode)) {
                const char *rel = full + root_len;
                while (*rel == '/' || *rel == '\\') rel++;
                if (strchr(rel, '\n') || strchr(rel, '\r') || strchr(rel, '\t')) {
                    secure_g_free_string(&full);
                    continue;
                }
                size_t need = strlen(rel) + 32;
                if (files_count >= DB_MAX_INDEX_FILES ||
                    need > DB_MAX_INDEX_BYTES - s->len) {
                    secure_g_free_string(&full);
                    exceeded = TRUE;
                    break;
                }
                g_string_append_printf(s, "%s\t%lld\n", rel, (long long)st.st_size);
                files_count++;
                secure_g_free_string(&full);
            } else {
                secure_g_free_string(&full);
            }
        }
        g_dir_close(d);
        secure_g_free_string(&dir);
    }

    while (!g_queue_is_empty(queue)) {
        char *pending = g_queue_pop_head(queue);
        secure_g_free_string(&pending);
    }
    g_queue_free(queue);

    if (exceeded) {
        fprintf(stderr,
            "scan_directory_recursive: exceeded limits "
            "(files=%zu, dirs=%zu, bytes=%zu)\n",
            files_count, dirs_count, s->len);
        sodium_memzero(s->str, s->len + 1);
        g_string_free(s, TRUE);
        return NULL;
    }

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
        secure_g_free_string(&list[i].device);
        secure_g_free_string(&list[i].uuid);
        secure_g_free_string(&list[i].size_h);
        secure_g_free_string(&list[i].fstype);
        secure_g_free_string(&list[i].mountpoint);
        secure_g_free_string(&list[i].model);
        secure_g_free_string(&list[i].transport);
        secure_g_free_string(&list[i].label);
    }
    free(list);
}

static gboolean uuid_is_connected(const char *uuid) {
    if (!uuid || !uuid[0] || strlen(uuid) > 128) return FALSE;
    for (const unsigned char *p = (const unsigned char *)uuid; *p; p++) {
        if (!(g_ascii_isxdigit(*p) || *p == '-')) return FALSE;
    }
    char path[160];
    int n = snprintf(path, sizeof(path), "/dev/disk/by-uuid/%s", uuid);
    if (n < 0 || (size_t)n >= sizeof(path)) return FALSE;
    return access(path, F_OK) == 0;
}

static gboolean walk_lsblk(cJSON *arr, disk_info_t **list, int *count, int *cap) {
    if (!arr || !list || !count || !cap) return FALSE;
    int n = cJSON_GetArraySize(arr);
    for (int i = 0; i < n; i++) {
        cJSON *dev = cJSON_GetArrayItem(arr, i);
        cJSON *j_uuid = cJSON_GetObjectItem(dev, "uuid");
        cJSON *j_path = cJSON_GetObjectItem(dev, "path");
        if (j_uuid && cJSON_IsString(j_uuid) && j_uuid->valuestring[0] &&
            j_path && cJSON_IsString(j_path)) {

            if (*count >= *cap) {
                if (*cap > INT_MAX / 2) return FALSE;
                int new_cap = *cap ? (*cap) * 2 : 16;
                if ((size_t)new_cap > SIZE_MAX / sizeof(disk_info_t)) return FALSE;
                disk_info_t *tmp = realloc(*list, (size_t)new_cap * sizeof(disk_info_t));
                if (!tmp) return FALSE;
                *list = tmp;
                *cap = new_cap;
            }
            disk_info_t *d = &(*list)[*count];
            memset(d, 0, sizeof(*d));

            d->device = g_strdup(j_path->valuestring);
            d->uuid = g_strdup(j_uuid->valuestring);

            cJSON *j_size = cJSON_GetObjectItem(dev, "size");
            if (j_size && cJSON_IsNumber(j_size)) {
                d->size_bytes = (long long)j_size->valuedouble;
                d->size_h = format_bytes(d->size_bytes);
            } else {
                d->size_h = g_strdup("?");
            }

            cJSON *j_fs = cJSON_GetObjectItem(dev, "fstype");
            if (j_fs && cJSON_IsString(j_fs)) d->fstype = g_strdup(j_fs->valuestring);

            cJSON *j_mnt = cJSON_GetObjectItem(dev, "mountpoint");
            if (j_mnt && cJSON_IsString(j_mnt) && j_mnt->valuestring[0])
                d->mountpoint = g_strdup(j_mnt->valuestring);

            cJSON *j_model = cJSON_GetObjectItem(dev, "model");
            if (j_model && cJSON_IsString(j_model)) d->model = g_strdup(j_model->valuestring);

            cJSON *j_tran = cJSON_GetObjectItem(dev, "tran");
            if (j_tran && cJSON_IsString(j_tran)) d->transport = g_strdup(j_tran->valuestring);

            cJSON *j_label = cJSON_GetObjectItem(dev, "label");
            if (j_label && cJSON_IsString(j_label) && j_label->valuestring[0])
                d->label = g_strdup(j_label->valuestring);

            d->connected = TRUE;
            (*count)++;
        }

        cJSON *children = cJSON_GetObjectItem(dev, "children");
        if (children && cJSON_IsArray(children) &&
            !walk_lsblk(children, list, count, cap))
            return FALSE;
    }
    return TRUE;
}

static disk_info_t *list_disks(int *out_count) {
    *out_count = 0;
    gchar *argv[] = { "/usr/bin/lsblk", "-J", "-b",
        "-o", "PATH,UUID,SIZE,FSTYPE,MOUNTPOINT,MODEL,TRAN,TYPE,LABEL",
        NULL };
    gchar *out = NULL;
    GError *err = NULL;
    gint status = 0;
    if (!g_spawn_sync(NULL, argv, NULL, 0,
            NULL, NULL, &out, NULL, &status, &err)) {
        if (err) g_error_free(err);
        secure_g_free_string(&out);
        return NULL;
    }
    if (!out || status != 0) { secure_g_free_string(&out); return NULL; }

    cJSON *root = cJSON_Parse(out);
    secure_g_free_string(&out);
    if (!root) return NULL;

    cJSON *devices = cJSON_GetObjectItem(root, "blockdevices");
    if (!devices || !cJSON_IsArray(devices)) {
        db_json_zero_strings(root);
        cJSON_Delete(root);
        return NULL;
    }

    disk_info_t *list = NULL;
    int count = 0, cap = 0;
    if (!walk_lsblk(devices, &list, &count, &cap)) {
        free_disk_list(list, count);
        db_json_zero_strings(root);
        cJSON_Delete(root);
        return NULL;
    }
    db_json_zero_strings(root);
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
        if (mnt_len > 1 && use[mnt_len] != '\0' && use[mnt_len] != '/') continue;
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
    if (strncmp(dev, "/dev/", 5) != 0) { secure_free_string(&dev); return NULL; }

    gchar *argv[] = { "/usr/bin/lsblk", "-no", "UUID", dev, NULL };
    gchar *out = NULL;
    GError *err = NULL;
    if (!g_spawn_sync(NULL, argv, NULL, 0,
            NULL, NULL, &out, NULL, NULL, &err)) {
        if (err) g_error_free(err);
        secure_free_string(&dev);
        secure_g_free_string(&out);
        return NULL;
    }
    secure_free_string(&dev);
    if (!out) return NULL;

    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
    char *res = out[0] ? xstrdup(out) : NULL;
    secure_g_free_string(&out);
    return res;
}

static void json_set_string(cJSON *obj, const char *key, const char *value) {
    if (!obj || !key || !value) return;
    cJSON *item = cJSON_CreateString(value);
    if (!item) return;
    if (cJSON_GetObjectItemCaseSensitive(obj, key)) {
        if (!cJSON_ReplaceItemInObjectCaseSensitive(obj, key, item)) cJSON_Delete(item);
    } else if (!cJSON_AddItemToObject(obj, key, item)) {
        cJSON_Delete(item);
    }
}

static char *collect_smart_data(const char *mount_path) {
    if (!mount_path) return NULL;
    char *dev = find_device_for_path(mount_path);
    if (!dev) return NULL;
    if (strncmp(dev, "/dev/", 5) != 0) { secure_free_string(&dev); return NULL; }

    gchar *smartctl = g_find_program_in_path("smartctl");
    if (!smartctl && g_file_test("/usr/sbin/smartctl", G_FILE_TEST_IS_EXECUTABLE))
        smartctl = g_strdup("/usr/sbin/smartctl");
    if (!smartctl && g_file_test("/usr/bin/smartctl", G_FILE_TEST_IS_EXECUTABLE))
        smartctl = g_strdup("/usr/bin/smartctl");
    if (!smartctl) { secure_free_string(&dev); return NULL; }

    gchar *argv[] = { smartctl, "-j", "-H", "-i", "-A", dev, NULL };
    gchar *stdout_buf = NULL;
    gint exit_status = 0;
    GError *serr = NULL;
    gboolean ok = g_spawn_sync(NULL, argv, NULL,
        G_SPAWN_STDERR_TO_DEV_NULL,
        NULL, NULL, &stdout_buf, NULL, &exit_status, &serr);
    g_free(smartctl);
    secure_free_string(&dev);

    if (!ok || !stdout_buf || !stdout_buf[0]) {
        if (serr) g_error_free(serr);
        secure_g_free_string(&stdout_buf);
        return NULL;
    }
    if (serr) g_error_free(serr);
    (void)exit_status;

    cJSON *root = cJSON_Parse(stdout_buf);
    secure_g_free_string(&stdout_buf);
    if (!root) return NULL;

    cJSON *result = cJSON_CreateObject();
    if (!result) { db_json_zero_strings(root); cJSON_Delete(root); return NULL; }

    cJSON *model = cJSON_GetObjectItem(root, "model_name");
    if (!model) model = cJSON_GetObjectItem(root, "device_model");
    if (model && cJSON_IsString(model))
        json_set_string(result, "model", model->valuestring);

    cJSON *serial = cJSON_GetObjectItem(root, "serial_number");
    if (serial && cJSON_IsString(serial))
        json_set_string(result, "serial", serial->valuestring);

    cJSON *fw = cJSON_GetObjectItem(root, "firmware_version");
    if (fw && cJSON_IsString(fw))
        json_set_string(result, "firmware", fw->valuestring);

    cJSON *cap = cJSON_GetObjectItem(root, "user_capacity");
    if (cap) {
        cJSON *bytes = cJSON_GetObjectItem(cap, "bytes");
        if (bytes && cJSON_IsNumber(bytes)) {
            char *v = format_bytes((long long)bytes->valuedouble);
            if (v) { json_set_string(result, "capacity", v); g_free(v); }
        }
    }

    cJSON *status = cJSON_GetObjectItem(root, "smart_status");
    if (status) {
        cJSON *passed = cJSON_GetObjectItem(status, "passed");
        if (cJSON_IsBool(passed))
            json_set_string(result, "health", cJSON_IsTrue(passed) ? "PASSED" : "FAILED");
    }

    cJSON *temp = cJSON_GetObjectItem(root, "temperature");
    if (temp) {
        cJSON *cur = cJSON_GetObjectItem(temp, "current");
        if (cur && cJSON_IsNumber(cur)) {
            char t[32]; snprintf(t, sizeof(t), "%.0f °C", cur->valuedouble);
            json_set_string(result, "temperature", t);
        }
    }

    cJSON *pot = cJSON_GetObjectItem(root, "power_on_time");
    if (pot) {
        cJSON *h = cJSON_GetObjectItem(pot, "hours");
        if (h && cJSON_IsNumber(h)) {
            char t[32]; snprintf(t, sizeof(t), "%.0f", h->valuedouble);
            json_set_string(result, "hours", t);
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
                cJSON *val = raw ? cJSON_GetObjectItem(raw, "value") : NULL;
                if (!val || !cJSON_IsNumber(val)) continue;

                const char *nm = name->valuestring;
                char t[32]; snprintf(t, sizeof(t), "%.0f", val->valuedouble);
                if (strcmp(nm, "Reallocated_Sector_Ct") == 0)
                    json_set_string(result, "reallocated", t);
                else if (strcmp(nm, "Power_Cycle_Count") == 0)
                    json_set_string(result, "power_cycles", t);
                else if (strcmp(nm, "Wear_Leveling_Count") == 0 ||
                         strcmp(nm, "Media_Wearout_Indicator") == 0 ||
                         strcmp(nm, "Percentage_Used") == 0)
                    json_set_string(result, "wear", t);
                else if (strcmp(nm, "UDMA_CRC_Error_Count") == 0 ||
                         strcmp(nm, "CRC_Error_Count") == 0)
                    json_set_string(result, "crc_errors", t);
            }
        }
    }

    cJSON *nvme = cJSON_GetObjectItem(root, "nvme_smart_health_information_log");
    if (nvme && cJSON_IsObject(nvme)) {
        struct { const char *src; const char *dst; } nv_fields[] = {
            {"power_on_hours", "hours"},
            {"power_cycles", "power_cycles"},
            {"percentage_used", "wear"},
            {"media_errors", "media_errors"},
            {"unsafe_shutdowns", "unsafe_shutdowns"},
            {"available_spare", "available_spare"},
            {"critical_warning", "critical_warning"}
        };
        for (size_t i = 0; i < ARRAY_SIZE(nv_fields); i++) {
            cJSON *v = cJSON_GetObjectItem(nvme, nv_fields[i].src);
            if (v && cJSON_IsNumber(v)) {
                char t[48];
                if (strcmp(nv_fields[i].src, "percentage_used") == 0 ||
                    strcmp(nv_fields[i].src, "available_spare") == 0)
                    snprintf(t, sizeof(t), "%.0f%%", v->valuedouble);
                else
                    snprintf(t, sizeof(t), "%.0f", v->valuedouble);
                json_set_string(result, nv_fields[i].dst, t);
            }
        }
        cJSON *nvtemp = cJSON_GetObjectItem(nvme, "temperature");
        if (nvtemp && cJSON_IsNumber(nvtemp) && !cJSON_GetObjectItem(result, "temperature")) {
            char t[32]; snprintf(t, sizeof(t), "%.0f °C", nvtemp->valuedouble);
            json_set_string(result, "temperature", t);
        }
        if (!cJSON_GetObjectItem(result, "health")) {
            cJSON *cw = cJSON_GetObjectItem(nvme, "critical_warning");
            cJSON *me = cJSON_GetObjectItem(nvme, "media_errors");
            gboolean failed = cw && cJSON_IsNumber(cw) && cw->valuedouble != 0;
            gboolean warning = me && cJSON_IsNumber(me) && me->valuedouble > 0;
            json_set_string(result, "health", failed ? "FAILED" : (warning ? "WARNING" : "PASSED"));
        }
    }

    db_json_zero_strings(root);
    cJSON_Delete(root);
    char *final = cJSON_PrintUnformatted(result);
    db_json_zero_strings(result);
    cJSON_Delete(result);
    return final;
}

static int db_set_entry_snapshot(db_manager_t *m, const char *label,
    const char *files, const char *smart_json,
    char *err_msg, size_t err_msg_sz)
{
    if (!m || !label || !files || strlen(files) > DB_MAX_INDEX_BYTES ||
        (smart_json && strlen(smart_json) > 2 * 1024 * 1024)) {
        snprintf(err_msg, err_msg_sz, "Index scan failed or exceeded safety limits; previous snapshot was kept");
        return -1;
    }
    for (int i = 0; i < m->entry_count; i++) {
        if (strcmp(m->entries[i].label, label) == 0) {
            char *new_files = (files && files[0]) ? xstrdup(files) : NULL;
            char *new_smart = (smart_json && smart_json[0]) ? xstrdup(smart_json) : NULL;
            char *old_files = m->entries[i].files;
            char *old_smart = m->entries[i].smart;
            long long old_snapshot = m->entries[i].last_snapshot;
            m->entries[i].files = new_files;
            m->entries[i].smart = new_smart;
            m->entries[i].last_snapshot = (long long)time(NULL);
            if (db_save(m, err_msg, err_msg_sz) != 0) {
                secure_free_string(&m->entries[i].files);
                secure_free_string(&m->entries[i].smart);
                m->entries[i].files = old_files;
                m->entries[i].smart = old_smart;
                m->entries[i].last_snapshot = old_snapshot;
                return -1;
            }
            secure_free_string(&old_files);
            secure_free_string(&old_smart);
            return 0;
        }
    }
    return -1;
}

static int db_set_entry_smart(db_manager_t *m, const char *label, const char *smart_json,
    char *err_msg, size_t err_msg_sz)
{
    if (!m || !label || !smart_json || !smart_json[0] || strlen(smart_json) > 2 * 1024 * 1024) {
        snprintf(err_msg, err_msg_sz, "SMART data is missing or exceeds the safety limit");
        return -1;
    }
    for (int i = 0; i < m->entry_count; i++) {
        if (m->entries[i].label && strcmp(m->entries[i].label, label) == 0) {
            char *replacement = xstrdup(smart_json);
            char *old = m->entries[i].smart;
            m->entries[i].smart = replacement;
            if (db_save(m, err_msg, err_msg_sz) != 0) {
                secure_free_string(&m->entries[i].smart);
                m->entries[i].smart = old;
                return -1;
            }
            secure_free_string(&old);
            return 0;
        }
    }
    snprintf(err_msg, err_msg_sz, "Database entry was not found");
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
    size_t copy_len = strlen(files) + 1;
    char *copy = xstrdup(files);
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *tab = strchr(line, '\t');
        if (tab) total += atoll(tab + 1);
    }
    sodium_memzero(copy, copy_len);
    free(copy);
    return total;
}

static int db_add_entry(db_manager_t *m, const char *type, const char *size,
    const char *cipher, const char *content_tag, const char *dsalt,
    const char *tag_full, const char *dpass, const char *notes,
    const char *alias, const char *uuid,
    char *err_msg, size_t err_msg_sz) {
    if (!m || !type || !size || !cipher || !content_tag || !dsalt ||
        !map_has_name(TYPE_MAP, TYPE_MAP_N, type) ||
        !map_has_name(SIZE_MAP, SIZE_MAP_N, size) ||
        !map_has_name(CIPHER_MAP, CIPHER_MAP_N, cipher) ||
        strlen(content_tag) != 2 || !valid_ascii_tag_char((unsigned char)content_tag[0]) ||
        !valid_ascii_tag_char((unsigned char)content_tag[1]) ||
        !valid_alphabet_string(dsalt, 2)) {
        snprintf(err_msg, err_msg_sz, "Invalid tag fields: use a known type, size and cipher, a two-character alphanumeric tag, and a valid salt");
        return -1;
    }
    if ((tag_full && strlen(tag_full) > 4096) ||
        (dpass && strlen(dpass) > 16384) ||
        (notes && strlen(notes) > 1024 * 1024) ||
        (alias && strlen(alias) > 4096) ||
        (uuid && strlen(uuid) > 256)) {
        snprintf(err_msg, err_msg_sz, "Entry field exceeds configured safety limit");
        return -1;
    }
    if (m->entry_count >= DB_MAX_ENTRIES) {
        snprintf(err_msg, err_msg_sz, "Database entry limit reached");
        return -1;
    }
    if (m->entry_count >= m->entry_cap) {
        int new_cap = m->entry_cap > DB_MAX_ENTRIES / 2 ? DB_MAX_ENTRIES : m->entry_cap * 2;
        db_entry_t *ne = realloc(m->entries, new_cap * sizeof(db_entry_t));
        if (!ne) { snprintf(err_msg, err_msg_sz, "alloc failed"); return -1; }
        memset(ne + m->entry_cap, 0, (new_cap - m->entry_cap) * sizeof(db_entry_t));
        m->entries = ne; m->entry_cap = new_cap;
    }
    db_entry_t *e = &m->entries[m->entry_count];
    db_entry_init(e);
    e->label = db_encode_label(m, type, size, content_tag, cipher, dsalt);
    if (!e->label) {
        snprintf(err_msg, err_msg_sz, "Cannot encode invalid tag fields");
        return -1;
    }
    e->type = xstrdup(type); e->size = xstrdup(size); e->cipher = xstrdup(cipher);
    e->content_tag = xstrdup(content_tag); e->dsalt = xstrdup(dsalt);
    e->tag_full = xstrdup(tag_full ? tag_full : "");
    if (dpass && dpass[0]) e->dpass = sec_strdup(dpass);
    if (notes) e->notes = xstrdup(notes);
    if (alias && alias[0]) e->alias = xstrdup(alias);
    if (uuid && uuid[0]) e->uuid = xstrdup(uuid);
    m->entry_count++;
    if (db_save(m, err_msg, err_msg_sz) != 0) {
        m->entry_count--;
        db_entry_clear(&m->entries[m->entry_count]);
        memset(&m->entries[m->entry_count], 0, sizeof(db_entry_t));
        return -1;
    }
    return 0;
}

static int db_remove_entry(db_manager_t *m, const char *label, char *err_msg, size_t err_msg_sz) {
    if (!m || !label) return -1;
    for (int i = 0; i < m->entry_count; i++) {
        if (strcmp(m->entries[i].label, label) == 0) {
            db_entry_t removed = m->entries[i];
            int old_count = m->entry_count;
            memmove(&m->entries[i], &m->entries[i+1],
                (size_t)(old_count - i - 1) * sizeof(db_entry_t));
            m->entry_count--;
            memset(&m->entries[m->entry_count], 0, sizeof(db_entry_t));
            if (db_save(m, err_msg, err_msg_sz) != 0) {
                memmove(&m->entries[i+1], &m->entries[i],
                    (size_t)(m->entry_count - i) * sizeof(db_entry_t));
                m->entries[i] = removed;
                m->entry_count++;
                memset(&m->entries[m->entry_count], 0, sizeof(db_entry_t));
                return -1;
            }
            db_entry_clear(&removed);
            return 0;
        }
    }
    return -1;
}

static int db_update_entry(db_manager_t *m, const char *label,
    const char *new_dpass, const char *new_notes,
    const char *new_alias,
    char *err_msg, size_t err_msg_sz) {
    if (!m || !label) return -1;
    if ((new_dpass && strlen(new_dpass) > 16384) ||
        (new_notes && strlen(new_notes) > 1024 * 1024) ||
        (new_alias && strlen(new_alias) > 4096)) {
        snprintf(err_msg, err_msg_sz, "Updated field exceeds configured safety limit");
        return -1;
    }
    for (int i = 0; i < m->entry_count; i++) {
        if (strcmp(m->entries[i].label, label) == 0) {
            char *replacement_pass = (new_dpass && new_dpass[0]) ? sec_strdup(new_dpass) : NULL;
            char *replacement_notes = new_notes ? xstrdup(new_notes) : NULL;
            char *replacement_alias = (new_alias && new_alias[0]) ? xstrdup(new_alias) : NULL;
            char *old_pass = m->entries[i].dpass;
            char *old_notes = m->entries[i].notes;
            char *old_alias = m->entries[i].alias;
            m->entries[i].dpass = replacement_pass;
            m->entries[i].notes = replacement_notes;
            m->entries[i].alias = replacement_alias;
            if (db_save(m, err_msg, err_msg_sz) != 0) {
                if (m->entries[i].dpass) sec_strfree(m->entries[i].dpass);
                secure_free_string(&m->entries[i].notes);
                secure_free_string(&m->entries[i].alias);
                m->entries[i].dpass = old_pass;
                m->entries[i].notes = old_notes;
                m->entries[i].alias = old_alias;
                return -1;
            }
            if (old_pass) sec_strfree(old_pass);
            secure_free_string(&old_notes);
            secure_free_string(&old_alias);
            return 0;
        }
    }
    return -1;
}

typedef struct {
    char *fingerprint;
    char *uid;
    gboolean has_pqc;
} gpg_key_info_t;

