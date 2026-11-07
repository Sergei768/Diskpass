#include "diskpass.h"
#include <inttypes.h>
#include <sys/file.h>
#include <webp/encode.h>
#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/mman.h>
#endif

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
#define DB_MAX_HISTORY 256
#define DB_HISTORY_ACTION_MAX 48
#define DB_HISTORY_TARGET_MAX 256
#define DB_MAX_INDEX_BYTES (128ULL * 1024ULL * 1024ULL)
#define DB_MAX_INDEX_FILES 2000000ULL
#define DB_MAX_INDEX_DEPTH 128U
#define DB_MAX_INDEX_LINE_BYTES (64U * 1024U)
#define DB_MAX_TREE_RENDER_NODES 250000U
#define DB_MAX_INDEX_QUEUED_DIRS 100000ULL
#define DB_MAX_INDEX_DIRS 1000000ULL
#define DB_ID_HEX_LEN 32
#define DB_COMMIT_HEX_LEN 64
#define DB_COMMIT_ALG_V1 "v1"
#define DB_COMMIT_ALG_V2 "v2"
#define DB_STATE_KEY_BYTES 32
#define DB_STATE_MAC_BYTES crypto_auth_hmacsha256_BYTES
#define DB_CONTAINER_MAGIC "DISKPASS3"
#define DB_SECURITY_PQC "pqc-v1"
#define DB_OPAQUE_ENVELOPE_SLOT (16U * 1024U)
#define DB_OPAQUE_COMPACT_ENVELOPE_SLOT (8U * 1024U)
#define DB_OPAQUE_COMPACT_FLAG 0x8000U
#define DB_OPAQUE_OFFSET_MASK 0x7FFFU
#define DB_OPAQUE_HEADER_BYTES 4U
#define DB_OPAQUE_MIN_ENVELOPE 64U
#define DB_OPAQUE_ENV_TAG "DPENV4"
#define DB_OPAQUE_AAD "DiskPass opaque payload v4"
#define DB_SECURITY_CLASSIC "classic-v1"
#define DB_CARRIER_MAX_BYTES (16ULL * 1024ULL * 1024ULL * 1024ULL)

typedef union {
    max_align_t align;
    struct { size_t size; } meta;
} secure_json_header_t;

static void *secure_json_malloc(size_t size) {
    if (size > SIZE_MAX - sizeof(secure_json_header_t)) return NULL;
    secure_json_header_t *h = malloc(sizeof(*h) + size);
    if (!h) return NULL;
    h->meta.size = size;
    return (void *)(h + 1);
}

static void secure_json_free(void *ptr) {
    if (!ptr) return;
    secure_json_header_t *h = ((secure_json_header_t *)ptr) - 1;
    size_t size = h->meta.size;
    if (size <= SIZE_MAX - sizeof(*h)) sodium_memzero(ptr, size);
    sodium_memzero(h, sizeof(*h));
    free(h);
}

static void db_install_secure_cjson_hooks(void) {
    cJSON_Hooks hooks = {
        .malloc_fn = secure_json_malloc,
        .free_fn = secure_json_free
    };
    cJSON_InitHooks(&hooks);
}

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

static void secure_free_cb(gpointer p) {
    if (!p) return;
    sodium_memzero(p, strlen((const char *)p) + 1);
    free(p);
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


            sodium_memzero(cur->valuestring, strlen(cur->valuestring) + 1);
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
            for (cJSON *a = cur->child; a; a = a->next)
                if (++members > 128) return TRUE;
            for (cJSON *a = cur->child; a; a = a->next) {
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

static gboolean db_path_has_dpdb_extension(const char *path) {
    if (!path) return FALSE;
    size_t n = strlen(path);
    return n >= 5 && g_ascii_strcasecmp(path + n - 5, ".dpdb") == 0;
}

static void db_store_u16le(unsigned char out[2], uint16_t v) {
    out[0] = (unsigned char)(v & 0xffU);
    out[1] = (unsigned char)((v >> 8) & 0xffU);
}

static uint16_t db_load_u16le(const unsigned char in[2]) {
    return (uint16_t)in[0] | ((uint16_t)in[1] << 8);
}

static void db_store_u64le(unsigned char out[8], uint64_t v) {
    for (unsigned i = 0; i < 8; i++) out[i] = (unsigned char)(v >> (i * 8U));
}

static uint64_t db_load_u64le(const unsigned char in[8]) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) v |= ((uint64_t)in[i]) << (i * 8U);
    return v;
}

static const uint64_t DB_OPAQUE_BUCKETS[] = {
    64ULL * 1024ULL,
    256ULL * 1024ULL,
    1ULL * 1024ULL * 1024ULL,
    4ULL * 1024ULL * 1024ULL,
    16ULL * 1024ULL * 1024ULL,
    64ULL * 1024ULL * 1024ULL,
    128ULL * 1024ULL * 1024ULL,
    256ULL * 1024ULL * 1024ULL,
    320ULL * 1024ULL * 1024ULL
};

static size_t db_opaque_bucket_size(size_t need, gboolean compact) {
    if (compact) {

        const size_t quantum = 1024U;
        if (need == 0 || need > (size_t)DB_MAX_JSON_BYTES + 8U ||
            need > SIZE_MAX - (quantum - 1U)) return 0;
        size_t rounded = ((need + quantum - 1U) / quantum) * quantum;
        return rounded < quantum ? quantum : rounded;
    }
    for (size_t i = 0; i < ARRAY_SIZE(DB_OPAQUE_BUCKETS); i++)
        if ((uint64_t)need <= DB_OPAQUE_BUCKETS[i]) return (size_t)DB_OPAQUE_BUCKETS[i];
    return 0;
}

static gboolean db_opaque_payload_size_valid(size_t n, gboolean compact) {
    if (compact)
        return n >= 1024U && n <= (size_t)DB_MAX_JSON_BYTES + 8U && (n % 1024U) == 0;
    for (size_t i = 0; i < ARRAY_SIZE(DB_OPAQUE_BUCKETS); i++)
        if ((uint64_t)n == DB_OPAQUE_BUCKETS[i]) return TRUE;
    return FALSE;
}

static gboolean db_opaque_header_layout(const unsigned char hdr[4], gboolean *compact,
    size_t *slot_size, uint16_t *env_off, uint16_t *env_len)
{
    if (!hdr || !slot_size || !env_off || !env_len) return FALSE;
    uint16_t off_field = db_load_u16le(hdr);
    gboolean is_compact = (off_field & DB_OPAQUE_COMPACT_FLAG) != 0;
    uint16_t off = (uint16_t)(off_field & DB_OPAQUE_OFFSET_MASK);
    uint16_t len = db_load_u16le(hdr + 2);
    size_t slot = is_compact ? DB_OPAQUE_COMPACT_ENVELOPE_SLOT : DB_OPAQUE_ENVELOPE_SLOT;
    if (len < DB_OPAQUE_MIN_ENVELOPE || len > slot || (size_t)off + (size_t)len > slot)
        return FALSE;
    if (compact) *compact = is_compact;
    *slot_size = slot;
    *env_off = off;
    *env_len = len;
    return TRUE;
}

static int db_read_raw_file(const char *path, unsigned char **out, size_t *out_len,
    char *err_msg, size_t err_msg_sz)
{
    if (!path || !out || !out_len) return -1;
    *out = NULL; *out_len = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        snprintf(err_msg, err_msg_sz, "Cannot open file safely: %s", strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > (uint64_t)DB_MAX_FILE_BYTES) {
        snprintf(err_msg, err_msg_sz, "Invalid database file type or size limit exceeded");
        close(fd); return -1;
    }

    if (st.st_nlink != 1) {
        snprintf(err_msg, err_msg_sz,
            "Database file has multiple hard links; refusing to open (potential attack).");
        close(fd); return -1;
    }
    size_t len = (size_t)st.st_size;
    unsigned char *buf = malloc(len);
    if (!buf) { close(fd); snprintf(err_msg, err_msg_sz, "Out of memory while reading database"); return -1; }
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            snprintf(err_msg, err_msg_sz, "Error while reading database");
            sodium_memzero(buf, len); free(buf); close(fd); return -1;
        }
        off += (size_t)n;
    }
    if (close(fd) != 0) {
        sodium_memzero(buf, len); free(buf);
        snprintf(err_msg, err_msg_sz, "Error while closing database"); return -1;
    }
    *out = buf; *out_len = len; return 0;
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


static gboolean db_generation_valid(const char *s) {
    if (!s || !*s) return FALSE;
    size_t len = strnlen(s, 21);
    if (len > 20) return FALSE;
    for (size_t i = 0; i < len; i++)
        if (s[i] < '0' || s[i] > '9') return FALSE;
    return TRUE;
}

static gboolean db_hex_string_valid(const char *s, size_t expected_len);
static char *db_rollback_state_dir(void);

static char *db_backup_pointer_path(const char *db_id) {
    if (!db_hex_string_valid(db_id, DB_ID_HEX_LEN)) return NULL;
    char *dir = db_rollback_state_dir();
    if (!dir) return NULL;
    char name[DB_ID_HEX_LEN + 20];
    snprintf(name, sizeof(name), "%s.backup", db_id);
    char *path = g_build_filename(dir, name, NULL);
    g_free(dir);
    return path;
}

static char *db_read_backup_pointer(const char *db_id) {
    char *state_path = db_backup_pointer_path(db_id);
    if (!state_path) return NULL;
    int fd = open(state_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    g_free(state_path);
    if (fd < 0) return NULL;
    struct stat st;
    char buf[PATH_MAX + 1];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    gboolean ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        (st.st_mode & 077) == 0 && n > 0 && n < (ssize_t)sizeof(buf) - 1;
    close(fd);
    if (!ok) return NULL;
    buf[n] = '\0';
    char *nl = strpbrk(buf, "\r\n"); if (nl) *nl = '\0';
    if (!buf[0] || !db_path_has_dpdb_extension(buf)) return NULL;
    return xstrdup(buf);
}

static gboolean db_write_backup_pointer(const char *db_id, const char *backup_path) {
    char *dir = db_rollback_state_dir();
    char *path = db_backup_pointer_path(db_id);
    if (!dir || !path || !backup_path || !db_path_has_dpdb_extension(backup_path)) {
        g_free(dir); g_free(path); return FALSE;
    }
    if (g_mkdir_with_parents(dir, 0700) != 0) { g_free(dir); g_free(path); return FALSE; }
    (void)chmod(dir, 0700);
    size_t tlen = strlen(path) + sizeof(".tmp.XXXXXX");
    char *tmp = malloc(tlen);
    if (!tmp) { g_free(dir); g_free(path); return FALSE; }
    snprintf(tmp, tlen, "%s.tmp.XXXXXX", path);
    int fd = g_mkstemp_full(tmp, O_WRONLY | O_CLOEXEC, 0600);
    gboolean ok = FALSE;
    if (fd >= 0) {
        size_t n = strlen(backup_path);
        ok = write_all_fd(fd, backup_path, n) == 0 && write_all_fd(fd, "\n", 1) == 0 && fsync(fd) == 0;
        if (close(fd) != 0) ok = FALSE;
        if (ok && rename(tmp, path) != 0) ok = FALSE;
        if (ok) {
            int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (dfd >= 0) { (void)fsync(dfd); close(dfd); }
        }
    }
    if (!ok) unlink(tmp);
    free(tmp); g_free(dir); g_free(path);
    return ok;
}

static gboolean db_private_backup_path_valid(const char *main_path, const char *backup_path) {
    if (!main_path || !backup_path) return FALSE;
    gchar *main_dir = g_path_get_dirname(main_path);
    gchar *bak_dir = g_path_get_dirname(backup_path);
    gchar *base = g_path_get_basename(backup_path);
    gboolean ok = main_dir && bak_dir && base && strcmp(main_dir, bak_dir) == 0;
    if (ok) {
        size_t n = strlen(base);
        ok = n == 38 && base[0] == '.' && g_ascii_strcasecmp(base + 33, ".dpdb") == 0;
        for (size_t i = 1; ok && i <= 32; i++) if (!g_ascii_isxdigit((guchar)base[i])) ok = FALSE;
    }
    g_free(main_dir); g_free(bak_dir); g_free(base);
    return ok;
}

static void db_remove_recorded_backup(const char *db_id, const char *main_path) {
    char *old = db_read_backup_pointer(db_id);
    if (old) {
        if (db_private_backup_path_valid(main_path, old)) (void)unlink(old);
        free(old);
    }
    char *ptr = db_backup_pointer_path(db_id);
    if (ptr) { (void)unlink(ptr); g_free(ptr); }
}

static int db_backup_existing_file(const char *path, const char *db_id,
    char *err_msg, size_t err_msg_sz) {
    int src = -1, dst = -1;
    char *bak = NULL, *tmp = NULL, *old_backup = NULL;
    gchar *dir = NULL;
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
    if (!db_hex_string_valid(db_id, DB_ID_HEX_LEN)) {
        snprintf(err_msg, err_msg_sz, "Cannot create private backup without a database ID");
        goto cleanup;
    }

    unsigned char rnd[16]; char hex[33];
    randombytes_buf(rnd, sizeof(rnd));
    sodium_bin2hex(hex, sizeof(hex), rnd, sizeof(rnd));
    sodium_memzero(rnd, sizeof(rnd));
    dir = g_path_get_dirname(path);
    if (!dir) { snprintf(err_msg, err_msg_sz, "Cannot determine backup directory"); goto cleanup; }
    char name[40]; snprintf(name, sizeof(name), ".%s.dpdb", hex);
    sodium_memzero(hex, sizeof(hex));
    bak = g_build_filename(dir, name, NULL);
    if (!bak) { snprintf(err_msg, err_msg_sz, "Backup path allocation failed"); goto cleanup; }
    size_t tmp_len = strlen(bak) + sizeof(".tmp.XXXXXX");
    tmp = malloc(tmp_len);
    if (!tmp) { snprintf(err_msg, err_msg_sz, "Backup temporary path allocation failed"); goto cleanup; }
    snprintf(tmp, tmp_len, "%s.tmp.XXXXXX", bak);
    dst = g_mkstemp_full(tmp, O_WRONLY | O_CLOEXEC, 0600);
    if (dst < 0 || fchmod(dst, 0600) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot create private database backup: %s", strerror(errno));
        goto cleanup;
    }
    gboolean cloned = FALSE;
#ifdef __linux__
    if (ioctl(dst, FICLONE, src) == 0) cloned = TRUE;
#endif
    unsigned char buf[64 * 1024];
    if (!cloned) {
        for (;;) {
            ssize_t n = read(src, buf, sizeof(buf));
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) { sodium_memzero(buf, sizeof(buf)); snprintf(err_msg, err_msg_sz, "Cannot read existing database for backup: %s", strerror(errno)); goto cleanup; }
            if (n == 0) break;
            if (write_all_fd(dst, buf, (size_t)n) != 0) { sodium_memzero(buf, sizeof(buf)); snprintf(err_msg, err_msg_sz, "Cannot write database backup: %s", strerror(errno)); goto cleanup; }
        }
    }
    sodium_memzero(buf, sizeof(buf));
    if (fsync(dst) != 0) { snprintf(err_msg, err_msg_sz, "Cannot sync database backup: %s", strerror(errno)); goto cleanup; }
    if (close(dst) != 0) { dst = -1; snprintf(err_msg, err_msg_sz, "Cannot close database backup: %s", strerror(errno)); goto cleanup; }
    dst = -1;
    if (rename(tmp, bak) != 0) { snprintf(err_msg, err_msg_sz, "Cannot atomically install database backup: %s", strerror(errno)); goto cleanup; }

    old_backup = db_read_backup_pointer(db_id);
    if (!db_write_backup_pointer(db_id, bak)) {
        snprintf(err_msg, err_msg_sz, "Backup created but private backup pointer could not be updated");
        (void)unlink(bak);
        goto cleanup;
    }
    if (old_backup && strcmp(old_backup, bak) != 0 && db_private_backup_path_valid(path, old_backup))
        (void)unlink(old_backup);

    size_t legacy_len = strlen(path) + sizeof(".bak");
    char *legacy = malloc(legacy_len);
    if (legacy) { snprintf(legacy, legacy_len, "%s.bak", path); (void)unlink(legacy); free(legacy); }
    rc = 0;
cleanup:
    if (src >= 0) close(src);
    if (dst >= 0) close(dst);
    if (rc != 0 && tmp) unlink(tmp);
    free(old_backup); free(tmp); g_free(bak); g_free(dir);
    return rc;
}

#define STEGO_HEADER_BYTES 64U
#define STEGO_SEED_BYTES 32U
#define STEGO_HASH_BYTES 32U
#define STEGO_CHECK_BYTES 8U
#define STEGO_VERSION 3U
#define STEGO_LEGACY_VERSION 2U
#define STEGO_MAX_PIXELS 25000000ULL


static volatile gint g_stego_replace_existing_payload = 0;


static unsigned char g_stego_secret_key[32];
static gboolean g_stego_secret_key_set = FALSE;


static const void *g_stego_secret_owner = NULL;


static GMutex g_stego_secret_mutex;


static void stego_secret_init_mutex(void) {
    g_mutex_init(&g_stego_secret_mutex);
}


static void stego_secret_clear_owner(const void *owner);

static void stego_secret_set(const void *owner, const unsigned char *noise_key, size_t key_len) {
    unsigned char derived[32];
    sodium_memzero(derived, sizeof(derived));
    if (!owner || !noise_key || key_len != 32) return;


    static const unsigned char domain[] = "DiskPass stego secret v3";
    crypto_generichash_state st;
    if (crypto_generichash_init(&st, noise_key, key_len, sizeof(derived)) != 0) {
        sodium_memzero(&st, sizeof(st));
        return;
    }
    crypto_generichash_update(&st, domain, sizeof(domain) - 1);
    crypto_generichash_final(&st, derived, sizeof(derived));
    sodium_memzero(&st, sizeof(st));

    g_mutex_lock(&g_stego_secret_mutex);
    if (!g_stego_secret_key_set || g_stego_secret_owner == owner) {
        memcpy(g_stego_secret_key, derived, sizeof(g_stego_secret_key));
        g_stego_secret_key_set = TRUE;
        g_stego_secret_owner = owner;
    } else if (sodium_memcmp(g_stego_secret_key, derived, sizeof(derived)) == 0) {


    } else {


    }
    g_mutex_unlock(&g_stego_secret_mutex);
    sodium_memzero(derived, sizeof(derived));
}


static void stego_secret_clear_owner(const void *owner) {
    if (!owner) return;
    g_mutex_lock(&g_stego_secret_mutex);
    if (g_stego_secret_key_set && g_stego_secret_owner == owner) {
        sodium_memzero(g_stego_secret_key, sizeof(g_stego_secret_key));
        g_stego_secret_key_set = FALSE;
        g_stego_secret_owner = NULL;
    }
    g_mutex_unlock(&g_stego_secret_mutex);
}


static gboolean stego_secret_snapshot(unsigned char out[32]) {
    g_mutex_lock(&g_stego_secret_mutex);
    gboolean ok = g_stego_secret_key_set;
    if (ok) {
        memcpy(out, g_stego_secret_key, 32);
    } else {
        sodium_memzero(out, 32);
    }
    g_mutex_unlock(&g_stego_secret_mutex);
    return ok;
}


static gboolean carrier_opaque_layout_at_fd(int fd, uint64_t start, uint64_t len) {
    if (fd < 0 || start > (uint64_t)LLONG_MAX || len < DB_OPAQUE_HEADER_BYTES +
        DB_OPAQUE_COMPACT_ENVELOPE_SLOT + crypto_aead_xchacha20poly1305_ietf_ABYTES + 1024U)
        return FALSE;
    unsigned char hdr[4];
    ssize_t n = pread(fd, hdr, sizeof(hdr), (off_t)start);
    if (n != (ssize_t)sizeof(hdr)) return FALSE;
    gboolean compact = FALSE;
    size_t slot_size = 0;
    uint16_t env_off = 0, env_len = 0;
    if (!db_opaque_header_layout(hdr, &compact, &slot_size, &env_off, &env_len)) return FALSE;
    uint64_t fixed = (uint64_t)DB_OPAQUE_HEADER_BYTES + (uint64_t)slot_size;
    if (len <= fixed + crypto_aead_xchacha20poly1305_ietf_ABYTES) return FALSE;
    uint64_t padded64 = len - fixed - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (padded64 > SIZE_MAX || !db_opaque_payload_size_valid((size_t)padded64, compact)) return FALSE;

    unsigned char packet = 0;
    uint64_t packet_pos = start + DB_OPAQUE_HEADER_BYTES + env_off;
    if (packet_pos > (uint64_t)LLONG_MAX ||
        pread(fd, &packet, 1, (off_t)packet_pos) != 1 || !(packet & 0x80U))
        return FALSE;
    return TRUE;
}

static gboolean carrier_legacy_layout_at_fd(int fd, uint64_t start, uint64_t len) {
    if (fd < 0 || len < 64U || len > (uint64_t)DB_MAX_FILE_BYTES ||
        start > (uint64_t)LLONG_MAX || len > (uint64_t)LLONG_MAX - start)
        return FALSE;

    unsigned char head[384];
    size_t head_len = len < sizeof(head) - 1U ? (size_t)len : sizeof(head) - 1U;
    if (pread(fd, head, head_len, (off_t)start) != (ssize_t)head_len) return FALSE;
    head[head_len] = '\0';

    unsigned char *nl = memchr(head, '\n', head_len);
    if (!nl) return FALSE;
    size_t first_len = (size_t)(nl - head);
    if (first_len && head[first_len - 1U] == '\r') first_len--;

    gboolean header_ok = FALSE;
    const size_t magic_len = sizeof(DB_CONTAINER_MAGIC) - 1U;
    if (first_len == magic_len && memcmp(head, DB_CONTAINER_MAGIC, magic_len) == 0) {
        header_ok = TRUE;
    } else if (first_len == 32U || first_len == 40U || first_len == 64U) {
        header_ok = TRUE;
        for (size_t i = 0; i < first_len; i++) {
            if (!g_ascii_isxdigit((guchar)head[i])) { header_ok = FALSE; break; }
        }
    }
    if (!header_ok) return FALSE;

    size_t pos = (size_t)(nl - head) + 1U;
    static const char armor_begin[] = "-----BEGIN PGP MESSAGE-----";
    if (head_len - pos < sizeof(armor_begin) - 1U ||
        memcmp(head + pos, armor_begin, sizeof(armor_begin) - 1U) != 0)
        return FALSE;

    unsigned char tail[160];
    size_t tail_len = len < sizeof(tail) - 1U ? (size_t)len : sizeof(tail) - 1U;
    uint64_t tail_pos = start + len - tail_len;
    if (tail_pos > (uint64_t)LLONG_MAX ||
        pread(fd, tail, tail_len, (off_t)tail_pos) != (ssize_t)tail_len)
        return FALSE;
    tail[tail_len] = '\0';
    return strstr((const char *)tail, "-----END PGP MESSAGE-----") != NULL;
}

static gboolean carrier_dpdb_layout_at_fd(int fd, uint64_t start, uint64_t len) {
    return carrier_opaque_layout_at_fd(fd, start, len) ||
           carrier_legacy_layout_at_fd(fd, start, len);
}

static int carrier_open_regular(const char *path, uint64_t max_size, int *out_fd,
    uint64_t *out_size, char *err_msg, size_t err_msg_sz)
{
    if (!path || !out_fd || !out_size) return -1;
    *out_fd = -1; *out_size = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        snprintf(err_msg, err_msg_sz, "Cannot open file safely: %s", strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > max_size) {
        snprintf(err_msg, err_msg_sz, "File is not a supported regular file or exceeds the size limit");
        close(fd);
        return -1;
    }
    *out_fd = fd; *out_size = (uint64_t)st.st_size;
    return 0;
}

static gboolean carrier_paths_distinct(const char *a, const char *b) {
    if (!a || !b) return FALSE;
    gchar *ca = g_canonicalize_filename(a, NULL);
    gchar *cb = g_canonicalize_filename(b, NULL);
    gboolean distinct = ca && cb && strcmp(ca, cb) != 0;
    g_free(ca); g_free(cb);
    return distinct;
}

static int carrier_create_temp(const char *output_path, char **out_tmp, int *out_fd,
    char *err_msg, size_t err_msg_sz)
{
    if (!output_path || !out_tmp || !out_fd) return -1;
    *out_tmp = NULL; *out_fd = -1;
    if (!db_parent_directory_is_safe(output_path, err_msg, err_msg_sz)) return -1;
    size_t n = strlen(output_path) + sizeof(".tmp.XXXXXX");
    char *tmp = malloc(n);
    if (!tmp) { snprintf(err_msg, err_msg_sz, "Out of memory for temporary path"); return -1; }
    snprintf(tmp, n, "%s.tmp.XXXXXX", output_path);
    int fd = g_mkstemp_full(tmp, O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0 || fchmod(fd, 0600) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot create safe output file: %s", strerror(errno));
        if (fd >= 0) close(fd);
        unlink(tmp); free(tmp);
        return -1;
    }
    *out_tmp = tmp; *out_fd = fd;
    return 0;
}

static void carrier_fsync_parent(const char *path) {
    gchar *dir = g_path_get_dirname(path);
    if (!dir) return;
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) { (void)fsync(dfd); close(dfd); }
    g_free(dir);
}

static uint64_t stego_gcd_u64(uint64_t a, uint64_t b) {
    while (b) { uint64_t t = a % b; a = b; b = t; }
    return a;
}

typedef struct {
    uint64_t slots;
    uint64_t pos;
    uint64_t step;
} stego_iter_t;

static gboolean stego_iter_init(stego_iter_t *it, uint64_t slots,
    const unsigned char seed[STEGO_SEED_BYTES])
{
    if (!it || !seed || slots == 0) return FALSE;
    uint64_t start = db_load_u64le(seed) % slots;
    uint64_t step = db_load_u64le(seed + 8) % slots;
    if (step == 0) step = 1;
    if ((step & 1U) == 0) step++;
    if (step >= slots) step %= slots;
    if (step == 0) step = 1;
    while (stego_gcd_u64(step, slots) != 1) {
        step += 2;
        if (step >= slots) step = (step % slots) | 1U;
        if (step == 0) step = 1;
    }
    it->slots = slots;
    it->pos = start;
    it->step = step;
    return TRUE;
}

static uint64_t stego_iter_next(stego_iter_t *it) {
    uint64_t cur = it->pos;
    if (it->pos >= it->slots - it->step)
        it->pos -= (it->slots - it->step);
    else
        it->pos += it->step;
    return cur;
}

static gboolean stego_path_is_decodable_image(const char *path) {
    if (!path || !*path) return FALSE;
    int fd = -1; uint64_t file_size = 0; char err[96] = "";
    if (carrier_open_regular(path, DB_CARRIER_MAX_BYTES, &fd, &file_size, err, sizeof(err)) != 0)
        return FALSE;
    (void)file_size;
    char fd_path[64];
    int pn = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    if (pn <= 0 || (size_t)pn >= sizeof(fd_path)) { close(fd); return FALSE; }
    int w = 0, h = 0;
    GdkPixbufFormat *fmt = gdk_pixbuf_get_file_info(fd_path, &w, &h);
    close(fd);
    if (!fmt || w <= 0 || h <= 0) return FALSE;
    uint64_t uw = (uint64_t)(unsigned)w, uh = (uint64_t)(unsigned)h;
    return uw <= UINT64_MAX / uh && uw * uh <= STEGO_MAX_PIXELS;
}

static GdkPixbuf *stego_load_image_safe_limit(const char *path, uint64_t max_pixels,
    char *err_msg, size_t err_msg_sz)
{
    if (!path || !*path || max_pixels == 0) {
        snprintf(err_msg, err_msg_sz, "Image path is empty");
        return NULL;
    }

    int fd = -1;
    uint64_t file_size = 0;
    if (carrier_open_regular(path, DB_CARRIER_MAX_BYTES, &fd, &file_size,
            err_msg, err_msg_sz) != 0)
        return NULL;
    (void)file_size;

    char fd_path[64];
    int pn = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    if (pn <= 0 || (size_t)pn >= sizeof(fd_path)) {
        close(fd);
        snprintf(err_msg, err_msg_sz, "Cannot construct safe image descriptor path");
        return NULL;
    }

    int w = 0, h = 0;
    GdkPixbufFormat *fmt = gdk_pixbuf_get_file_info(fd_path, &w, &h);
    if (!fmt || w <= 0 || h <= 0 ||
        (uint64_t)(unsigned)w > UINT64_MAX / (uint64_t)(unsigned)h ||
        (uint64_t)(unsigned)w * (uint64_t)(unsigned)h > max_pixels) {
        close(fd);
        snprintf(err_msg, err_msg_sz, "Unsupported image or decoded dimensions exceed the safety limit");
        return NULL;
    }

    GError *gerr = NULL;
    GdkPixbuf *pb = gdk_pixbuf_new_from_file(fd_path, &gerr);
    close(fd);
    if (!pb) {
        snprintf(err_msg, err_msg_sz, "Cannot decode image: %s",
            gerr && gerr->message ? gerr->message : "unsupported image format");
        g_clear_error(&gerr);
        return NULL;
    }
    g_clear_error(&gerr);
    return pb;
}

static GdkPixbuf *stego_load_image_safe(const char *path,
    char *err_msg, size_t err_msg_sz)
{
    return stego_load_image_safe_limit(path, STEGO_MAX_PIXELS, err_msg, err_msg_sz);
}

static gboolean stego_pixbuf_layout(GdkPixbuf *pb, uint64_t *out_slots,
    char *err_msg, size_t err_msg_sz)
{
    if (!pb || !out_slots) return FALSE;
    int w = gdk_pixbuf_get_width(pb);
    int h = gdk_pixbuf_get_height(pb);
    int channels = gdk_pixbuf_get_n_channels(pb);
    if (w <= 0 || h <= 0 || channels < 3 || gdk_pixbuf_get_bits_per_sample(pb) != 8) {
        snprintf(err_msg, err_msg_sz, "Image must decode to 8-bit RGB/RGBA pixels");
        return FALSE;
    }
    uint64_t pixels = (uint64_t)(unsigned)w * (uint64_t)(unsigned)h;
    if (pixels == 0 || pixels > STEGO_MAX_PIXELS || pixels > UINT64_MAX / 3U) {
        snprintf(err_msg, err_msg_sz, "Image dimensions exceed the steganography safety limit");
        return FALSE;
    }
    *out_slots = pixels * 3U;
    return TRUE;
}

static unsigned char *stego_channel_ptr(GdkPixbuf *pb, uint64_t slot) {
    int w = gdk_pixbuf_get_width(pb);
    int channels = gdk_pixbuf_get_n_channels(pb);
    int rowstride = gdk_pixbuf_get_rowstride(pb);
    guchar *pixels = gdk_pixbuf_get_pixels(pb);
    uint64_t pixel = slot / 3U;
    unsigned channel = (unsigned)(slot % 3U);
    uint64_t y = pixel / (uint64_t)(unsigned)w;
    uint64_t x = pixel % (uint64_t)(unsigned)w;
    return pixels + y * (uint64_t)rowstride + x * (uint64_t)channels + channel;
}

static gboolean stego_seed_from_pixbuf_mode(GdkPixbuf *pb,
    unsigned char out[STEGO_SEED_BYTES], gboolean keyed,
    char *err_msg, size_t err_msg_sz)
{
    uint64_t slots = 0;
    if (!stego_pixbuf_layout(pb, &slots, err_msg, err_msg_sz)) return FALSE;
    (void)slots;

    unsigned char secret_snapshot[32];
    const unsigned char *key = NULL;
    size_t key_len = 0;
    sodium_memzero(secret_snapshot, sizeof(secret_snapshot));
    if (keyed) {
        if (!stego_secret_snapshot(secret_snapshot)) return FALSE;
        key = secret_snapshot;
        key_len = sizeof(secret_snapshot);
    }

    crypto_generichash_state st;
    if (crypto_generichash_init(&st, key, key_len, STEGO_SEED_BYTES) != 0) {
        sodium_memzero(secret_snapshot, sizeof(secret_snapshot));
        snprintf(err_msg, err_msg_sz, "Cannot initialize steganography hash");
        return FALSE;
    }

    static const unsigned char public_ctx[] = "DiskPass image steganography bootstrap seed v4";
    static const unsigned char legacy_ctx[] = "DiskPass image steganography seed v3";
    const unsigned char *ctx = keyed ? legacy_ctx : public_ctx;
    size_t ctx_len = keyed ? sizeof(legacy_ctx) - 1 : sizeof(public_ctx) - 1;
    crypto_generichash_update(&st, ctx, ctx_len);
    unsigned char dims[8];
    uint32_t w = (uint32_t)gdk_pixbuf_get_width(pb);
    uint32_t h = (uint32_t)gdk_pixbuf_get_height(pb);
    dims[0]=(unsigned char)w; dims[1]=(unsigned char)(w>>8); dims[2]=(unsigned char)(w>>16); dims[3]=(unsigned char)(w>>24);
    dims[4]=(unsigned char)h; dims[5]=(unsigned char)(h>>8); dims[6]=(unsigned char)(h>>16); dims[7]=(unsigned char)(h>>24);
    crypto_generichash_update(&st, dims, sizeof(dims));

    int width = gdk_pixbuf_get_width(pb);
    int height = gdk_pixbuf_get_height(pb);
    int channels = gdk_pixbuf_get_n_channels(pb);
    int rowstride = gdk_pixbuf_get_rowstride(pb);
    const guchar *pixels = gdk_pixbuf_get_pixels(pb);
    unsigned char buf[4096];
    size_t used = 0;
    for (int y = 0; y < height; y++) {
        const guchar *row = pixels + (size_t)y * (size_t)rowstride;
        for (int x = 0; x < width; x++) {
            const guchar *px = row + (size_t)x * (size_t)channels;
            for (int c = 0; c < 3; c++) {
                buf[used++] = (unsigned char)(px[c] & 0xFCU);
                if (used == sizeof(buf)) {
                    crypto_generichash_update(&st, buf, used);
                    used = 0;
                }
            }
        }
    }
    if (used) crypto_generichash_update(&st, buf, used);
    sodium_memzero(buf, sizeof(buf));
    crypto_generichash_final(&st, out, STEGO_SEED_BYTES);
    sodium_memzero(secret_snapshot, sizeof(secret_snapshot));
    return TRUE;
}

static gboolean stego_seed_from_pixbuf(GdkPixbuf *pb,
    unsigned char out[STEGO_SEED_BYTES], char *err_msg, size_t err_msg_sz)
{
    return stego_seed_from_pixbuf_mode(pb, out, FALSE, err_msg, err_msg_sz);
}

static gboolean stego_seed_from_pixbuf_legacy(GdkPixbuf *pb,
    unsigned char out[STEGO_SEED_BYTES], char *err_msg, size_t err_msg_sz)
{
    return stego_seed_from_pixbuf_mode(pb, out, TRUE, err_msg, err_msg_sz);
}

static void stego_header_mask(const unsigned char seed[STEGO_SEED_BYTES],
    unsigned char mask[STEGO_HEADER_BYTES])
{
    static const unsigned char ctx[] = "DiskPass image steganography header mask v1";


    if (crypto_generichash(mask, STEGO_HEADER_BYTES, ctx, sizeof(ctx) - 1,
            seed, STEGO_SEED_BYTES) != 0) {
        sodium_memzero(mask, STEGO_HEADER_BYTES);
    }
}

static void stego_header_check(const unsigned char seed[STEGO_SEED_BYTES],
    const unsigned char plain[STEGO_HEADER_BYTES], unsigned char out[STEGO_CHECK_BYTES])
{


    unsigned char digest[crypto_generichash_BYTES_MIN];


    if (crypto_generichash(digest, sizeof(digest), plain,
            STEGO_HEADER_BYTES - STEGO_CHECK_BYTES, seed, STEGO_SEED_BYTES) != 0) {
        sodium_memzero(digest, sizeof(digest));
    }
    memcpy(out, digest, STEGO_CHECK_BYTES);
    sodium_memzero(digest, sizeof(digest));
}

#define STEGO_IMAGE_VERSION 4U
#define STEGO_IMAGE_LEGACY_VERSION 3U

static unsigned char stego_image_match_bit(unsigned char value, unsigned wanted) {
    wanted &= 1U;
    if ((value & 1U) == wanted) return value;
    unsigned low = value & 3U;
    if (low == 0) return (unsigned char)(value + 1);
    if (low == 3) return (unsigned char)(value - 1);
    return (unsigned char)((int)value + (randombytes_uniform(2) ? 1 : -1));
}

static void stego_write_bytes(GdkPixbuf *pb, stego_iter_t *it,
    const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char v = data[i];
        for (unsigned b = 0; b < 8; b++) {
            unsigned char *p = stego_channel_ptr(pb, stego_iter_next(it));
            *p = stego_image_match_bit(*p, (v >> b) & 1U);
        }
    }
}

static void stego_read_bytes(GdkPixbuf *pb, stego_iter_t *it,
    unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char v = 0;
        for (unsigned b = 0; b < 8; b++) {
            const unsigned char *p = stego_channel_ptr(pb, stego_iter_next(it));
            v |= (unsigned char)((*p & 1U) << b);
        }
        data[i] = v;
    }
}

static gboolean stego_decode_header(GdkPixbuf *pb, uint64_t slots,
    const unsigned char seed[STEGO_SEED_BYTES], unsigned char expected_version,
    uint64_t *payload_len, unsigned char payload_hash[STEGO_HASH_BYTES],
    stego_iter_t *payload_it)
{
    if (slots < (uint64_t)STEGO_HEADER_BYTES * 8U) return FALSE;
    stego_iter_t it;
    if (!stego_iter_init(&it, slots, seed)) return FALSE;
    unsigned char enc[STEGO_HEADER_BYTES], plain[STEGO_HEADER_BYTES], mask[STEGO_HEADER_BYTES];
    unsigned char check[STEGO_CHECK_BYTES];
    stego_read_bytes(pb, &it, enc, sizeof(enc));
    stego_header_mask(seed, mask);
    for (size_t i = 0; i < sizeof(plain); i++) plain[i] = (unsigned char)(enc[i] ^ mask[i]);
    stego_header_check(seed, plain, check);
    gboolean ok = sodium_memcmp(check, plain + STEGO_HEADER_BYTES - STEGO_CHECK_BYTES,
        STEGO_CHECK_BYTES) == 0 && plain[40] == expected_version;
    uint64_t len = db_load_u64le(plain);
    uint64_t capacity = slots / 8U;
    if (!ok || len == 0 || len > DB_MAX_FILE_BYTES ||
        len > capacity || STEGO_HEADER_BYTES > capacity - len) ok = FALSE;
    if (ok) {
        if (payload_len) *payload_len = len;
        if (payload_hash) memcpy(payload_hash, plain + 8, STEGO_HASH_BYTES);
        if (payload_it) *payload_it = it;
    }
    sodium_memzero(enc, sizeof(enc));
    sodium_memzero(plain, sizeof(plain));
    sodium_memzero(mask, sizeof(mask));
    sodium_memzero(check, sizeof(check));
    return ok;
}

static int stego_hash_fd(int fd, uint64_t len, unsigned char out[STEGO_HASH_BYTES],
    char *err_msg, size_t err_msg_sz)
{
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, STEGO_HASH_BYTES);
    unsigned char buf[128 * 1024];
    uint64_t off = 0;
    while (off < len) {
        size_t want = sizeof(buf);
        if (len - off < want) want = (size_t)(len - off);
        ssize_t n = pread(fd, buf, want, (off_t)off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            snprintf(err_msg, err_msg_sz, "Cannot read database while hashing: %s",
                n < 0 ? strerror(errno) : "unexpected end of file");
            sodium_memzero(buf, sizeof(buf));
            return -1;
        }
        crypto_generichash_update(&st, buf, (size_t)n);
        off += (uint64_t)n;
    }
    sodium_memzero(buf, sizeof(buf));
    crypto_generichash_final(&st, out, STEGO_HASH_BYTES);
    return 0;
}


static int stego_keyed_hash_fd(int fd, uint64_t len, unsigned char out[32],
    char *err_msg, size_t err_msg_sz)
{
    static const unsigned char domain[] = "DiskPass carrier identity v2";
    crypto_generichash_state st;
    if (crypto_generichash_init(&st, NULL, 0, 32) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot initialize carrier integrity hash");
        return -1;
    }
    crypto_generichash_update(&st, domain, sizeof(domain) - 1);
    unsigned char buf[128 * 1024];
    uint64_t off = 0;
    while (off < len) {
        size_t want = sizeof(buf);
        if (len - off < want) want = (size_t)(len - off);
        ssize_t n = pread(fd, buf, want, (off_t)off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            snprintf(err_msg, err_msg_sz, "Cannot read carrier while hashing: %s",
                n < 0 ? strerror(errno) : "unexpected end of file");
            sodium_memzero(buf, sizeof(buf));
            return -1;
        }
        crypto_generichash_update(&st, buf, (size_t)n);
        off += (uint64_t)n;
    }
    sodium_memzero(buf, sizeof(buf));
    crypto_generichash_final(&st, out, 32);
    return 0;
}

static gboolean stego_output_is_ci(const char *path, const char *ext) {
    if (!path || !ext) return FALSE;
    size_t lp = strlen(path), le = strlen(ext);
    return lp >= le && g_ascii_strcasecmp(path + lp - le, ext) == 0;
}

static int stego_write_pixbuf_ppm(int fd, GdkPixbuf *pb) {
    int w = gdk_pixbuf_get_width(pb), h = gdk_pixbuf_get_height(pb);
    int channels = gdk_pixbuf_get_n_channels(pb), stride = gdk_pixbuf_get_rowstride(pb);
    const guchar *pixels = gdk_pixbuf_get_pixels(pb);
    if (w <= 0 || h <= 0 || channels < 3 || !pixels) return -1;
    char hdr[96];
    int hn = snprintf(hdr, sizeof(hdr), "P6\n%d %d\n255\n", w, h);
    if (hn <= 0 || (size_t)hn >= sizeof(hdr) || write_all_fd(fd, (unsigned char *)hdr, (size_t)hn) != 0)
        return -1;
    unsigned char row[64 * 1024];
    for (int y = 0; y < h; y++) {
        const guchar *src = pixels + (size_t)y * (size_t)stride;
        size_t x = 0;
        while (x < (size_t)w) {
            size_t px = (sizeof(row) / 3U);
            if ((size_t)w - x < px) px = (size_t)w - x;
            for (size_t i = 0; i < px; i++) {
                const guchar *sp = src + (x + i) * (size_t)channels;
                row[i*3U+0] = sp[0]; row[i*3U+1] = sp[1]; row[i*3U+2] = sp[2];
            }
            if (write_all_fd(fd, row, px * 3U) != 0) { sodium_memzero(row, sizeof(row)); return -1; }
            x += px;
        }
    }
    sodium_memzero(row, sizeof(row));
    return 0;
}

static int stego_write_pixbuf_tga(int fd, GdkPixbuf *pb) {
    int w = gdk_pixbuf_get_width(pb), h = gdk_pixbuf_get_height(pb);
    int channels = gdk_pixbuf_get_n_channels(pb), stride = gdk_pixbuf_get_rowstride(pb);
    const guchar *pixels = gdk_pixbuf_get_pixels(pb);
    gboolean alpha = gdk_pixbuf_get_has_alpha(pb) && channels >= 4;
    if (w <= 0 || h <= 0 || w > 65535 || h > 65535 || channels < 3 || !pixels) return -1;
    unsigned char hdr[18] = {0};
    hdr[2] = 2;
    hdr[12] = (unsigned char)w; hdr[13] = (unsigned char)(w >> 8);
    hdr[14] = (unsigned char)h; hdr[15] = (unsigned char)(h >> 8);
    hdr[16] = alpha ? 32 : 24;
    hdr[17] = (unsigned char)(0x20U | (alpha ? 8U : 0U));
    if (write_all_fd(fd, hdr, sizeof(hdr)) != 0) return -1;
    unsigned char row[64 * 1024];
    size_t outch = alpha ? 4U : 3U;
    for (int y = 0; y < h; y++) {
        const guchar *src = pixels + (size_t)y * (size_t)stride;
        size_t x = 0;
        while (x < (size_t)w) {
            size_t px = sizeof(row) / outch;
            if ((size_t)w - x < px) px = (size_t)w - x;
            for (size_t i = 0; i < px; i++) {
                const guchar *sp = src + (x + i) * (size_t)channels;
                unsigned char *dp = row + i * outch;
                dp[0] = sp[2]; dp[1] = sp[1]; dp[2] = sp[0];
                if (alpha) dp[3] = sp[3];
            }
            if (write_all_fd(fd, row, px * outch) != 0) { sodium_memzero(row, sizeof(row)); return -1; }
            x += px;
        }
    }
    sodium_memzero(row, sizeof(row));
    return 0;
}

static int stego_write_pixbuf_webp(int fd, GdkPixbuf *pb) {
    int w = gdk_pixbuf_get_width(pb), h = gdk_pixbuf_get_height(pb);
    int channels = gdk_pixbuf_get_n_channels(pb), stride = gdk_pixbuf_get_rowstride(pb);
    const uint8_t *pixels = gdk_pixbuf_get_pixels(pb);
    if (w <= 0 || h <= 0 || channels < 3 || !pixels) return -1;
    uint8_t *encoded = NULL;
    size_t n = (gdk_pixbuf_get_has_alpha(pb) && channels >= 4)
        ? WebPEncodeLosslessRGBA(pixels, w, h, stride, &encoded)
        : WebPEncodeLosslessRGB(pixels, w, h, stride, &encoded);
    if (n == 0 || !encoded) return -1;
    int rc = write_all_fd(fd, encoded, n);
    WebPFree(encoded);
    return rc;
}

static int stego_save_image_atomic(GdkPixbuf *pb, const char *output_path,
    char *err_msg, size_t err_msg_sz)
{
    enum { FMT_PNG, FMT_BMP, FMT_TIFF, FMT_WEBP, FMT_PPM, FMT_TGA } fmt = FMT_PNG;
    const char *label = "PNG";
    if (stego_output_is_ci(output_path, ".bmp")) { fmt = FMT_BMP; label = "BMP"; }
    else if (stego_output_is_ci(output_path, ".tif") || stego_output_is_ci(output_path, ".tiff")) { fmt = FMT_TIFF; label = "TIFF"; }
    else if (stego_output_is_ci(output_path, ".webp")) { fmt = FMT_WEBP; label = "lossless WebP"; }
    else if (stego_output_is_ci(output_path, ".ppm") || stego_output_is_ci(output_path, ".pnm")) { fmt = FMT_PPM; label = "PPM"; }
    else if (stego_output_is_ci(output_path, ".tga")) { fmt = FMT_TGA; label = "TGA"; }
    else if (!stego_output_is_ci(output_path, ".png")) {
        snprintf(err_msg, err_msg_sz, "Unsupported lossless image output format");
        return -1;
    }

    char *tmp = NULL;
    int fd = -1;
    if (carrier_create_temp(output_path, &tmp, &fd, err_msg, err_msg_sz) != 0) return -1;
    int custom_rc = 0;
    if (fmt == FMT_WEBP) custom_rc = stego_write_pixbuf_webp(fd, pb);
    else if (fmt == FMT_PPM) custom_rc = stego_write_pixbuf_ppm(fd, pb);
    else if (fmt == FMT_TGA) custom_rc = stego_write_pixbuf_tga(fd, pb);
    if (fmt == FMT_WEBP || fmt == FMT_PPM || fmt == FMT_TGA) {
        int saved_errno = custom_rc == 0 ? 0 : errno;
        gboolean ok = custom_rc == 0;
        if (ok && fsync(fd) != 0) { ok = FALSE; saved_errno = errno; }
        if (close(fd) != 0) { if (ok || saved_errno == 0) saved_errno = errno; ok = FALSE; }
        fd = -1;
        if (!ok) {
            if (saved_errno == 0) saved_errno = EIO;
            snprintf(err_msg, err_msg_sz, "Cannot encode/sync stego %s: %s", label, strerror(saved_errno));
            unlink(tmp); free(tmp); return -1;
        }
    } else {
        if (close(fd) != 0) {
            snprintf(err_msg, err_msg_sz, "Cannot close temporary %s: %s", label, strerror(errno));
            unlink(tmp); free(tmp); return -1;
        }
        fd = -1;
        GError *gerr = NULL;
        gboolean ok = FALSE;
        if (fmt == FMT_BMP) ok = gdk_pixbuf_save(pb, tmp, "bmp", &gerr, NULL);
        else if (fmt == FMT_TIFF) ok = gdk_pixbuf_save(pb, tmp, "tiff", &gerr, NULL);
        else ok = gdk_pixbuf_save(pb, tmp, "png", &gerr, "compression", "9", NULL);
        if (!ok) {
            snprintf(err_msg, err_msg_sz, "Cannot encode stego %s: %s", label,
                gerr && gerr->message ? gerr->message : "image encoder unavailable");
            g_clear_error(&gerr); unlink(tmp); free(tmp); return -1;
        }
        if (chmod(tmp, 0600) != 0) {
            snprintf(err_msg, err_msg_sz, "Cannot set private permissions on stego %s: %s", label, strerror(errno));
            unlink(tmp); free(tmp); return -1;
        }
        fd = open(tmp, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            snprintf(err_msg, err_msg_sz, "Cannot open stego %s for sync: %s", label, strerror(errno));
            unlink(tmp); free(tmp); return -1;
        }
        if (fsync(fd) != 0) {
            int saved_errno = errno;
            close(fd); fd = -1;
            snprintf(err_msg, err_msg_sz, "Cannot sync stego %s: %s", label, strerror(saved_errno));
            unlink(tmp); free(tmp); return -1;
        }
        if (close(fd) != 0) {
            int saved_errno = errno;
            fd = -1;
            snprintf(err_msg, err_msg_sz, "Cannot close stego %s: %s", label, strerror(saved_errno));
            unlink(tmp); free(tmp); return -1;
        }
        fd = -1;
    }
    if (chmod(tmp, 0600) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot set private permissions on stego %s: %s", label, strerror(errno));
        unlink(tmp); free(tmp); return -1;
    }
    if (rename(tmp, output_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot atomically install stego %s: %s", label, strerror(errno));
        unlink(tmp); free(tmp); return -1;
    }
    carrier_fsync_parent(output_path);
    free(tmp);
    return 0;
}

static gboolean stego_embedding_percent(unsigned *out_percent,
    char *err_msg, size_t err_msg_sz)
{
    if (!out_percent) return FALSE;
    const char *setting = g_getenv("DISKPASS_STEGO_MAX_PERCENT");
    unsigned percent = 100;
    if (setting) {
        size_t n = strlen(setting);
        if (!n || n > 3) goto invalid;
        percent = 0;
        for (size_t i = 0; i < n; i++) {
            if (setting[i] < '0' || setting[i] > '9') goto invalid;
            percent = percent * 10 + (unsigned)(setting[i] - '0');
        }
        if (!percent || percent > 100) goto invalid;
    }
    *out_percent = percent;
    return TRUE;
invalid:
    snprintf(err_msg, err_msg_sz, "DISKPASS_STEGO_MAX_PERCENT must be an integer from 1 to 100");
    return FALSE;
}

static gboolean stego_embedding_budget(uint64_t slots, uint64_t payload_bytes,
    char *err_msg, size_t err_msg_sz)
{
    unsigned percent = 100;
    if (!stego_embedding_percent(&percent, err_msg, err_msg_sz)) return FALSE;
    uint64_t budget_bits = (slots / 100) * percent + ((slots % 100) * percent) / 100;
    uint64_t budget_bytes = budget_bits / 8;
    if (budget_bytes < STEGO_HEADER_BYTES || payload_bytes > budget_bytes - STEGO_HEADER_BYTES) {
        uint64_t usable = budget_bytes > STEGO_HEADER_BYTES ? budget_bytes - STEGO_HEADER_BYTES : 0;
        snprintf(err_msg, err_msg_sz,
            "Stego capacity at %u%% is %.2f MiB, but the database is %.2f MiB. "
            "Use a larger/higher-detail carrier or allow automatic enlargement",
            percent, (double)usable / (1024.0 * 1024.0),
            (double)payload_bytes / (1024.0 * 1024.0));
        return FALSE;
    }
    return TRUE;
}

static int carrier_attach_dpdb_image(const char *carrier_path, const char *db_path,
    const char *output_path, char *err_msg, size_t err_msg_sz)
{
    int dfd = -1;
    uint64_t db_size = 0;
    GdkPixbuf *pb = NULL;
    int rc = -1;
    unsigned char seed[STEGO_SEED_BYTES], payload_hash[STEGO_HASH_BYTES];
    unsigned char header[STEGO_HEADER_BYTES], mask[STEGO_HEADER_BYTES], check[STEGO_CHECK_BYTES];
    uint64_t slots = 0;

    if (!carrier_path || !db_path || !output_path ||
        !carrier_paths_distinct(carrier_path, output_path) ||
        !carrier_paths_distinct(db_path, output_path)) {
        snprintf(err_msg, err_msg_sz, "Output image must be different from the cover image and database");
        return -1;
    }
    if (!stego_output_is_ci(output_path, ".png") && !stego_output_is_ci(output_path, ".bmp") &&
        !stego_output_is_ci(output_path, ".tif") && !stego_output_is_ci(output_path, ".tiff") &&
        !stego_output_is_ci(output_path, ".webp") && !stego_output_is_ci(output_path, ".ppm") &&
        !stego_output_is_ci(output_path, ".pnm") && !stego_output_is_ci(output_path, ".tga")) {
        snprintf(err_msg, err_msg_sz,
            "Image steganography output must be PNG, BMP, TIFF, lossless WebP, PPM/PNM, or TGA");
        return -1;
    }
    if (carrier_open_regular(db_path, DB_MAX_FILE_BYTES, &dfd, &db_size, err_msg, err_msg_sz) != 0)
        goto cleanup;
    if (!db_path_has_dpdb_extension(db_path) || !carrier_dpdb_layout_at_fd(dfd, 0, db_size)) {
        snprintf(err_msg, err_msg_sz,
            "Only valid DiskPass .dpdb databases can be hidden");
        goto cleanup;
    }

    pb = stego_load_image_safe(carrier_path, err_msg, err_msg_sz);
    if (!pb) goto cleanup;
    if (!stego_pixbuf_layout(pb, &slots, err_msg, err_msg_sz) ||
        !stego_seed_from_pixbuf(pb, seed, err_msg, err_msg_sz)) goto cleanup;

    if (!stego_embedding_budget(slots, db_size, err_msg, err_msg_sz)) goto cleanup;
    uint64_t capacity = slots / 8U;
    if (capacity < STEGO_HEADER_BYTES || db_size > capacity - STEGO_HEADER_BYTES) {
        uint64_t usable = capacity > STEGO_HEADER_BYTES ? capacity - STEGO_HEADER_BYTES : 0;
        snprintf(err_msg, err_msg_sz,
            "Image is too small for this database: capacity %.2f MiB, database %.2f MiB. Use a larger image",
            (double)usable / (1024.0 * 1024.0), (double)db_size / (1024.0 * 1024.0));
        goto cleanup;
    }

    if (!g_atomic_int_get(&g_stego_replace_existing_payload)) {
        gboolean has_payload = stego_decode_header(pb, slots, seed, STEGO_IMAGE_VERSION,
            NULL, NULL, NULL);
        if (!has_payload) {
            unsigned char legacy_seed[STEGO_SEED_BYTES];
            if (stego_seed_from_pixbuf_legacy(pb, legacy_seed, err_msg, err_msg_sz))
                has_payload = stego_decode_header(pb, slots, legacy_seed,
                    STEGO_IMAGE_LEGACY_VERSION, NULL, NULL, NULL);
            sodium_memzero(legacy_seed, sizeof(legacy_seed));
        }
        if (has_payload) {
            snprintf(err_msg, err_msg_sz, "The selected image already appears to contain a DiskPass stego payload");
            goto cleanup;
        }
    }
    if (stego_hash_fd(dfd, db_size, payload_hash, err_msg, err_msg_sz) != 0) goto cleanup;

    memset(header, 0, sizeof(header));
    db_store_u64le(header, db_size);
    memcpy(header + 8, payload_hash, STEGO_HASH_BYTES);
    header[40] = STEGO_IMAGE_VERSION;
    randombytes_buf(header + 41, 15);
    stego_header_check(seed, header, check);
    memcpy(header + STEGO_HEADER_BYTES - STEGO_CHECK_BYTES, check, STEGO_CHECK_BYTES);
    stego_header_mask(seed, mask);
    for (size_t i = 0; i < sizeof(header); i++) header[i] ^= mask[i];

    stego_iter_t it;
    stego_iter_init(&it, slots, seed);
    stego_write_bytes(pb, &it, header, sizeof(header));

    unsigned char buf[128 * 1024];
    uint64_t off = 0;
    while (off < db_size) {
        size_t want = sizeof(buf);
        if (db_size - off < want) want = (size_t)(db_size - off);
        ssize_t n = pread(dfd, buf, want, (off_t)off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            snprintf(err_msg, err_msg_sz, "Cannot read database for steganography: %s",
                n < 0 ? strerror(errno) : "unexpected end of file");
            sodium_memzero(buf, sizeof(buf)); goto cleanup;
        }
        stego_write_bytes(pb, &it, buf, (size_t)n);
        off += (uint64_t)n;
    }
    sodium_memzero(buf, sizeof(buf));

    if (stego_save_image_atomic(pb, output_path, err_msg, err_msg_sz) != 0) goto cleanup;
    rc = 0;
cleanup:
    if (dfd >= 0) close(dfd);
    if (pb) g_object_unref(pb);
    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(payload_hash, sizeof(payload_hash));
    sodium_memzero(header, sizeof(header));
    sodium_memzero(mask, sizeof(mask));
    sodium_memzero(check, sizeof(check));
    return rc;
}

static int carrier_extract_dpdb_image(const char *image_path, const char *output_db_path,
    char *err_msg, size_t err_msg_sz)
{
    GdkPixbuf *pb = NULL;
    unsigned char seed[STEGO_SEED_BYTES], expected_hash[STEGO_HASH_BYTES], actual_hash[STEGO_HASH_BYTES];
    uint64_t slots = 0, payload_len = 0;
    stego_iter_t it;
    int ofd = -1;
    char *tmp = NULL;
    int rc = -1;

    if (!image_path || !output_db_path || !db_path_has_dpdb_extension(output_db_path) ||
        !carrier_paths_distinct(image_path, output_db_path)) {
        snprintf(err_msg, err_msg_sz, "Extracted database must use a different .dpdb path");
        return -1;
    }
    pb = stego_load_image_safe(image_path, err_msg, err_msg_sz);
    if (!pb) goto cleanup;
    if (!stego_pixbuf_layout(pb, &slots, err_msg, err_msg_sz) ||
        !stego_seed_from_pixbuf(pb, seed, err_msg, err_msg_sz)) goto cleanup;
    gboolean found = stego_decode_header(pb, slots, seed, STEGO_IMAGE_VERSION,
        &payload_len, expected_hash, &it);
    if (!found) {
        unsigned char legacy_seed[STEGO_SEED_BYTES];
        if (stego_seed_from_pixbuf_legacy(pb, legacy_seed, err_msg, err_msg_sz)) {
            found = stego_decode_header(pb, slots, legacy_seed, STEGO_IMAGE_LEGACY_VERSION,
                &payload_len, expected_hash, &it);
            if (found) memcpy(seed, legacy_seed, sizeof(seed));
        }
        sodium_memzero(legacy_seed, sizeof(legacy_seed));
    }
    if (!found) {
        snprintf(err_msg, err_msg_sz,
            "No valid DiskPass steganographic payload was found in this image");
        goto cleanup;
    }
    if (carrier_create_temp(output_db_path, &tmp, &ofd, err_msg, err_msg_sz) != 0) goto cleanup;

    crypto_generichash_state hst;
    crypto_generichash_init(&hst, NULL, 0, STEGO_HASH_BYTES);
    unsigned char buf[128 * 1024];
    uint64_t remaining = payload_len;
    while (remaining) {
        size_t take = sizeof(buf);
        if (remaining < take) take = (size_t)remaining;
        stego_read_bytes(pb, &it, buf, take);
        crypto_generichash_update(&hst, buf, take);
        if (write_all_fd(ofd, buf, take) != 0) {
            snprintf(err_msg, err_msg_sz, "Cannot write extracted database: %s", strerror(errno));
            sodium_memzero(buf, sizeof(buf)); goto cleanup;
        }
        remaining -= take;
    }
    sodium_memzero(buf, sizeof(buf));
    crypto_generichash_final(&hst, actual_hash, STEGO_HASH_BYTES);
    if (sodium_memcmp(expected_hash, actual_hash, STEGO_HASH_BYTES) != 0) {
        snprintf(err_msg, err_msg_sz, "Steganographic payload integrity check failed; image may have been modified or recompressed");
        goto cleanup;
    }
    if (fsync(ofd) != 0) { snprintf(err_msg, err_msg_sz, "Cannot sync extracted database: %s", strerror(errno)); goto cleanup; }
    if (close(ofd) != 0) { ofd = -1; snprintf(err_msg, err_msg_sz, "Cannot close extracted database: %s", strerror(errno)); goto cleanup; }
    ofd = -1;
    int verify_fd = open(tmp, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (verify_fd < 0 || !carrier_dpdb_layout_at_fd(verify_fd, 0, payload_len)) {
        if (verify_fd >= 0) close(verify_fd);
        snprintf(err_msg, err_msg_sz, "Hidden payload is intact but is not a recognized DiskPass .dpdb container");
        goto cleanup;
    }
    close(verify_fd);
    if (rename(tmp, output_db_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot atomically install extracted database: %s", strerror(errno));
        goto cleanup;
    }
    carrier_fsync_parent(output_db_path);
    rc = 0;
cleanup:
    if (ofd >= 0) close(ofd);
    if (rc != 0 && tmp) unlink(tmp);
    free(tmp);
    if (pb) g_object_unref(pb);
    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(expected_hash, sizeof(expected_hash));
    sodium_memzero(actual_hash, sizeof(actual_hash));
    return rc;
}

typedef struct {
    uint16_t format_tag;
    uint16_t channels;
    uint32_t sample_rate;
    uint16_t block_align;
    uint16_t bits_per_sample;
    uint32_t bytes_per_sample;
    uint64_t data_offset;
    uint64_t data_size;
} stego_wav_info_t;

static uint32_t stego_load_u32le(const unsigned char p[4]) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static gboolean stego_path_is_wav(const char *path) {
    if (!path) return FALSE;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return FALSE;
    unsigned char h[12];
    ssize_t n = pread(fd, h, sizeof(h), 0);
    close(fd);
    return n == (ssize_t)sizeof(h) && memcmp(h, "RIFF", 4) == 0 &&
        memcmp(h + 8, "WAVE", 4) == 0;
}

static int stego_wav_parse_fd(int fd, uint64_t file_size, stego_wav_info_t *info,
    char *err_msg, size_t err_msg_sz)
{
    if (fd < 0 || !info || file_size < 44) return -1;
    unsigned char riff[12];
    if (pread(fd, riff, sizeof(riff), 0) != (ssize_t)sizeof(riff) ||
        memcmp(riff, "RIFF", 4) != 0 || memcmp(riff + 8, "WAVE", 4) != 0) {
        snprintf(err_msg, err_msg_sz, "Carrier is not a RIFF/WAVE file");
        return -1;
    }

    gboolean have_fmt = FALSE, have_data = FALSE;
    uint16_t fmt_tag = 0, channels = 0, block_align = 0, bits = 0;
    uint32_t sample_rate = 0;
    uint64_t data_offset = 0, data_size = 0;
    uint64_t pos = 12;
    while (pos + 8 <= file_size) {
        unsigned char ch[8];
        if (pos > (uint64_t)LLONG_MAX || pread(fd, ch, sizeof(ch), (off_t)pos) != (ssize_t)sizeof(ch)) {
            snprintf(err_msg, err_msg_sz, "Cannot read WAV chunk header");
            return -1;
        }
        uint32_t chunk_size = stego_load_u32le(ch + 4);
        uint64_t body = pos + 8;
        if (body > file_size || (uint64_t)chunk_size > file_size - body) {
            snprintf(err_msg, err_msg_sz, "Malformed WAV chunk length");
            return -1;
        }
        if (memcmp(ch, "fmt ", 4) == 0 && !have_fmt) {
            if (chunk_size < 16) {
                snprintf(err_msg, err_msg_sz, "WAV fmt chunk is too short");
                return -1;
            }
            unsigned char fmt[40] = {0};
            size_t take = chunk_size < sizeof(fmt) ? chunk_size : sizeof(fmt);
            if (body > (uint64_t)LLONG_MAX || pread(fd, fmt, take, (off_t)body) != (ssize_t)take) {
                snprintf(err_msg, err_msg_sz, "Cannot read WAV format information");
                return -1;
            }
            fmt_tag = db_load_u16le(fmt);
            channels = db_load_u16le(fmt + 2);
            sample_rate = stego_load_u32le(fmt + 4);
            block_align = db_load_u16le(fmt + 12);
            bits = db_load_u16le(fmt + 14);
            if (fmt_tag == 0xFFFEU) {

                static const unsigned char pcm_guid[16] = {
                    0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x00,
                    0x80,0x00,0x00,0xAA,0x00,0x38,0x9B,0x71
                };
                if (chunk_size < 40 || memcmp(fmt + 24, pcm_guid, sizeof(pcm_guid)) != 0) {
                    snprintf(err_msg, err_msg_sz, "Only integer PCM WAV is supported for steganography");
                    return -1;
                }
            } else if (fmt_tag != 1U) {
                snprintf(err_msg, err_msg_sz, "Only uncompressed integer PCM WAV is supported for steganography");
                return -1;
            }
            have_fmt = TRUE;
        } else if (memcmp(ch, "data", 4) == 0 && !have_data) {
            data_offset = body;
            data_size = chunk_size;
            have_data = TRUE;
        }
        uint64_t advance = 8ULL + (uint64_t)chunk_size + (uint64_t)(chunk_size & 1U);
        if (advance > file_size - pos) break;
        pos += advance;
    }

    if (!have_fmt || !have_data || channels == 0 || sample_rate == 0 ||
        (bits != 8 && bits != 16 && bits != 24 && bits != 32) || bits % 8 != 0) {
        snprintf(err_msg, err_msg_sz, "WAV must be PCM with 8, 16, 24, or 32-bit integer samples");
        return -1;
    }
    uint32_t bytes_per_sample = (uint32_t)bits / 8U;
    uint64_t expected_align = (uint64_t)channels * bytes_per_sample;
    if (expected_align == 0 || expected_align > UINT16_MAX || block_align != (uint16_t)expected_align ||
        data_size < bytes_per_sample || data_size % block_align != 0 ||
        data_offset > file_size || data_size > file_size - data_offset) {
        snprintf(err_msg, err_msg_sz, "WAV sample layout is inconsistent");
        return -1;
    }

    memset(info, 0, sizeof(*info));
    info->format_tag = fmt_tag;
    info->channels = channels;
    info->sample_rate = sample_rate;
    info->block_align = block_align;
    info->bits_per_sample = bits;
    info->bytes_per_sample = bytes_per_sample;
    info->data_offset = data_offset;
    info->data_size = data_size;
    return 0;
}

static unsigned char *stego_wav_slot_ptr(unsigned char *map,
    const stego_wav_info_t *info, uint64_t slot)
{
    return map + info->data_offset + slot * (uint64_t)info->bytes_per_sample;
}

static gboolean stego_wav_seed_mode(const unsigned char *map, const stego_wav_info_t *info,
    unsigned char out[STEGO_SEED_BYTES], gboolean keyed, char *err_msg, size_t err_msg_sz)
{
    if (!map || !info || !out || info->bytes_per_sample == 0) return FALSE;
    uint64_t slots = info->data_size / info->bytes_per_sample;
    if (slots < (uint64_t)STEGO_HEADER_BYTES * 8U) {
        snprintf(err_msg, err_msg_sz, "WAV contains too few PCM samples for steganography");
        return FALSE;
    }

    unsigned char secret_snapshot[32];
    const unsigned char *key = NULL;
    size_t key_len = 0;
    sodium_memzero(secret_snapshot, sizeof(secret_snapshot));
    if (keyed) {
        if (!stego_secret_snapshot(secret_snapshot)) return FALSE;
        key = secret_snapshot;
        key_len = sizeof(secret_snapshot);
    }

    crypto_generichash_state st;
    if (crypto_generichash_init(&st, key, key_len, STEGO_SEED_BYTES) != 0) {
        sodium_memzero(secret_snapshot, sizeof(secret_snapshot));
        snprintf(err_msg, err_msg_sz, "Cannot initialize WAV steganography hash");
        return FALSE;
    }
    static const unsigned char public_ctx[] = "DiskPass WAV PCM bootstrap seed v3";
    static const unsigned char legacy_ctx[] = "DiskPass WAV PCM steganography seed v2";
    const unsigned char *ctx = keyed ? legacy_ctx : public_ctx;
    size_t ctx_len = keyed ? sizeof(legacy_ctx) - 1 : sizeof(public_ctx) - 1;
    crypto_generichash_update(&st, ctx, ctx_len);
    unsigned char meta[24] = {0};
    meta[0] = (unsigned char)info->channels;
    meta[1] = (unsigned char)(info->channels >> 8);
    meta[2] = (unsigned char)info->bits_per_sample;
    meta[3] = (unsigned char)(info->bits_per_sample >> 8);
    meta[4] = (unsigned char)info->sample_rate;
    meta[5] = (unsigned char)(info->sample_rate >> 8);
    meta[6] = (unsigned char)(info->sample_rate >> 16);
    meta[7] = (unsigned char)(info->sample_rate >> 24);
    db_store_u64le(meta + 8, info->data_size);
    db_store_u64le(meta + 16, slots);
    crypto_generichash_update(&st, meta, sizeof(meta));

    unsigned char buf[4096];
    size_t used = 0;
    for (uint64_t i = 0; i < slots; i++) {
        const unsigned char *p = map + info->data_offset + i * (uint64_t)info->bytes_per_sample;
        buf[used++] = (unsigned char)(*p & 0xFEU);
        if (used == sizeof(buf)) {
            crypto_generichash_update(&st, buf, used);
            used = 0;
        }
    }
    if (used) crypto_generichash_update(&st, buf, used);
    sodium_memzero(buf, sizeof(buf));
    crypto_generichash_final(&st, out, STEGO_SEED_BYTES);
    sodium_memzero(secret_snapshot, sizeof(secret_snapshot));
    return TRUE;
}

static gboolean stego_wav_seed(const unsigned char *map, const stego_wav_info_t *info,
    unsigned char out[STEGO_SEED_BYTES], char *err_msg, size_t err_msg_sz)
{
    return stego_wav_seed_mode(map, info, out, FALSE, err_msg, err_msg_sz);
}

static gboolean stego_wav_seed_legacy(const unsigned char *map, const stego_wav_info_t *info,
    unsigned char out[STEGO_SEED_BYTES], char *err_msg, size_t err_msg_sz)
{
    return stego_wav_seed_mode(map, info, out, TRUE, err_msg, err_msg_sz);
}

static void stego_wav_write_bytes(unsigned char *map, const stego_wav_info_t *info,
    stego_iter_t *it, const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char v = data[i];
        for (unsigned b = 0; b < 8; b++) {
            unsigned char *p = stego_wav_slot_ptr(map, info, stego_iter_next(it));
            *p = (unsigned char)((*p & 0xFEU) | ((v >> b) & 1U));
        }
    }
}

static void stego_wav_read_bytes(const unsigned char *map, const stego_wav_info_t *info,
    stego_iter_t *it, unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char v = 0;
        for (unsigned b = 0; b < 8; b++) {
            const unsigned char *p = map + info->data_offset +
                stego_iter_next(it) * (uint64_t)info->bytes_per_sample;
            v |= (unsigned char)((*p & 1U) << b);
        }
        data[i] = v;
    }
}

static gboolean stego_wav_decode_header(const unsigned char *map,
    const stego_wav_info_t *info, const unsigned char seed[STEGO_SEED_BYTES],
    unsigned char expected_version, uint64_t *payload_len,
    unsigned char payload_hash[STEGO_HASH_BYTES], stego_iter_t *payload_it)
{
    uint64_t slots = info->data_size / info->bytes_per_sample;
    if (slots < (uint64_t)STEGO_HEADER_BYTES * 8U) return FALSE;
    stego_iter_t it;
    if (!stego_iter_init(&it, slots, seed)) return FALSE;
    unsigned char enc[STEGO_HEADER_BYTES], plain[STEGO_HEADER_BYTES], mask[STEGO_HEADER_BYTES];
    unsigned char check[STEGO_CHECK_BYTES];
    stego_wav_read_bytes(map, info, &it, enc, sizeof(enc));
    stego_header_mask(seed, mask);
    for (size_t i = 0; i < sizeof(plain); i++) plain[i] = (unsigned char)(enc[i] ^ mask[i]);
    stego_header_check(seed, plain, check);
    gboolean ok = sodium_memcmp(check, plain + STEGO_HEADER_BYTES - STEGO_CHECK_BYTES,
        STEGO_CHECK_BYTES) == 0 && plain[40] == expected_version;
    uint64_t len = db_load_u64le(plain);
    uint64_t capacity = slots / 8U;
    if (!ok || len == 0 || len > DB_MAX_FILE_BYTES || len > capacity ||
        STEGO_HEADER_BYTES > capacity - len) ok = FALSE;
    if (ok) {
        if (payload_len) *payload_len = len;
        if (payload_hash) memcpy(payload_hash, plain + 8, STEGO_HASH_BYTES);
        if (payload_it) *payload_it = it;
    }
    sodium_memzero(enc, sizeof(enc));
    sodium_memzero(plain, sizeof(plain));
    sodium_memzero(mask, sizeof(mask));
    sodium_memzero(check, sizeof(check));
    return ok;
}

static int carrier_copy_fd_exact(int src, int dst, uint64_t len,
    char *err_msg, size_t err_msg_sz)
{
    unsigned char buf[256 * 1024];
    uint64_t off = 0;
    while (off < len) {
        size_t want = sizeof(buf);
        if (len - off < want) want = (size_t)(len - off);
        ssize_t n = pread(src, buf, want, (off_t)off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            snprintf(err_msg, err_msg_sz, "Cannot copy carrier file: %s",
                n < 0 ? strerror(errno) : "unexpected end of file");
            sodium_memzero(buf, sizeof(buf));
            return -1;
        }
        if (write_all_fd(dst, buf, (size_t)n) != 0) {
            snprintf(err_msg, err_msg_sz, "Cannot write carrier output: %s", strerror(errno));
            sodium_memzero(buf, sizeof(buf));
            return -1;
        }
        off += (uint64_t)n;
    }
    sodium_memzero(buf, sizeof(buf));
    return 0;
}

static int carrier_attach_dpdb_wav(const char *carrier_path, const char *db_path,
    const char *output_path, char *err_msg, size_t err_msg_sz)
{
    int cfd = -1, dfd = -1, tfd = -1;
    uint64_t carrier_size = 0, db_size = 0;
    unsigned char *src_map = MAP_FAILED, *dst_map = MAP_FAILED;
    char *tmp = NULL;
    int rc = -1;
    stego_wav_info_t info;
    unsigned char seed[STEGO_SEED_BYTES], payload_hash[STEGO_HASH_BYTES];
    unsigned char header[STEGO_HEADER_BYTES], mask[STEGO_HEADER_BYTES], check[STEGO_CHECK_BYTES];

    if (!carrier_path || !db_path || !output_path ||
        !carrier_paths_distinct(carrier_path, output_path) ||
        !carrier_paths_distinct(db_path, output_path)) {
        snprintf(err_msg, err_msg_sz, "Output WAV must be different from the cover WAV and database");
        return -1;
    }
    if (!g_str_has_suffix(output_path, ".wav") && !g_str_has_suffix(output_path, ".WAV")) {
        snprintf(err_msg, err_msg_sz, "PCM audio steganography output must use the .wav extension");
        return -1;
    }
    if (carrier_open_regular(db_path, DB_MAX_FILE_BYTES, &dfd, &db_size, err_msg, err_msg_sz) != 0)
        goto cleanup;
    if (!db_path_has_dpdb_extension(db_path) || !carrier_dpdb_layout_at_fd(dfd, 0, db_size)) {
        snprintf(err_msg, err_msg_sz,
            "Only valid DiskPass .dpdb databases can be hidden");
        goto cleanup;
    }
    if (carrier_open_regular(carrier_path, DB_CARRIER_MAX_BYTES, &cfd, &carrier_size, err_msg, err_msg_sz) != 0)
        goto cleanup;
    if (stego_wav_parse_fd(cfd, carrier_size, &info, err_msg, err_msg_sz) != 0) goto cleanup;
    if (carrier_size > SIZE_MAX) {
        snprintf(err_msg, err_msg_sz, "WAV is too large for this build");
        goto cleanup;
    }
    /* Verify the opened carrier has not changed since its size was checked.
     * Mapping an fd avoids pathname substitution, while this also catches
     * truncation races that could otherwise SIGBUS during access. */
    struct stat carrier_st;
    if (fstat(cfd, &carrier_st) != 0 || !S_ISREG(carrier_st.st_mode) ||
        carrier_st.st_size < 0 || (uint64_t)carrier_st.st_size != carrier_size) {
        snprintf(err_msg, err_msg_sz, "WAV carrier changed while opening");
        goto cleanup;
    }
    src_map = mmap(NULL, (size_t)carrier_size, PROT_READ, MAP_PRIVATE, cfd, 0);
    if (src_map == MAP_FAILED) {
        snprintf(err_msg, err_msg_sz, "Cannot map WAV carrier: %s", strerror(errno));
        goto cleanup;
    }
    if (!stego_wav_seed(src_map, &info, seed, err_msg, err_msg_sz)) goto cleanup;
    uint64_t slots = info.data_size / info.bytes_per_sample;
    if (!stego_embedding_budget(slots, db_size, err_msg, err_msg_sz)) goto cleanup;
    uint64_t capacity = slots / 8U;
    if (capacity < STEGO_HEADER_BYTES || db_size > capacity - STEGO_HEADER_BYTES) {
        uint64_t usable = capacity > STEGO_HEADER_BYTES ? capacity - STEGO_HEADER_BYTES : 0;
        snprintf(err_msg, err_msg_sz,
            "WAV is too small for this database: capacity %.2f MiB, database %.2f MiB. Use a longer/higher-rate PCM WAV",
            (double)usable / (1024.0 * 1024.0), (double)db_size / (1024.0 * 1024.0));
        goto cleanup;
    }
    if (!g_atomic_int_get(&g_stego_replace_existing_payload)) {
        gboolean has_payload = stego_wav_decode_header(src_map, &info, seed, STEGO_VERSION,
            NULL, NULL, NULL);
        if (!has_payload) {
            unsigned char legacy_seed[STEGO_SEED_BYTES];
            if (stego_wav_seed_legacy(src_map, &info, legacy_seed, err_msg, err_msg_sz))
                has_payload = stego_wav_decode_header(src_map, &info, legacy_seed,
                    STEGO_LEGACY_VERSION, NULL, NULL, NULL);
            sodium_memzero(legacy_seed, sizeof(legacy_seed));
        }
        if (has_payload) {
            snprintf(err_msg, err_msg_sz, "The selected WAV already appears to contain a DiskPass stego payload");
            goto cleanup;
        }
    }
    if (stego_hash_fd(dfd, db_size, payload_hash, err_msg, err_msg_sz) != 0) goto cleanup;

    memset(header, 0, sizeof(header));
    db_store_u64le(header, db_size);
    memcpy(header + 8, payload_hash, STEGO_HASH_BYTES);
    header[40] = STEGO_VERSION;
    randombytes_buf(header + 41, 15);
    stego_header_check(seed, header, check);
    memcpy(header + STEGO_HEADER_BYTES - STEGO_CHECK_BYTES, check, STEGO_CHECK_BYTES);
    stego_header_mask(seed, mask);
    for (size_t i = 0; i < sizeof(header); i++) header[i] ^= mask[i];

    if (carrier_create_temp(output_path, &tmp, &tfd, err_msg, err_msg_sz) != 0) goto cleanup;
    if (carrier_copy_fd_exact(cfd, tfd, carrier_size, err_msg, err_msg_sz) != 0) goto cleanup;
    if (fsync(tfd) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot sync temporary WAV: %s", strerror(errno));
        goto cleanup;
    }
    if (close(tfd) != 0) {
        tfd = -1;
        snprintf(err_msg, err_msg_sz, "Cannot close temporary WAV: %s", strerror(errno));
        goto cleanup;
    }
    tfd = -1;
    tfd = open(tmp, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (tfd < 0) {
        snprintf(err_msg, err_msg_sz, "Cannot reopen temporary WAV: %s", strerror(errno));
        goto cleanup;
    }
    dst_map = mmap(NULL, (size_t)carrier_size, PROT_READ | PROT_WRITE, MAP_SHARED, tfd, 0);
    if (dst_map == MAP_FAILED) {
        snprintf(err_msg, err_msg_sz, "Cannot map temporary WAV: %s", strerror(errno));
        goto cleanup;
    }

    stego_iter_t it;
    stego_iter_init(&it, slots, seed);
    stego_wav_write_bytes(dst_map, &info, &it, header, sizeof(header));
    unsigned char buf[128 * 1024];
    uint64_t off = 0;
    while (off < db_size) {
        size_t want = sizeof(buf);
        if (db_size - off < want) want = (size_t)(db_size - off);
        ssize_t n = pread(dfd, buf, want, (off_t)off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            snprintf(err_msg, err_msg_sz, "Cannot read database for WAV steganography: %s",
                n < 0 ? strerror(errno) : "unexpected end of file");
            sodium_memzero(buf, sizeof(buf));
            goto cleanup;
        }
        stego_wav_write_bytes(dst_map, &info, &it, buf, (size_t)n);
        off += (uint64_t)n;
    }
    sodium_memzero(buf, sizeof(buf));
    if (msync(dst_map, (size_t)carrier_size, MS_SYNC) != 0 || fsync(tfd) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot sync stego WAV: %s", strerror(errno));
        goto cleanup;
    }
    munmap(dst_map, (size_t)carrier_size); dst_map = MAP_FAILED;
    if (close(tfd) != 0) {
        tfd = -1;
        snprintf(err_msg, err_msg_sz, "Cannot close stego WAV: %s", strerror(errno));
        goto cleanup;
    }
    tfd = -1;
    if (rename(tmp, output_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot atomically install stego WAV: %s", strerror(errno));
        goto cleanup;
    }
    carrier_fsync_parent(output_path);
    rc = 0;
cleanup:
    if (src_map != MAP_FAILED) munmap(src_map, (size_t)carrier_size);
    if (dst_map != MAP_FAILED) munmap(dst_map, (size_t)carrier_size);
    if (cfd >= 0) close(cfd);
    if (dfd >= 0) close(dfd);
    if (tfd >= 0) close(tfd);
    if (rc != 0 && tmp) unlink(tmp);
    free(tmp);
    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(payload_hash, sizeof(payload_hash));
    sodium_memzero(header, sizeof(header));
    sodium_memzero(mask, sizeof(mask));
    sodium_memzero(check, sizeof(check));
    return rc;
}

static int carrier_extract_dpdb_wav(const char *wav_path, const char *output_db_path,
    char *err_msg, size_t err_msg_sz)
{
    int wfd = -1, ofd = -1;
    uint64_t wav_size = 0, payload_len = 0;
    unsigned char *map = MAP_FAILED;
    char *tmp = NULL;
    int rc = -1;
    stego_wav_info_t info;
    unsigned char seed[STEGO_SEED_BYTES], expected_hash[STEGO_HASH_BYTES], actual_hash[STEGO_HASH_BYTES];
    stego_iter_t it;

    if (!wav_path || !output_db_path || !db_path_has_dpdb_extension(output_db_path) ||
        !carrier_paths_distinct(wav_path, output_db_path)) {
        snprintf(err_msg, err_msg_sz, "Extracted database must use a different .dpdb path");
        return -1;
    }
    if (carrier_open_regular(wav_path, DB_CARRIER_MAX_BYTES, &wfd, &wav_size, err_msg, err_msg_sz) != 0)
        goto cleanup;
    if (stego_wav_parse_fd(wfd, wav_size, &info, err_msg, err_msg_sz) != 0) goto cleanup;
    if (wav_size > SIZE_MAX) {
        snprintf(err_msg, err_msg_sz, "WAV is too large for this build");
        goto cleanup;
    }
    map = mmap(NULL, (size_t)wav_size, PROT_READ, MAP_PRIVATE, wfd, 0);
    if (map == MAP_FAILED) {
        snprintf(err_msg, err_msg_sz, "Cannot map WAV carrier: %s", strerror(errno));
        goto cleanup;
    }
    if (!stego_wav_seed(map, &info, seed, err_msg, err_msg_sz)) goto cleanup;
    gboolean found = stego_wav_decode_header(map, &info, seed, STEGO_VERSION,
        &payload_len, expected_hash, &it);
    if (!found) {
        unsigned char legacy_seed[STEGO_SEED_BYTES];
        if (stego_wav_seed_legacy(map, &info, legacy_seed, err_msg, err_msg_sz)) {
            found = stego_wav_decode_header(map, &info, legacy_seed, STEGO_LEGACY_VERSION,
                &payload_len, expected_hash, &it);
            if (found) memcpy(seed, legacy_seed, sizeof(seed));
        }
        sodium_memzero(legacy_seed, sizeof(legacy_seed));
    }
    if (!found) {
        snprintf(err_msg, err_msg_sz, "No valid DiskPass steganographic payload was found in this PCM WAV");
        goto cleanup;
    }
    if (carrier_create_temp(output_db_path, &tmp, &ofd, err_msg, err_msg_sz) != 0) goto cleanup;

    crypto_generichash_state hst;
    crypto_generichash_init(&hst, NULL, 0, STEGO_HASH_BYTES);
    unsigned char buf[128 * 1024];
    uint64_t remaining = payload_len;
    while (remaining) {
        size_t take = sizeof(buf);
        if (remaining < take) take = (size_t)remaining;
        stego_wav_read_bytes(map, &info, &it, buf, take);
        crypto_generichash_update(&hst, buf, take);
        if (write_all_fd(ofd, buf, take) != 0) {
            snprintf(err_msg, err_msg_sz, "Cannot write extracted database: %s", strerror(errno));
            sodium_memzero(buf, sizeof(buf));
            goto cleanup;
        }
        remaining -= take;
    }
    sodium_memzero(buf, sizeof(buf));
    crypto_generichash_final(&hst, actual_hash, STEGO_HASH_BYTES);
    if (sodium_memcmp(expected_hash, actual_hash, STEGO_HASH_BYTES) != 0) {
        snprintf(err_msg, err_msg_sz, "Steganographic payload integrity check failed; WAV may have been modified or re-encoded");
        goto cleanup;
    }
    if (fsync(ofd) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot sync extracted database: %s", strerror(errno));
        goto cleanup;
    }
    if (close(ofd) != 0) {
        ofd = -1;
        snprintf(err_msg, err_msg_sz, "Cannot close extracted database: %s", strerror(errno));
        goto cleanup;
    }
    ofd = -1;
    int verify_fd = open(tmp, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (verify_fd < 0 || !carrier_dpdb_layout_at_fd(verify_fd, 0, payload_len)) {
        if (verify_fd >= 0) close(verify_fd);
        snprintf(err_msg, err_msg_sz, "Hidden payload is intact but is not a recognized DiskPass .dpdb container");
        goto cleanup;
    }
    close(verify_fd);
    if (rename(tmp, output_db_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot atomically install extracted database: %s", strerror(errno));
        goto cleanup;
    }
    carrier_fsync_parent(output_db_path);
    rc = 0;
cleanup:
    if (map != MAP_FAILED) munmap(map, (size_t)wav_size);
    if (wfd >= 0) close(wfd);
    if (ofd >= 0) close(ofd);
    if (rc != 0 && tmp) unlink(tmp);
    free(tmp);
    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(expected_hash, sizeof(expected_hash));
    sodium_memzero(actual_hash, sizeof(actual_hash));
    return rc;
}

static int carrier_attach_dpdb_base(const char *carrier_path, const char *db_path,
    const char *output_path, char *err_msg, size_t err_msg_sz)
{
    if (stego_path_is_wav(carrier_path))
        return carrier_attach_dpdb_wav(carrier_path, db_path, output_path, err_msg, err_msg_sz);
    return carrier_attach_dpdb_image(carrier_path, db_path, output_path, err_msg, err_msg_sz);
}

static int carrier_extract_dpdb_base(const char *carrier_path, const char *output_db_path,
    char *err_msg, size_t err_msg_sz)
{
    if (stego_path_is_wav(carrier_path))
        return carrier_extract_dpdb_wav(carrier_path, output_db_path, err_msg, err_msg_sz);
    return carrier_extract_dpdb_image(carrier_path, output_db_path, err_msg, err_msg_sz);
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
    long long timestamp;
    uint64_t generation;
    char *action;
    char *target;
} db_history_event_t;

typedef struct {
    char *label, *type, *size, *cipher, *content_tag, *dsalt, *tag_full, *dpass, *notes, *alias;
    char *files;
    char *smart;
    char *uuid;
    long long last_snapshot;
    int file_count;
    long long indexed_bytes;
} db_entry_t;


static gboolean db_parse_size_span(const char *s, const char *end, long long *out) {
    if (!s || !end || !out || end <= s || (size_t)(end - s) > 19) return FALSE;
    long long n = 0;
    for (const char *p = s; p < end; p++) {
        if (*p < '0' || *p > '9') return FALSE;
        int digit = *p - '0';
        if (n > (LLONG_MAX - digit) / 10) return FALSE;
        n = n * 10 + digit;
    }
    *out = n;
    return TRUE;
}

static gboolean db_json_size_valid(const cJSON *value) {
    return cJSON_IsNumber(value) && isfinite(value->valuedouble) &&
        value->valuedouble >= 0 && value->valuedouble < (double)LLONG_MAX &&
        floor(value->valuedouble) == value->valuedouble;
}

static void db_entry_refresh_index_stats(db_entry_t *e) {
    if (!e) return;
    e->file_count = 0;
    e->indexed_bytes = 0;
    if (!e->files || !e->files[0]) return;

    const char *p = e->files;
    while (*p) {
        const char *line_end = strchr(p, '\n');
        if (!line_end) line_end = p + strlen(p);
        const char *tab = memchr(p, '\t', (size_t)(line_end - p));
        if (line_end > p) {
            e->file_count++;
            if (tab && tab + 1 < line_end) {
                long long v = 0;
                if (db_parse_size_span(tab + 1, line_end, &v) && v > 0 &&
                    LLONG_MAX - e->indexed_bytes >= v)
                    e->indexed_bytes += v;
            }
        }
        if (!*line_end) break;
        p = line_end + 1;
    }
}

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

typedef int (*db_external_commit_hook_t)(const char *db_path, char *err_msg, size_t err_msg_sz);
static db_external_commit_hook_t g_db_external_commit_hook = NULL;


typedef struct {
    gboolean valid, exists;
    struct stat st;
    unsigned char hash[crypto_generichash_BYTES];
} db_file_snapshot_t;

static gboolean db_same_file_stat(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int db_file_snapshot(const char *path, db_file_snapshot_t *out,
    char *err_msg, size_t err_msg_sz) {
    memset(out, 0, sizeof(*out));
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            struct stat st;
            if (lstat(path, &st) != 0 && errno == ENOENT) {
                out->valid = TRUE;
                return 0;
            }
        }
        snprintf(err_msg, err_msg_sz, "Cannot snapshot database safely: %s", strerror(errno));
        return -1;
    }
    struct stat after, named;
    int rc = -1;
    crypto_generichash_state hs;
    unsigned char buf[65536];
    if (fstat(fd, &out->st) != 0 || !S_ISREG(out->st.st_mode) ||
        out->st.st_size < 0 || (uint64_t)out->st.st_size > DB_MAX_FILE_BYTES) goto done;
    crypto_generichash_init(&hs, NULL, 0, sizeof(out->hash));
    uint64_t total = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto done;
        if (n == 0) break;
        total += (uint64_t)n;
        if (total > DB_MAX_FILE_BYTES) goto done;
        crypto_generichash_update(&hs, buf, (size_t)n);
    }
    if (fstat(fd, &after) != 0 || lstat(path, &named) != 0 ||
        !db_same_file_stat(&out->st, &after) || !db_same_file_stat(&after, &named) ||
        total != (uint64_t)after.st_size) goto done;
    crypto_generichash_final(&hs, out->hash, sizeof(out->hash));
    out->valid = out->exists = TRUE;
    rc = 0;
done:
    sodium_memzero(buf, sizeof(buf));
    sodium_memzero(&hs, sizeof(hs));
    close(fd);
    if (rc != 0) snprintf(err_msg, err_msg_sz, "Database changed or could not be safely inspected; reopen it");
    return rc;
}

static int db_snapshot_check(const char *path, const db_file_snapshot_t *expected,
    char *err_msg, size_t err_msg_sz) {
    db_file_snapshot_t now;
    if (!expected->valid || db_file_snapshot(path, &now, err_msg, err_msg_sz) != 0 ||
        now.exists != expected->exists || (now.exists &&
        (!db_same_file_stat(&now.st, &expected->st) ||
         sodium_memcmp(now.hash, expected->hash, sizeof(now.hash)) != 0))) {
        snprintf(err_msg, err_msg_sz, "Database changed since open/create or snapshot unavailable; reopen before saving");
        return -1;
    }
    return 0;
}


static int db_save_lock(const char *path, char *err_msg, size_t err_msg_sz) {
    char *name = g_strconcat(path, ".lock", NULL);
    if (!name) { snprintf(err_msg, err_msg_sz, "Cannot allocate database lock path"); return -1; }
    int fd = open(name, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    struct stat st, named;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != geteuid() || st.st_nlink != 1 || (st.st_mode & 077) != 0 ||
        flock(fd, LOCK_EX | LOCK_NB) != 0 || lstat(name, &named) != 0 ||
        st.st_dev != named.st_dev || st.st_ino != named.st_ino) {
        if (fd >= 0) close(fd);
        g_free(name);
        snprintf(err_msg, err_msg_sz, "Database is busy or its sidecar lock is unsafe; close other writers and retry");
        return -1;
    }
    g_free(name);
    return fd;
}

typedef struct {
    char *file_path, *recipient;
    db_file_snapshot_t file_snapshot;
    uint8_t *salt; size_t salt_len;
    uint8_t *noise_key; size_t noise_key_len;
    char *schema_order[5];
    char lang[32];
    db_entry_t *entries;
    int entry_count, entry_cap;
    search_filter_t *filters;
    int filter_count, filter_cap;
    db_history_event_t *history;
    int history_count, history_cap;
    gpgme_ctx_t gpg_ctx;
    gboolean is_signed;
    gboolean is_pqc_encrypted;

    char db_id[DB_ID_HEX_LEN + 1];
    uint64_t generation;
    char previous_commit[DB_COMMIT_HEX_LEN + 1];
    char commit[DB_COMMIT_HEX_LEN + 1];
    int commit_version;
    gboolean has_commit_chain;
    gboolean rollback_state_verified;

    gboolean defer_chainless_consent;
    gboolean legacy_read_only;

    gboolean require_pqc;


    gboolean force_fresh_pinentry;
} db_manager_t;

static gboolean db_hex_string_valid(const char *s, size_t expected_len) {
    if (!s || strlen(s) != expected_len) return FALSE;
    for (size_t i = 0; i < expected_len; i++)
        if (!g_ascii_isxdigit((guchar)s[i])) return FALSE;
    return TRUE;
}

static void db_history_event_clear(db_history_event_t *ev) {
    if (!ev) return;
    secure_free_string(&ev->action);
    secure_free_string(&ev->target);
    ev->timestamp = 0;
    ev->generation = 0;
}

static gboolean db_history_action_valid(const char *action) {
    if (!action || !action[0] || strlen(action) > DB_HISTORY_ACTION_MAX) return FALSE;
    for (const unsigned char *p = (const unsigned char *)action; *p; p++) {
        if (!(g_ascii_islower(*p) || g_ascii_isdigit(*p) || *p == '_')) return FALSE;
    }
    return TRUE;
}

static const char *db_history_entry_target(const db_entry_t *e) {
    if (!e) return "";
    if (e->alias && e->alias[0] && strlen(e->alias) <= DB_HISTORY_TARGET_MAX &&
        g_utf8_validate(e->alias, -1, NULL))
        return e->alias;
    return e->label ? e->label : "";
}

static int db_history_mark(db_manager_t *m, const char *action, const char *target,
    int *previous_count, char *err_msg, size_t err_msg_sz)
{
    if (!m || !db_history_action_valid(action)) {
        if (err_msg && err_msg_sz) snprintf(err_msg, err_msg_sz, "Invalid history event");
        return -1;
    }
    if (target && (!g_utf8_validate(target, -1, NULL) || strlen(target) > DB_HISTORY_TARGET_MAX)) {
        if (err_msg && err_msg_sz) snprintf(err_msg, err_msg_sz, "History target is invalid or too long");
        return -1;
    }
    if (m->has_commit_chain && m->generation == UINT64_MAX) {
        if (err_msg && err_msg_sz) snprintf(err_msg, err_msg_sz, "Database generation counter exhausted");
        return -1;
    }
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        if (err_msg && err_msg_sz) snprintf(err_msg, err_msg_sz, "Cannot read system time for database history");
        return -1;
    }
    if (previous_count) *previous_count = m->history_count;
    if (m->history_count >= DB_MAX_HISTORY + 1) {
        if (err_msg && err_msg_sz) snprintf(err_msg, err_msg_sz, "History buffer limit reached");
        return -1;
    }
    if (m->history_count >= m->history_cap) {
        int new_cap = m->history_cap ? m->history_cap * 2 : 16;
        if (new_cap > DB_MAX_HISTORY + 1) new_cap = DB_MAX_HISTORY + 1;
        if (new_cap <= m->history_count) {
            if (err_msg && err_msg_sz) snprintf(err_msg, err_msg_sz, "History buffer limit reached");
            return -1;
        }
        db_history_event_t *tmp = realloc(m->history, (size_t)new_cap * sizeof(*tmp));
        if (!tmp) {
            if (err_msg && err_msg_sz) snprintf(err_msg, err_msg_sz, "Cannot allocate database history");
            return -1;
        }
        memset(tmp + m->history_cap, 0, (size_t)(new_cap - m->history_cap) * sizeof(*tmp));
        m->history = tmp;
        m->history_cap = new_cap;
    }
    db_history_event_t *ev = &m->history[m->history_count];
    memset(ev, 0, sizeof(*ev));
    ev->timestamp = (long long)now;
    ev->generation = m->has_commit_chain ? m->generation + 1 : 1;
    ev->action = xstrdup(action);
    ev->target = xstrdup(target ? target : "");
    if (!ev->action || !ev->target) {
        db_history_event_clear(ev);
        if (err_msg && err_msg_sz) snprintf(err_msg, err_msg_sz, "Cannot allocate database history event");
        return -1;
    }
    m->history_count++;
    return 0;
}

static void db_history_restore_count(db_manager_t *m, int count) {
    if (!m) return;
    if (count < 0) count = 0;
    while (m->history_count > count) {
        m->history_count--;
        db_history_event_clear(&m->history[m->history_count]);
    }
}

static void db_history_trim(db_manager_t *m) {
    if (!m || m->history_count <= DB_MAX_HISTORY) return;
    int drop = m->history_count - DB_MAX_HISTORY;
    for (int i = 0; i < drop; i++) db_history_event_clear(&m->history[i]);
    memmove(m->history, m->history + drop,
        (size_t)(m->history_count - drop) * sizeof(*m->history));
    m->history_count -= drop;
    memset(m->history + m->history_count, 0,
        (size_t)(m->history_cap - m->history_count) * sizeof(*m->history));
}

static void db_random_id(char out[DB_ID_HEX_LEN + 1]) {
    unsigned char raw[DB_ID_HEX_LEN / 2];
    randombytes_buf(raw, sizeof(raw));
    sodium_bin2hex(out, DB_ID_HEX_LEN + 1, raw, sizeof(raw));
    sodium_memzero(raw, sizeof(raw));
}

static void db_hash_u64(crypto_generichash_state *st, uint64_t v) {
    unsigned char b[8];
    for (unsigned i = 0; i < 8; i++) b[i] = (unsigned char)(v >> (56U - i * 8U));
    crypto_generichash_update(st, b, sizeof(b));
}

static void db_hash_string(crypto_generichash_state *st, const char *s) {
    const unsigned char present = s ? 1U : 0U;
    crypto_generichash_update(st, &present, 1);
    if (!s) return;
    size_t len = strlen(s);
    db_hash_u64(st, (uint64_t)len);
    if (len) crypto_generichash_update(st, (const unsigned char *)s, len);
}

static gboolean db_compute_commit_hex_version(const db_manager_t *m, const char *db_id,
    uint64_t generation, const char *previous_commit, int commit_version,
    char out[DB_COMMIT_HEX_LEN + 1])
{
    if (!m || !m->noise_key || m->noise_key_len != crypto_generichash_KEYBYTES ||
        !db_hex_string_valid(db_id, DB_ID_HEX_LEN) ||
        !db_hex_string_valid(previous_commit, DB_COMMIT_HEX_LEN) ||
        (commit_version != 1 && commit_version != 2))
        return FALSE;

    crypto_generichash_state st;
    unsigned char digest[crypto_generichash_BYTES];
    if (crypto_generichash_init(&st, m->noise_key, m->noise_key_len, sizeof(digest)) != 0)
        return FALSE;

    if (commit_version == 1) {
        static const unsigned char domain_v1[] = "DiskPass-v3.1-commit-v1";
        crypto_generichash_update(&st, domain_v1, sizeof(domain_v1) - 1);
    } else {
        static const unsigned char domain_v2[] = "DiskPass-v3.2-commit-v2";
        crypto_generichash_update(&st, domain_v2, sizeof(domain_v2) - 1);
    }
    db_hash_string(&st, db_id);
    db_hash_u64(&st, generation);
    db_hash_string(&st, previous_commit);
    db_hash_u64(&st, (uint64_t)m->salt_len);
    if (m->salt_len) crypto_generichash_update(&st, m->salt, m->salt_len);
    db_hash_string(&st, m->lang);

    db_hash_u64(&st, SCHEMA_COUNT);
    for (int i = 0; i < SCHEMA_COUNT; i++) db_hash_string(&st, m->schema_order[i]);

    db_hash_u64(&st, (uint64_t)m->entry_count);
    for (int i = 0; i < m->entry_count; i++) {
        const db_entry_t *e = &m->entries[i];
        db_hash_string(&st, e->label);
        db_hash_string(&st, e->type);
        db_hash_string(&st, e->size);
        db_hash_string(&st, e->cipher);
        db_hash_string(&st, e->content_tag);
        db_hash_string(&st, e->dsalt);
        db_hash_string(&st, e->tag_full);
        db_hash_string(&st, e->dpass);
        db_hash_string(&st, e->notes);
        db_hash_string(&st, e->alias);
        db_hash_string(&st, e->files);
        db_hash_string(&st, e->smart);
        db_hash_string(&st, e->uuid);
        db_hash_u64(&st, (uint64_t)e->last_snapshot);
    }

    db_hash_u64(&st, (uint64_t)m->filter_count);
    for (int i = 0; i < m->filter_count; i++) {
        db_hash_string(&st, m->filters[i].name);
        db_hash_string(&st, m->filters[i].exts);
    }

    if (commit_version >= 2) {

        db_hash_string(&st, m->require_pqc ? DB_SECURITY_PQC : DB_SECURITY_CLASSIC);
        int history_start = m->history_count > DB_MAX_HISTORY ?
            m->history_count - DB_MAX_HISTORY : 0;
        int history_serialized = m->history_count - history_start;
        db_hash_u64(&st, (uint64_t)history_serialized);
        for (int i = history_start; i < m->history_count; i++) {
            const db_history_event_t *ev = &m->history[i];
            db_hash_u64(&st, (uint64_t)ev->timestamp);
            db_hash_u64(&st, ev->generation);
            db_hash_string(&st, ev->action);
            db_hash_string(&st, ev->target);
        }
    }

    crypto_generichash_final(&st, digest, sizeof(digest));
    sodium_bin2hex(out, DB_COMMIT_HEX_LEN + 1, digest, sizeof(digest));
    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(&st, sizeof(st));
    return TRUE;
}

static gboolean db_compute_commit_hex(const db_manager_t *m, const char *db_id,
    uint64_t generation, const char *previous_commit,
    char out[DB_COMMIT_HEX_LEN + 1])
{
    int version = (m && m->commit_version == 1) ? 1 : 2;
    return db_compute_commit_hex_version(m, db_id, generation, previous_commit,
        version, out);
}

static char *db_rollback_state_dir(void) {
    const char *override = g_getenv("DISKPASS_PRIVATE_DIR");
    if (override && override[0] == '/')
        return g_build_filename(override, "rollback-state", NULL);
    return g_build_filename(g_get_user_config_dir(), "diskpass", "rollback-state", NULL);
}

static gboolean db_rollback_state_dir_prepare(char **out_dir, gboolean create) {
    if (out_dir) *out_dir = NULL;
    char *dir = db_rollback_state_dir();
    if (!dir) return FALSE;
    if (create && g_mkdir_with_parents(dir, 0700) != 0) {
        g_free(dir);
        return FALSE;
    }
    struct stat st;
    if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 077) != 0) {
        g_free(dir);
        return FALSE;
    }
    if (chmod(dir, 0700) != 0) {
        g_free(dir);
        return FALSE;
    }
    if (out_dir) *out_dir = dir; else g_free(dir);
    return TRUE;
}

static gboolean db_any_protected_rollback_state_exists(void) {
    char *raw_dir = db_rollback_state_dir();
    if (!raw_dir) return TRUE;
    struct stat dir_st;
    if (lstat(raw_dir, &dir_st) != 0) {
        gboolean absent = errno == ENOENT;
        g_free(raw_dir);
        return absent ? FALSE : TRUE;
    }
    if (!S_ISDIR(dir_st.st_mode) || S_ISLNK(dir_st.st_mode) ||
        dir_st.st_uid != geteuid() || (dir_st.st_mode & 077) != 0) {
        g_free(raw_dir);
        return TRUE;
    }
    char *dir = raw_dir;
    DIR *dp = opendir(dir);
    if (!dp) { g_free(dir); return TRUE; }
    gboolean found = FALSE;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        size_t n = strlen(de->d_name);
        if (n <= 6 || strcmp(de->d_name + n - 6, ".state") != 0) continue;
        char *path = g_build_filename(dir, de->d_name, NULL);
        struct stat st;
        if (path && lstat(path, &st) == 0 && S_ISREG(st.st_mode) &&
            !S_ISLNK(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 077) == 0)
            found = TRUE;
        g_free(path);
        if (found) break;
    }
    closedir(dp);
    g_free(dir);
    return found;
}

static gboolean db_state_key_load_or_create(unsigned char key[DB_STATE_KEY_BYTES],
    gboolean *created)
{
    if (created) *created = FALSE;
    char *dir = NULL;
    if (!db_rollback_state_dir_prepare(&dir, TRUE)) return FALSE;

    char *path = g_build_filename(dir, "device.key", NULL);
    g_free(dir);
    if (!path) return FALSE;

    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd >= 0) {
        struct stat st;
        ssize_t got = read(fd, key, DB_STATE_KEY_BYTES);
        unsigned char extra;
        ssize_t more = read(fd, &extra, 1);
        gboolean ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
            st.st_uid == geteuid() && (st.st_mode & 077) == 0 &&
            got == DB_STATE_KEY_BYTES && more == 0;
        close(fd);
        g_free(path);
        return ok;
    }
    if (errno != ENOENT) { g_free(path); return FALSE; }

    unsigned char tmp[DB_STATE_KEY_BYTES];
    randombytes_buf(tmp, sizeof(tmp));
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        sodium_memzero(tmp, sizeof(tmp));
        g_free(path);
        return FALSE;
    }
    gboolean ok = fchmod(fd, 0600) == 0 &&
        write_all_fd(fd, tmp, sizeof(tmp)) == 0 && fsync(fd) == 0;
    if (close(fd) != 0) ok = FALSE;
    if (!ok) {
        unlink(path);
    } else {
        memcpy(key, tmp, sizeof(tmp));
        if (created) *created = TRUE;
    }
    sodium_memzero(tmp, sizeof(tmp));
    g_free(path);
    return ok;
}

static void db_state_mac_v1(const unsigned char key[DB_STATE_KEY_BYTES], const char *db_id,
    uint64_t generation, const char *commit, unsigned char mac[DB_STATE_MAC_BYTES])
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, DB_STATE_KEY_BYTES);
    static const unsigned char domain[] = "DiskPass-rollback-state-v1";
    crypto_auth_hmacsha256_update(&st, domain, sizeof(domain) - 1);
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)db_id, strlen(db_id));
    unsigned char sep = 0;
    crypto_auth_hmacsha256_update(&st, &sep, 1);
    char gen[32];
    snprintf(gen, sizeof(gen), "%" PRIu64, generation);
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)gen, strlen(gen));
    crypto_auth_hmacsha256_update(&st, &sep, 1);
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)commit, strlen(commit));
    crypto_auth_hmacsha256_final(&st, mac);
    sodium_memzero(&st, sizeof(st));
}

static void db_state_mac_v2(const unsigned char key[DB_STATE_KEY_BYTES], const char *db_id,
    uint64_t generation, const char *commit, gboolean require_pqc,
    unsigned char mac[DB_STATE_MAC_BYTES])
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, DB_STATE_KEY_BYTES);
    static const unsigned char domain[] = "DiskPass-rollback-state-v2";
    crypto_auth_hmacsha256_update(&st, domain, sizeof(domain) - 1);
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)db_id, strlen(db_id));
    unsigned char sep = 0;
    crypto_auth_hmacsha256_update(&st, &sep, 1);
    char gen[32];
    snprintf(gen, sizeof(gen), "%" PRIu64, generation);
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)gen, strlen(gen));
    crypto_auth_hmacsha256_update(&st, &sep, 1);
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)commit, strlen(commit));
    crypto_auth_hmacsha256_update(&st, &sep, 1);
    const unsigned char policy = require_pqc ? 1U : 0U;
    crypto_auth_hmacsha256_update(&st, &policy, 1);
    crypto_auth_hmacsha256_final(&st, mac);
    sodium_memzero(&st, sizeof(st));
}

static char *db_state_path_for_id(const char *db_id) {
    if (!db_hex_string_valid(db_id, DB_ID_HEX_LEN)) return NULL;
    char *dir = db_rollback_state_dir();
    if (!dir) return NULL;
    char name[DB_ID_HEX_LEN + 16];
    snprintf(name, sizeof(name), "%s.state", db_id);
    char *path = g_build_filename(dir, name, NULL);
    g_free(dir);
    return path;
}

static gboolean db_write_rollback_state(const db_manager_t *m) {
    if (!m || !m->has_commit_chain || !db_hex_string_valid(m->db_id, DB_ID_HEX_LEN) ||
        !db_hex_string_valid(m->commit, DB_COMMIT_HEX_LEN)) return FALSE;

    unsigned char key[DB_STATE_KEY_BYTES];
    gboolean created = FALSE;
    if (!db_state_key_load_or_create(key, &created)) return FALSE;
    (void)created;

    unsigned char mac[DB_STATE_MAC_BYTES];
    db_state_mac_v2(key, m->db_id, m->generation, m->commit, m->require_pqc, mac);
    char mac_hex[DB_STATE_MAC_BYTES * 2 + 1];
    sodium_bin2hex(mac_hex, sizeof(mac_hex), mac, sizeof(mac));

    char *dir = NULL;
    char *path = db_state_path_for_id(m->db_id);
    if (!db_rollback_state_dir_prepare(&dir, TRUE) || !path) {
        g_free(dir); g_free(path);
        sodium_memzero(key, sizeof(key)); sodium_memzero(mac, sizeof(mac));
        return FALSE;
    }

    size_t tlen = strlen(path) + sizeof(".tmp.XXXXXX");
    char *tmp_path = g_malloc(tlen);
    snprintf(tmp_path, tlen, "%s.tmp.XXXXXX", path);
    int fd = g_mkstemp_full(tmp_path, O_WRONLY | O_CLOEXEC, 0600);
    gboolean ok = FALSE;
    if (fd >= 0) {
        char body[256];
        int n = snprintf(body, sizeof(body), "DPSTATE2\n%s\n%" PRIu64 "\n%s\n%s\n%s\n",
            m->db_id, m->generation, m->commit, m->require_pqc ? "pqc" : "classic", mac_hex);
        gboolean wrote = n > 0 && (size_t)n < sizeof(body) &&
            write_all_fd(fd, body, (size_t)n) == 0 && fsync(fd) == 0;
        if (close(fd) != 0) wrote = FALSE;
        if (wrote && rename(tmp_path, path) == 0) {
            ok = TRUE;
            int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (dfd >= 0) { (void)fsync(dfd); close(dfd); }
        }
        sodium_memzero(body, sizeof(body));
    }
    if (!ok) unlink(tmp_path);

    sodium_memzero(key, sizeof(key));
    sodium_memzero(mac, sizeof(mac));
    sodium_memzero(mac_hex, sizeof(mac_hex));
    g_free(tmp_path); g_free(path); g_free(dir);
    return ok;
}

static int db_check_rollback_state(db_manager_t *m, char *err_msg, size_t err_msg_sz) {
    if (!m) return 0;
    if (!m->has_commit_chain) {
        m->legacy_read_only = TRUE;
        if (!m->defer_chainless_consent && db_any_protected_rollback_state_exists()) {
            snprintf(err_msg, err_msg_sz,
                "Protected rollback state exists; chainless opening requires explicit UI consent");
            return -1;
        }
        return 0;
    }
    unsigned char key[DB_STATE_KEY_BYTES];
    gboolean key_created = FALSE;
    if (!db_state_key_load_or_create(key, &key_created)) {
        snprintf(err_msg, err_msg_sz,
            "Rollback protection is unavailable; refusing to open a protected database");
        return -1;
    }

    char *path = db_state_path_for_id(m->db_id);
    if (!path) { sodium_memzero(key, sizeof(key)); return -1; }
    if (key_created) {
        g_free(path);
        sodium_memzero(key, sizeof(key));
        snprintf(err_msg, err_msg_sz,
            "Rollback state is missing on this device; refusing to trust an imported baseline automatically");
        return -1;
    }

    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        int saved_errno = errno;
        g_free(path);
        sodium_memzero(key, sizeof(key));
        if (saved_errno == ENOENT)
            snprintf(err_msg, err_msg_sz,
                "Rollback state is missing. Refusing to create a new baseline; use a separately reviewed trusted-import procedure only for an intentional device migration");
        else
            snprintf(err_msg, err_msg_sz, "Cannot open rollback state: %s", strerror(saved_errno));
        return -1;
    }
    struct stat st;
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    unsigned char extra = 0;
    ssize_t extra_n = (n > 0 && (size_t)n < sizeof(buf) - 1) ? read(fd, &extra, 1) : -1;
    gboolean regular = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && (st.st_mode & 077) == 0 &&
        st.st_size > 0 && st.st_size < (off_t)sizeof(buf) - 1 && extra_n == 0;
    close(fd);
    g_free(path);
    if (!regular || n <= 0 || (size_t)n >= sizeof(buf) - 1) {
        sodium_memzero(key, sizeof(key));
        snprintf(err_msg, err_msg_sz, "Local rollback state is corrupted");
        return -1;
    }
    buf[n] = '\0';

    char *save = NULL;
    char *magic = strtok_r(buf, "\n", &save);
    char *id = strtok_r(NULL, "\n", &save);
    char *gen_s = strtok_r(NULL, "\n", &save);
    char *commit = strtok_r(NULL, "\n", &save);
    char *policy = NULL;
    char *mac_hex = NULL;
    gboolean state_v2 = magic && strcmp(magic, "DPSTATE2") == 0;
    gboolean state_v1 = magic && strcmp(magic, "DPSTATE1") == 0;
    if (state_v2) {
        policy = strtok_r(NULL, "\n", &save);
        mac_hex = strtok_r(NULL, "\n", &save);
    } else if (state_v1) {
        mac_hex = strtok_r(NULL, "\n", &save);
    }
    if ((!state_v1 && !state_v2) || !id || !gen_s || !commit || !mac_hex ||
        strcmp(id, m->db_id) != 0 || !db_hex_string_valid(commit, DB_COMMIT_HEX_LEN) ||
        !db_hex_string_valid(mac_hex, DB_STATE_MAC_BYTES * 2) ||
        (state_v2 && (!policy || (strcmp(policy, "pqc") != 0 && strcmp(policy, "classic") != 0)))) {
        sodium_memzero(key, sizeof(key)); sodium_memzero(buf, sizeof(buf));
        snprintf(err_msg, err_msg_sz, "Local rollback state is invalid");
        return -1;
    }

    errno = 0;
    char *endp = NULL;
    unsigned long long stored_gen = strtoull(gen_s, &endp, 10);
    if (errno || !endp || *endp || !stored_gen || !db_generation_valid(gen_s)) {
        sodium_memzero(key, sizeof(key)); sodium_memzero(buf, sizeof(buf));
        snprintf(err_msg, err_msg_sz, "Local rollback generation is invalid");
        return -1;
    }

    gboolean stored_require_pqc = state_v2 ? strcmp(policy, "pqc") == 0 : m->is_pqc_encrypted;
    unsigned char expected_mac[DB_STATE_MAC_BYTES], stored_mac[DB_STATE_MAC_BYTES];
    size_t bin_len = 0;
    if (state_v2)
        db_state_mac_v2(key, id, (uint64_t)stored_gen, commit, stored_require_pqc, expected_mac);
    else
        db_state_mac_v1(key, id, (uint64_t)stored_gen, commit, expected_mac);
    if (sodium_hex2bin(stored_mac, sizeof(stored_mac), mac_hex, strlen(mac_hex),
            NULL, &bin_len, NULL) != 0 || bin_len != sizeof(stored_mac) ||
        sodium_memcmp(stored_mac, expected_mac, sizeof(stored_mac)) != 0) {
        sodium_memzero(key, sizeof(key)); sodium_memzero(buf, sizeof(buf));
        sodium_memzero(expected_mac, sizeof(expected_mac)); sodium_memzero(stored_mac, sizeof(stored_mac));
        snprintf(err_msg, err_msg_sz, "Local rollback state authentication failed");
        return -1;
    }

    int rc = 1;

    if (stored_require_pqc) m->require_pqc = TRUE;
    if (stored_require_pqc && !m->is_pqc_encrypted) {
        snprintf(err_msg, err_msg_sz,
            "Encryption downgrade detected: this database was previously pinned to PQC");
        rc = -1;
    } else if ((uint64_t)stored_gen > m->generation) {
        snprintf(err_msg, err_msg_sz,
            "Database rollback detected: local generation is newer than this file");
        rc = -1;
    } else if ((uint64_t)stored_gen == m->generation &&
               g_ascii_strcasecmp(commit, m->commit) != 0) {
        snprintf(err_msg, err_msg_sz,
            "Database fork detected: generation matches but commit differs");
        rc = -1;
    } else if ((uint64_t)stored_gen < m->generation || !state_v2 ||
               (m->require_pqc && !stored_require_pqc)) {
        if (stored_require_pqc) m->require_pqc = TRUE;
        if (!db_write_rollback_state(m)) {
            snprintf(err_msg, err_msg_sz, "Cannot update rollback state");
            rc = -1;
        } else {
            rc = 0;
        }
    }


    sodium_memzero(key, sizeof(key)); sodium_memzero(buf, sizeof(buf));
    sodium_memzero(expected_mac, sizeof(expected_mac)); sodium_memzero(stored_mac, sizeof(stored_mac));
    return rc;
}

static gboolean map_has_name(const map_entry_t *tbl, int n, const char *value);
static gboolean valid_ascii_tag_char(unsigned char c);
static gboolean valid_alphabet_string(const char *s, size_t expected_len);
static void secure_shuffle(const char **arr, int n);
static int db_init_gpg(db_manager_t *m, char *err_msg, size_t err_msg_sz);
static int db_read_file(const char *path, char **out_recipient, char **out_enc_data, char *err_msg, size_t err_msg_sz);
static char *db_gpg_decrypt(db_manager_t *m, const char *enc_data, size_t enc_len, char *err_msg, size_t err_msg_sz);
static gboolean db_recipient_has_pqc(db_manager_t *m);
static unsigned char *db_gpg_encrypt_binary_pqc(db_manager_t *m, const void *plaintext, size_t pt_len,
    gboolean hide_recipient, size_t *out_len, char *err_msg, size_t err_msg_sz);
static char *db_gpg_encrypt_legacy(db_manager_t *m, const char *plaintext, size_t pt_len, char *err_msg, size_t err_msg_sz);
static char *hex_encode(const uint8_t *data, size_t len);
static uint8_t *hex_decode(const char *hex, size_t *out_len);
static char *db_encode_label(db_manager_t *m, const char *type, const char *size, const char *content_tag, const char *cipher, const char *dsalt);
static gboolean db_label_matches_fields_compatible(db_manager_t *m, const char *label,
    const char *type, const char *size, const char *content_tag, const char *cipher, const char *dsalt);

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
    for (int i = 0; i < m->history_count; i++) db_history_event_clear(&m->history[i]);
    free(m->history); m->history = NULL;
    m->history_count = 0; m->history_cap = 0;
    secure_free_string(&m->file_path);
    secure_free_string(&m->recipient);
    if (m->salt) { SECURE_ZERO(m->salt, m->salt_len); sodium_free(m->salt); m->salt = NULL; m->salt_len = 0; }
    if (m->noise_key) { sec_free(m->noise_key, m->noise_key_len); m->noise_key = NULL; m->noise_key_len = 0; }


    stego_secret_clear_owner(m);
    for (int i = 0; i < SCHEMA_COUNT; i++) { secure_free_string(&m->schema_order[i]); }
    for (int i = 0; i < m->entry_count; i++) db_entry_clear(&m->entries[i]);
    free(m->entries); m->entries = NULL; m->entry_count = 0; m->entry_cap = 0;
    if (m->gpg_ctx) { gpgme_release(m->gpg_ctx); m->gpg_ctx = NULL; }
}

static gboolean db_index_shape_valid(const char *files);

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

    cJSON *j_security = cJSON_GetObjectItemCaseSensitive(root, "security_min");
    if (j_security) {
        if (!cJSON_IsString(j_security) || !j_security->valuestring ||
            (strcmp(j_security->valuestring, DB_SECURITY_PQC) != 0 &&
             strcmp(j_security->valuestring, DB_SECURITY_CLASSIC) != 0)) {
            snprintf(err_msg, err_msg_sz, "Invalid database security policy");
            goto cleanup;
        }
        m->require_pqc = strcmp(j_security->valuestring, DB_SECURITY_PQC) == 0;
    } else {

        m->require_pqc = m->is_pqc_encrypted;
    }
    if (m->require_pqc && !m->is_pqc_encrypted) {
        snprintf(err_msg, err_msg_sz,
            "Database security policy requires PQC encryption, but the current envelope is classical");
        goto cleanup;
    }

    cJSON *j_db_id = cJSON_GetObjectItemCaseSensitive(root, "db_id");
    cJSON *j_generation = cJSON_GetObjectItemCaseSensitive(root, "generation");
    cJSON *j_previous_commit = cJSON_GetObjectItemCaseSensitive(root, "previous_commit");
    cJSON *j_commit = cJSON_GetObjectItemCaseSensitive(root, "commit");
    cJSON *j_commit_alg = cJSON_GetObjectItemCaseSensitive(root, "commit_alg");
    gboolean any_chain = j_db_id || j_generation || j_previous_commit || j_commit || j_commit_alg;
    if (any_chain) {
        if (!j_db_id || !cJSON_IsString(j_db_id) ||
            !db_hex_string_valid(j_db_id->valuestring, DB_ID_HEX_LEN) ||
            !j_generation || !cJSON_IsString(j_generation) || !j_generation->valuestring ||
            !j_previous_commit || !cJSON_IsString(j_previous_commit) ||
            !db_hex_string_valid(j_previous_commit->valuestring, DB_COMMIT_HEX_LEN) ||
            !j_commit || !cJSON_IsString(j_commit) ||
            !db_hex_string_valid(j_commit->valuestring, DB_COMMIT_HEX_LEN)) {
            snprintf(err_msg, err_msg_sz, "Database commit-chain metadata is incomplete or invalid");
            goto cleanup;
        }
        errno = 0;
        char *endp = NULL;
        unsigned long long gen = strtoull(j_generation->valuestring, &endp, 10);
        if (errno || !endp || *endp || gen == 0 || !db_generation_valid(j_generation->valuestring)) {
            snprintf(err_msg, err_msg_sz, "Database generation is invalid");
            goto cleanup;
        }
        g_strlcpy(m->db_id, j_db_id->valuestring, sizeof(m->db_id));
        for (char *p = m->db_id; *p; p++) *p = (char)g_ascii_tolower(*p);
        m->generation = (uint64_t)gen;
        g_strlcpy(m->previous_commit, j_previous_commit->valuestring, sizeof(m->previous_commit));
        g_strlcpy(m->commit, j_commit->valuestring, sizeof(m->commit));
        for (char *p = m->previous_commit; *p; p++) *p = (char)g_ascii_tolower(*p);
        for (char *p = m->commit; *p; p++) *p = (char)g_ascii_tolower(*p);
        if (j_commit_alg) {
            if (!cJSON_IsString(j_commit_alg) || !j_commit_alg->valuestring ||
                (strcmp(j_commit_alg->valuestring, DB_COMMIT_ALG_V1) != 0 &&
                 strcmp(j_commit_alg->valuestring, DB_COMMIT_ALG_V2) != 0)) {
                snprintf(err_msg, err_msg_sz, "Unsupported database commit algorithm");
                goto cleanup;
            }
            m->commit_version = strcmp(j_commit_alg->valuestring, DB_COMMIT_ALG_V2) == 0 ? 2 : 1;
        } else {
            m->commit_version = 1;
        }
        m->has_commit_chain = TRUE;
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
    m->salt = sodium_malloc(slen);
    if (!m->salt) {
        sodium_memzero(salt, slen); free(salt);
        sec_free(secure_noise, nlen);
        snprintf(err_msg, err_msg_sz, "Cannot allocate protected memory for database salt");
        goto cleanup;
    }
    memcpy(m->salt, salt, slen);
    sodium_memzero(salt, slen); free(salt);
    m->salt_len = slen;
    m->noise_key = secure_noise; m->noise_key_len = nlen;

    stego_secret_set(m, m->noise_key, m->noise_key_len);

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

    cJSON *j_padding = cJSON_GetObjectItemCaseSensitive(root, "_padding");
    if (j_padding) {
        if (!cJSON_IsString(j_padding) || !j_padding->valuestring ||
            strlen(j_padding->valuestring) > DB_MAX_JSON_BYTES) {
            snprintf(err_msg, err_msg_sz, "Invalid database padding");
            goto cleanup;
        }
        for (const unsigned char *p = (const unsigned char *)j_padding->valuestring; *p; p++) {
            if (!strchr(ALPHABET, (int)*p)) {
                snprintf(err_msg, err_msg_sz, "Invalid database padding alphabet");
                goto cleanup;
            }
        }
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
    int entry_i = 0;
    cJSON *je = NULL;
    cJSON_ArrayForEach(je, j_entries) {
        int i = entry_i++;


        if (i >= m->entry_cap) {
            snprintf(err_msg, err_msg_sz, "Entry count mismatch (cJSON inconsistency)");
            goto cleanup;
        }
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

        if (!db_index_shape_valid(db_json_string(je, "files"))) {
            snprintf(err_msg, err_msg_sz, "Entry %d file index is malformed or exceeds safety limits", i + 1);
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
        db_entry_refresh_index_stats(e);

        if (!db_label_matches_fields_compatible(m, e->label, e->type, e->size,
                e->content_tag, e->cipher, e->dsalt)) {
            snprintf(err_msg, err_msg_sz, "Entry %d label does not match its authenticated fields", i + 1);
            goto cleanup;
        }
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
        int filter_i = 0;
        cJSON *jf = NULL;
        cJSON_ArrayForEach(jf, j_filters) {
            int i = filter_i++;
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

    cJSON *j_history = cJSON_GetObjectItemCaseSensitive(root, "history");
    if (j_history) {
        if (!cJSON_IsArray(j_history)) {
            snprintf(err_msg, err_msg_sz, "History must be an array");
            goto cleanup;
        }
        int nh = cJSON_GetArraySize(j_history);
        if (nh < 0 || nh > DB_MAX_HISTORY) {
            snprintf(err_msg, err_msg_sz, "Database history exceeds configured limit");
            goto cleanup;
        }
        m->history_cap = nh > 0 ? nh : 16;
        m->history = calloc((size_t)m->history_cap, sizeof(*m->history));
        if (!m->history) {
            snprintf(err_msg, err_msg_sz, "Out of memory while loading database history");
            goto cleanup;
        }
        int hi = 0;
        cJSON *jh = NULL;
        cJSON_ArrayForEach(jh, j_history) {
            cJSON *jt = cJSON_GetObjectItemCaseSensitive(jh, "time");
            cJSON *jg = cJSON_GetObjectItemCaseSensitive(jh, "generation");
            cJSON *ja = cJSON_GetObjectItemCaseSensitive(jh, "action");
            cJSON *jtarget = cJSON_GetObjectItemCaseSensitive(jh, "target");
            if (!cJSON_IsObject(jh) || !jt || !cJSON_IsNumber(jt) || !isfinite(jt->valuedouble) ||
                jt->valuedouble < 0 || jt->valuedouble >= (double)LLONG_MAX ||
                !jg || !cJSON_IsString(jg) || !jg->valuestring ||
                !ja || !cJSON_IsString(ja) || !db_history_action_valid(ja->valuestring) ||
                (jtarget && (!cJSON_IsString(jtarget) || !jtarget->valuestring ||
                 strlen(jtarget->valuestring) > DB_HISTORY_TARGET_MAX ||
                 !g_utf8_validate(jtarget->valuestring, -1, NULL)))) {
                snprintf(err_msg, err_msg_sz, "Database history entry %d is malformed", hi + 1);
                goto cleanup;
            }
            errno = 0;
            char *endg = NULL;
            unsigned long long gen = strtoull(jg->valuestring, &endg, 10);
            if (errno || !endg || *endg || gen == 0 || !db_generation_valid(jg->valuestring)) {
                snprintf(err_msg, err_msg_sz, "Database history generation is invalid");
                goto cleanup;
            }
            db_history_event_t *ev = &m->history[hi];
            ev->timestamp = (long long)jt->valuedouble;
            ev->generation = (uint64_t)gen;
            ev->action = xstrdup(ja->valuestring);
            ev->target = xstrdup(jtarget && jtarget->valuestring ? jtarget->valuestring : "");
            if (!ev->action || !ev->target) {
                db_history_event_clear(ev);
                snprintf(err_msg, err_msg_sz, "Out of memory while loading database history");
                goto cleanup;
            }
            m->history_count = ++hi;
        }
    }

    if (m->has_commit_chain) {
        char expected[DB_COMMIT_HEX_LEN + 1];
        if (!db_compute_commit_hex(m, m->db_id, m->generation, m->previous_commit, expected) ||
            g_ascii_strcasecmp(expected, m->commit) != 0) {
            sodium_memzero(expected, sizeof(expected));
            snprintf(err_msg, err_msg_sz, "Database commit chain verification failed");
            goto cleanup;
        }
        sodium_memzero(expected, sizeof(expected));
    }
    int rollback_rc = db_check_rollback_state(m, err_msg, err_msg_sz);
    if (rollback_rc < 0) goto cleanup;
    m->rollback_state_verified = m->has_commit_chain && rollback_rc > 0;

    rc = 0;
cleanup:
    if (root) {
        db_json_zero_strings(root);
        cJSON_Delete(root);
    }
    return rc;
}

static int db_validate_loaded_integrity(db_manager_t *m, char *err_msg, size_t err_msg_sz) {
    if (!m || !m->file_path || !m->recipient || !m->salt || m->salt_len != 32 ||
        !m->noise_key || m->noise_key_len != 32) {
        snprintf(err_msg, err_msg_sz, "Database state is incomplete");
        return -1;
    }
    if (!m->is_signed) {
        snprintf(err_msg, err_msg_sz, "Database signature is not verified");
        return -1;
    }
    if (m->require_pqc && !m->is_pqc_encrypted) {
        snprintf(err_msg, err_msg_sz, "Database security policy requires PQC encryption");
        return -1;
    }
    gboolean seen_schema[SCHEMA_COUNT] = { FALSE, FALSE, FALSE, FALSE, FALSE };
    for (int i = 0; i < SCHEMA_COUNT; i++) {
        int idx = -1;
        for (int j = 0; j < SCHEMA_COUNT; j++)
            if (m->schema_order[i] && strcmp(m->schema_order[i], SCHEMA_PARTS[j]) == 0) { idx = j; break; }
        if (idx < 0 || seen_schema[idx]) {
            snprintf(err_msg, err_msg_sz, "Database schema is invalid");
            return -1;
        }
        seen_schema[idx] = TRUE;
    }
    if (m->entry_count < 0 || m->entry_count > DB_MAX_ENTRIES ||
        m->filter_count < 0 || m->filter_count > DB_MAX_FILTERS ||
        m->history_count < 0 || m->history_count > DB_MAX_HISTORY) {
        snprintf(err_msg, err_msg_sz, "Database object count is outside configured limits");
        return -1;
    }
    GHashTable *labels = g_hash_table_new(g_str_hash, g_str_equal);
    if (!labels) {
        snprintf(err_msg, err_msg_sz, "Cannot allocate integrity-check state");
        return -1;
    }
    for (int i = 0; i < m->entry_count; i++) {
        db_entry_t *e = &m->entries[i];
        if (!e->label || g_hash_table_contains(labels, e->label)) {
            g_hash_table_destroy(labels);
            snprintf(err_msg, err_msg_sz, "Duplicate or missing entry label detected");
            return -1;
        }
        g_hash_table_add(labels, e->label);
        if (!db_label_matches_fields_compatible(m, e->label, e->type, e->size,
                e->content_tag, e->cipher, e->dsalt)) {
            g_hash_table_destroy(labels);
            snprintf(err_msg, err_msg_sz, "Entry %d label does not match authenticated fields", i + 1);
            return -1;
        }
    }
    g_hash_table_destroy(labels);
    for (int i = 0; i < m->filter_count; i++) {
        if (!m->filters[i].name || !m->filters[i].exts ||
            strlen(m->filters[i].name) > 256 || strlen(m->filters[i].exts) > 4096) {
            snprintf(err_msg, err_msg_sz, "Saved filter %d is invalid", i + 1);
            return -1;
        }
    }
    uint64_t last_hist_gen = 0;
    for (int i = 0; i < m->history_count; i++) {
        db_history_event_t *ev = &m->history[i];
        if (ev->timestamp < 0 || ev->generation == 0 || !db_history_action_valid(ev->action) ||
            !ev->target || strlen(ev->target) > DB_HISTORY_TARGET_MAX ||
            !g_utf8_validate(ev->target, -1, NULL) ||
            (last_hist_gen && ev->generation < last_hist_gen) ||
            (m->has_commit_chain && ev->generation > m->generation)) {
            snprintf(err_msg, err_msg_sz, "Database history entry %d is invalid", i + 1);
            return -1;
        }
        last_hist_gen = ev->generation;
    }
    if (m->has_commit_chain) {
        char expected[DB_COMMIT_HEX_LEN + 1];
        gboolean ok = db_compute_commit_hex(m, m->db_id, m->generation, m->previous_commit, expected) &&
            g_ascii_strcasecmp(expected, m->commit) == 0;
        sodium_memzero(expected, sizeof(expected));
        if (!ok) {
            snprintf(err_msg, err_msg_sz, "Database commit chain verification failed");
            return -1;
        }
    }
    return 0;
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

static int db_build_opaque_container(db_manager_t *m, const char *json, size_t json_len,
    gboolean compact, unsigned char **out_blob, size_t *out_blob_len,
    char *err_msg, size_t err_msg_sz)
{
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    char key_hex[crypto_aead_xchacha20poly1305_ietf_KEYBYTES * 2 + 1];
    char nonce_hex[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES * 2 + 1];
    unsigned char *env_cipher = NULL, *plain = NULL, *blob = NULL;
    size_t env_len = 0, bucket = 0, total = 0;
    size_t envelope_slot = compact ? DB_OPAQUE_COMPACT_ENVELOPE_SLOT : DB_OPAQUE_ENVELOPE_SLOT;
    unsigned long long payload_len = 0;
    int rc = -1;

    if (!m || !json || !json_len || !out_blob || !out_blob_len || json_len > DB_MAX_JSON_BYTES) {
        snprintf(err_msg, err_msg_sz, "Invalid opaque-container input");
        return -1;
    }
    *out_blob = NULL; *out_blob_len = 0;

    if (json_len > SIZE_MAX - 8U) {
        snprintf(err_msg, err_msg_sz, "Database is too large for opaque padding");
        return -1;
    }
    bucket = db_opaque_bucket_size(json_len + 8U, compact);
    if (!bucket || bucket > DB_MAX_FILE_BYTES) {
        snprintf(err_msg, err_msg_sz, "Database is too large for configured privacy buckets");
        return -1;
    }

    randombytes_buf(key, sizeof(key));
    randombytes_buf(nonce, sizeof(nonce));
    sodium_bin2hex(key_hex, sizeof(key_hex), key, sizeof(key));
    sodium_bin2hex(nonce_hex, sizeof(nonce_hex), nonce, sizeof(nonce));

    char envelope[256];
    int en = snprintf(envelope, sizeof(envelope),
        DB_OPAQUE_ENV_TAG "\nK=%s\nN=%s\nP=%s\n", key_hex, nonce_hex, DB_SECURITY_PQC);
    if (en <= 0 || (size_t)en >= sizeof(envelope)) {
        snprintf(err_msg, err_msg_sz, "Cannot construct opaque key envelope");
        goto cleanup;
    }
    env_cipher = db_gpg_encrypt_binary_pqc(m, envelope, (size_t)en, TRUE, &env_len,
        err_msg, err_msg_sz);
    sodium_memzero(envelope, sizeof(envelope));
    if (!env_cipher) goto cleanup;
    if (env_len < DB_OPAQUE_MIN_ENVELOPE || env_len > envelope_slot || env_len > UINT16_MAX) {
        snprintf(err_msg, err_msg_sz, compact
            ? "Encrypted key envelope does not fit the compact steganographic slot"
            : "Encrypted key envelope does not fit the fixed privacy slot");
        goto cleanup;
    }

    plain = sodium_malloc(bucket);
    if (!plain) { snprintf(err_msg, err_msg_sz, "Cannot allocate protected opaque payload"); goto cleanup; }
    db_store_u64le(plain, (uint64_t)json_len);
    memcpy(plain + 8, json, json_len);

    if (bucket > json_len + 8) memset(plain + 8 + json_len, 0, bucket - json_len - 8);

    if (bucket > SIZE_MAX - crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        snprintf(err_msg, err_msg_sz, "Opaque payload length overflow"); goto cleanup;
    }
    size_t payload_cap = bucket + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (DB_OPAQUE_HEADER_BYTES + envelope_slot > SIZE_MAX - payload_cap) {
        snprintf(err_msg, err_msg_sz, "Opaque container length overflow"); goto cleanup;
    }
    total = DB_OPAQUE_HEADER_BYTES + envelope_slot + payload_cap;
    if (total > DB_MAX_FILE_BYTES) {
        snprintf(err_msg, err_msg_sz, "Opaque database exceeds file size limit"); goto cleanup;
    }
    blob = malloc(total);
    if (!blob) { snprintf(err_msg, err_msg_sz, "Cannot allocate opaque database container"); goto cleanup; }

    unsigned char *slot = blob + DB_OPAQUE_HEADER_BYTES;
    randombytes_buf(slot, envelope_slot);
    size_t room = envelope_slot - env_len;
    uint16_t env_off = (uint16_t)(room ? randombytes_uniform((uint32_t)room + 1U) : 0U);
    uint16_t off_field = (uint16_t)(env_off | (compact ? DB_OPAQUE_COMPACT_FLAG : 0U));
    db_store_u16le(blob, off_field);
    db_store_u16le(blob + 2, (uint16_t)env_len);
    memcpy(slot + env_off, env_cipher, env_len);


    unsigned char aad_buf[64];
    size_t aad_len = 0;
    memcpy(aad_buf, DB_OPAQUE_AAD, strlen(DB_OPAQUE_AAD));
    aad_len = strlen(DB_OPAQUE_AAD);
    memcpy(aad_buf + aad_len, blob, DB_OPAQUE_HEADER_BYTES);
    aad_len += DB_OPAQUE_HEADER_BYTES;

    unsigned char *payload_dst = slot + envelope_slot;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(payload_dst, &payload_len,
            plain, (unsigned long long)bucket,
            aad_buf, aad_len,
            NULL, nonce, key) != 0 || payload_len != payload_cap) {
        snprintf(err_msg, err_msg_sz, "Cannot encrypt opaque database payload"); goto cleanup;
    }
    sodium_memzero(aad_buf, sizeof(aad_buf));

    *out_blob = blob; blob = NULL;
    *out_blob_len = total;
    rc = 0;
cleanup:
    sodium_memzero(key, sizeof(key)); sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(key_hex, sizeof(key_hex)); sodium_memzero(nonce_hex, sizeof(nonce_hex));
    if (env_cipher) { sodium_memzero(env_cipher, env_len); free(env_cipher); }
    if (plain) sec_free(plain, bucket);
    if (blob) { sodium_memzero(blob, total); free(blob); }
    return rc;
}

static int db_open_opaque_container(db_manager_t *m, const unsigned char *raw, size_t raw_len,
    char **out_json, char *err_msg, size_t err_msg_sz)
{
    if (!m || !raw || !out_json) return -1;
    *out_json = NULL;
    if (raw_len < DB_OPAQUE_HEADER_BYTES) return 0;
    gboolean compact = FALSE;
    size_t envelope_slot = 0;
    uint16_t env_off = 0, env_len = 0;
    if (!db_opaque_header_layout(raw, &compact, &envelope_slot, &env_off, &env_len)) return 0;
    const size_t fixed = DB_OPAQUE_HEADER_BYTES + envelope_slot;
    if (raw_len <= fixed + crypto_aead_xchacha20poly1305_ietf_ABYTES) return 0;

    size_t payload_cipher_len = raw_len - fixed;
    if (payload_cipher_len <= crypto_aead_xchacha20poly1305_ietf_ABYTES) return 0;
    size_t padded_len = payload_cipher_len - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (!db_opaque_payload_size_valid(padded_len, compact)) return 0;
    if (!m->recipient || !m->recipient[0]) {
        snprintf(err_msg, err_msg_sz,
            "Opaque .dpdb containers hide recipient metadata; select the OpenPGP key explicitly");
        return -1;
    }

    const unsigned char *slot = raw + DB_OPAQUE_HEADER_BYTES;
    char *envelope = db_gpg_decrypt(m, (const char *)(slot + env_off), env_len, err_msg, err_msg_sz);
    if (!envelope) return -1;
    if (!m->is_pqc_encrypted) {
        sec_strfree(envelope);
        snprintf(err_msg, err_msg_sz, "Opaque container requires ML-KEM/Kyber encryption");
        return -1;
    }

    char key_hex[crypto_aead_xchacha20poly1305_ietf_KEYBYTES * 2 + 1] = {0};
    char nonce_hex[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES * 2 + 1] = {0};
    char policy[32] = {0};
    int fields = sscanf(envelope,
        DB_OPAQUE_ENV_TAG "\nK=%64[0-9A-Fa-f]\nN=%48[0-9A-Fa-f]\nP=%31[^\n]\n",
        key_hex, nonce_hex, policy);
    sec_strfree(envelope);
    if (fields != 3 || strcmp(policy, DB_SECURITY_PQC) != 0) {
        sodium_memzero(key_hex, sizeof(key_hex)); sodium_memzero(nonce_hex, sizeof(nonce_hex));
        sodium_memzero(policy, sizeof(policy));
        snprintf(err_msg, err_msg_sz, "Invalid signed opaque key envelope");
        return -1;
    }

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    size_t key_len = 0, nonce_len = 0;
    if (sodium_hex2bin(key, sizeof(key), key_hex, strlen(key_hex), NULL, &key_len, NULL) != 0 ||
        key_len != sizeof(key) ||
        sodium_hex2bin(nonce, sizeof(nonce), nonce_hex, strlen(nonce_hex), NULL, &nonce_len, NULL) != 0 ||
        nonce_len != sizeof(nonce)) {
        sodium_memzero(key, sizeof(key)); sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(key_hex, sizeof(key_hex)); sodium_memzero(nonce_hex, sizeof(nonce_hex));
        sodium_memzero(policy, sizeof(policy));
        snprintf(err_msg, err_msg_sz, "Invalid opaque envelope key material");
        return -1;
    }
    sodium_memzero(key_hex, sizeof(key_hex)); sodium_memzero(nonce_hex, sizeof(nonce_hex));
    sodium_memzero(policy, sizeof(policy));

    unsigned char *plain = sodium_malloc(padded_len);
    if (!plain) {
        sodium_memzero(key, sizeof(key)); sodium_memzero(nonce, sizeof(nonce));
        snprintf(err_msg, err_msg_sz, "Cannot allocate protected opaque plaintext"); return -1;
    }


    unsigned char aad_buf[64];
    size_t aad_len = 0;
    memcpy(aad_buf, DB_OPAQUE_AAD, strlen(DB_OPAQUE_AAD));
    aad_len = strlen(DB_OPAQUE_AAD);
    memcpy(aad_buf + aad_len, raw, DB_OPAQUE_HEADER_BYTES);
    aad_len += DB_OPAQUE_HEADER_BYTES;

    unsigned long long plain_len = 0;
    const unsigned char *payload = raw + fixed;
    gboolean decrypt_ok = FALSE;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain, &plain_len, NULL,
            payload, (unsigned long long)payload_cipher_len,
            aad_buf, aad_len,
            nonce, key) == 0 && plain_len == padded_len) {
        decrypt_ok = TRUE;
    } else {


        plain_len = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain, &plain_len, NULL,
                payload, (unsigned long long)payload_cipher_len,
                (const unsigned char *)DB_OPAQUE_AAD, strlen(DB_OPAQUE_AAD),
                nonce, key) == 0 && plain_len == padded_len) {
            decrypt_ok = TRUE;
        }
    }
    sodium_memzero(aad_buf, sizeof(aad_buf));
    if (!decrypt_ok) {
        sodium_memzero(key, sizeof(key)); sodium_memzero(nonce, sizeof(nonce));
        sec_free(plain, padded_len);
        snprintf(err_msg, err_msg_sz, "Opaque database payload authentication failed");
        return -1;
    }
    sodium_memzero(key, sizeof(key)); sodium_memzero(nonce, sizeof(nonce));

    if (padded_len < 8) { sec_free(plain, padded_len); return -1; }
    uint64_t json_len64 = db_load_u64le(plain);
    if (json_len64 == 0 || json_len64 > DB_MAX_JSON_BYTES || json_len64 > padded_len - 8) {
        sec_free(plain, padded_len);
        snprintf(err_msg, err_msg_sz, "Opaque database contains an invalid logical length"); return -1;
    }
    size_t json_len = (size_t)json_len64;
    if (memchr(plain + 8, '\0', json_len) != NULL) {
        sec_free(plain, padded_len);
        snprintf(err_msg, err_msg_sz, "Opaque database JSON contains an embedded NUL byte"); return -1;
    }
    char *json = sodium_malloc(json_len + 1);
    if (!json) { sec_free(plain, padded_len); snprintf(err_msg, err_msg_sz, "Cannot allocate protected JSON"); return -1; }
    memcpy(json, plain + 8, json_len); json[json_len] = '\0';
    sec_free(plain, padded_len);
    *out_json = json;
    return 1;
}

static int db_save(db_manager_t *m, char *err_msg, size_t err_msg_sz) {
    if (m && m->legacy_read_only) {
        snprintf(err_msg, err_msg_sz, "%s", i18n("legacy_read_only"));
        return -1;
    }
    cJSON *root = NULL, *j_schema = NULL, *j_entries = NULL, *j_filters = NULL, *j_history = NULL;
    char *json_str = NULL, *enc = NULL, *tmp_path = NULL;
    unsigned char *opaque_blob = NULL;
    size_t json_len = 0, opaque_len = 0;
    int fd = -1;
    gboolean write_ok = FALSE;
    int lock_fd = -1;
    char *rollback_path = NULL;
    gboolean keep_rollback = FALSE;
    int rc = -1;
    gboolean save_with_pqc = FALSE;
    gboolean original_require_pqc = m ? m->require_pqc : FALSE;
    gboolean external_commit = g_db_external_commit_hook != NULL;
    gboolean backup_enabled = g_strcmp0(g_getenv("DISKPASS_BACKUP"), "0") != 0 && !external_commit;

    char candidate_db_id[DB_ID_HEX_LEN + 1] = {0};
    char candidate_previous[DB_COMMIT_HEX_LEN + 1] = {0};
    char candidate_commit[DB_COMMIT_HEX_LEN + 1] = {0};
    uint64_t candidate_generation = 0;

    if (!m || !m->file_path || !m->recipient || !m->salt || m->salt_len != 32 ||
        !m->noise_key || m->noise_key_len != 32) {
        snprintf(err_msg, err_msg_sz, "Database state is incomplete");
        return -1;
    }
    save_with_pqc = db_recipient_has_pqc(m);
    if (!save_with_pqc && m->require_pqc) {
        snprintf(err_msg, err_msg_sz,
            "PQC encryption is required for this database but the selected key has no valid ML-KEM/Kyber encryption subkey. "
            "Refusing security downgrade. To migrate, create a new database with a PQC-capable key and import entries manually.");
        return -1;
    }
    if (m->entry_count < 0 || m->entry_count > DB_MAX_ENTRIES ||
        m->filter_count < 0 || m->filter_count > DB_MAX_FILTERS ||
        m->history_count < 0 || m->history_count > DB_MAX_HISTORY + 1 ||
        (m->entry_count > 0 && !m->entries) ||
        (m->filter_count > 0 && !m->filters) ||
        (m->history_count > 0 && !m->history)) {
        snprintf(err_msg, err_msg_sz, "Database exceeds configured resource limits or has inconsistent state");
        return -1;
    }
    if (!db_path_has_dpdb_extension(m->file_path)) {
        snprintf(err_msg, err_msg_sz, "DiskPass database files must use the .dpdb extension");
        return -1;
    }
    if (!db_parent_directory_is_safe(m->file_path, err_msg, err_msg_sz))
        return -1;

    if (!i18n_language_code_valid(m->lang)) {
        snprintf(err_msg, err_msg_sz, "Invalid database language setting");
        return -1;
    }

    if (m->has_commit_chain) {
        if (!db_hex_string_valid(m->db_id, DB_ID_HEX_LEN) ||
            !db_hex_string_valid(m->commit, DB_COMMIT_HEX_LEN) ||
            m->generation == UINT64_MAX) {
            snprintf(err_msg, err_msg_sz, "Database commit-chain state is invalid");
            return -1;
        }
        g_strlcpy(candidate_db_id, m->db_id, sizeof(candidate_db_id));
        g_strlcpy(candidate_previous, m->commit, sizeof(candidate_previous));
        candidate_generation = m->generation + 1;
    } else {
        db_random_id(candidate_db_id);
        memset(candidate_previous, '0', DB_COMMIT_HEX_LEN);
        candidate_previous[DB_COMMIT_HEX_LEN] = '\0';
        candidate_generation = 1;
    }
    m->require_pqc = original_require_pqc || save_with_pqc;
    if (!db_compute_commit_hex_version(m, candidate_db_id, candidate_generation,
            candidate_previous, 2, candidate_commit)) {
        m->require_pqc = original_require_pqc;
        snprintf(err_msg, err_msg_sz, "Cannot compute database commit chain");
        return -1;
    }

    lock_fd = db_save_lock(m->file_path, err_msg, err_msg_sz);
    if (lock_fd < 0 || db_snapshot_check(m->file_path, &m->file_snapshot, err_msg, err_msg_sz) != 0)
        goto cleanup;

    root = cJSON_CreateObject();
    j_schema = cJSON_CreateArray();
    j_entries = cJSON_CreateArray();
    j_filters = cJSON_CreateArray();
    j_history = cJSON_CreateArray();
    if (!root || !j_schema || !j_entries || !j_filters || !j_history) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed");
        goto cleanup;
    }
    if (!db_json_add_number(root, "version", DB_VERSION)) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed for database version");
        goto cleanup;
    }
    char generation_buf[32];
    snprintf(generation_buf, sizeof(generation_buf), "%" PRIu64, candidate_generation);
    if (!db_json_add_string(root, "db_id", candidate_db_id) ||
        !db_json_add_string(root, "generation", generation_buf) ||
        !db_json_add_string(root, "previous_commit", candidate_previous) ||
        !db_json_add_string(root, "commit", candidate_commit) ||
        !db_json_add_string(root, "commit_alg", DB_COMMIT_ALG_V2)) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed for commit-chain metadata");
        goto cleanup;
    }
    if (!db_json_add_string(root, "security_min",
            m->require_pqc ? DB_SECURITY_PQC : DB_SECURITY_CLASSIC)) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed for security policy");
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
            (e->files && !db_index_shape_valid(e->files)) ||
            (e->smart && strlen(e->smart) > 2 * 1024 * 1024) ||
            (e->uuid && strlen(e->uuid) > 256)) {
            snprintf(err_msg, err_msg_sz, "Entry %d exceeds a field safety limit", i + 1);
            goto cleanup;
        }
        if (!db_label_matches_fields_compatible(m, e->label, e->type, e->size,
                e->content_tag, e->cipher, e->dsalt)) {
            snprintf(err_msg, err_msg_sz, "Entry %d label does not match its fields", i + 1);
            goto cleanup;
        }
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

    int history_start = m->history_count > DB_MAX_HISTORY ? m->history_count - DB_MAX_HISTORY : 0;
    for (int i = history_start; i < m->history_count; i++) {
        const db_history_event_t *ev = &m->history[i];
        if (ev->timestamp < 0 || ev->generation == 0 || !db_history_action_valid(ev->action) ||
            !ev->target || strlen(ev->target) > DB_HISTORY_TARGET_MAX ||
            !g_utf8_validate(ev->target, -1, NULL)) {
            snprintf(err_msg, err_msg_sz, "Database history contains an invalid event");
            goto cleanup;
        }
        cJSON *jh = cJSON_CreateObject();
        char hist_gen[32];
        snprintf(hist_gen, sizeof(hist_gen), "%" PRIu64, ev->generation);
        if (!jh || !db_json_add_number(jh, "time", (double)ev->timestamp) ||
            !db_json_add_string(jh, "generation", hist_gen) ||
            !db_json_add_string(jh, "action", ev->action) ||
            !db_json_add_string(jh, "target", ev->target)) {
            if (jh) cJSON_Delete(jh);
            snprintf(err_msg, err_msg_sz, "JSON allocation failed for database history");
            goto cleanup;
        }
        if (!cJSON_AddItemToArray(j_history, jh)) {
            cJSON_Delete(jh);
            snprintf(err_msg, err_msg_sz, "JSON allocation failed for database history");
            goto cleanup;
        }
    }
    if (!cJSON_AddItemToObject(root, "history", j_history)) {
        snprintf(err_msg, err_msg_sz, "JSON allocation failed for history array");
        goto cleanup;
    }
    j_history = NULL;

    json_str = cJSON_PrintUnformatted(root);
    if (!json_str) { snprintf(err_msg, err_msg_sz, "JSON print failed"); goto cleanup; }
    json_len = strlen(json_str);
    if (json_len > DB_MAX_JSON_BYTES) {
        snprintf(err_msg, err_msg_sz, "Database JSON exceeds size limit");
        goto cleanup;
    }
    if (!save_with_pqc && g_strcmp0(g_getenv("DISKPASS_DISABLE_PADDING"), "1") != 0) {
        size_t quantum = json_len <= 16 * 1024 ? 4 * 1024 :
                         json_len <= 1024 * 1024 ? 64 * 1024 :
                         json_len <= 16 * 1024 * 1024 ? 1024 * 1024 :
                         8 * 1024 * 1024;
        size_t target = ((json_len + quantum - 1) / quantum) * quantum;
        const size_t overhead = sizeof(",\"_padding\":\"\"") - 1;
        if (target <= json_len + overhead) target += quantum;
        if (target <= DB_MAX_JSON_BYTES && target > json_len + overhead) {
            size_t pad_len = target - json_len - overhead;
            char *padding = secure_json_malloc(pad_len + 1);
            if (!padding) { snprintf(err_msg, err_msg_sz, "Padding allocation failed"); goto cleanup; }
            for (size_t i = 0; i < pad_len; i++) padding[i] = ALPHABET[randombytes_uniform((uint32_t)ALPHABET_LEN)];
            padding[pad_len] = '\0';
            if (!db_json_add_string(root, "_padding", padding)) {
                secure_json_free(padding);
                snprintf(err_msg, err_msg_sz, "JSON allocation failed for database padding");
                goto cleanup;
            }
            secure_json_free(padding);
            sodium_memzero(json_str, json_len);
            secure_json_free(json_str);
            json_str = cJSON_PrintUnformatted(root);
            if (!json_str) { snprintf(err_msg, err_msg_sz, "JSON print failed after padding"); goto cleanup; }
            json_len = strlen(json_str);
            if (json_len > DB_MAX_JSON_BYTES) {
                snprintf(err_msg, err_msg_sz, "Padded database JSON exceeds size limit");
                goto cleanup;
            }
        }
    }
    db_json_zero_strings(root);
    cJSON_Delete(root); root = NULL;

    if (save_with_pqc) {
        if (db_build_opaque_container(m, json_str, json_len, external_commit,
                &opaque_blob, &opaque_len, err_msg, err_msg_sz) != 0)
            goto cleanup;
    } else {
        enc = db_gpg_encrypt_legacy(m, json_str, json_len, err_msg, err_msg_sz);
        if (!enc) goto cleanup;
    }
    sodium_memzero(json_str, json_len);
    secure_json_free(json_str); json_str = NULL;

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

    if (save_with_pqc) {
        if (!opaque_blob || opaque_len == 0 || write_all_fd(fd, opaque_blob, opaque_len) != 0 || fsync(fd) != 0) {
            snprintf(err_msg, err_msg_sz, "Cannot write opaque database safely: %s", strerror(errno));
            goto cleanup;
        }
    } else {
        size_t enc_len = strlen(enc);
        const char *container_magic = DB_CONTAINER_MAGIC "\n";
        if (write_all_fd(fd, container_magic, strlen(container_magic)) != 0 ||
            write_all_fd(fd, enc, enc_len) != 0 || fsync(fd) != 0) {
            snprintf(err_msg, err_msg_sz, "Cannot write legacy database safely: %s", strerror(errno));
            goto cleanup;
        }
    }
    if (close(fd) != 0) {
        fd = -1;
        snprintf(err_msg, err_msg_sz, "Cannot close temporary database: %s", strerror(errno));
        goto cleanup;
    }
    fd = -1;
    if (backup_enabled) {
        if (db_backup_existing_file(m->file_path, candidate_db_id, err_msg, err_msg_sz) != 0)
            goto cleanup;
    }
    if (db_snapshot_check(m->file_path, &m->file_snapshot, err_msg, err_msg_sz) != 0)
        goto cleanup;
    if (external_commit) {


        if (!m->file_snapshot.exists) {
            snprintf(err_msg, err_msg_sz, "Mounted database has no rollback source");
            goto cleanup;
        }
        rollback_path = g_strconcat(m->file_path, ".rollback.XXXXXX", NULL);
        int rfd = rollback_path ? g_mkstemp_full(rollback_path, O_RDWR | O_CLOEXEC, 0600) : -1;
        if (rfd < 0) {
            snprintf(err_msg, err_msg_sz, "Cannot reserve mounted database rollback path");
            goto cleanup;
        }
        close(rfd);


        if (!db_write_backup_pointer(m->db_id, rollback_path)) {
            snprintf(err_msg, err_msg_sz, "Cannot record rollback pointer for crash recovery");
            unlink(rollback_path);
            goto cleanup;
        }
        if (rename(m->file_path, rollback_path) != 0) {
            snprintf(err_msg, err_msg_sz, "Cannot preserve mounted database for rollback: %s", strerror(errno));
            db_remove_recorded_backup(m->db_id, m->file_path);
            goto cleanup;
        }
        keep_rollback = TRUE;
    }
    if (rename(tmp_path, m->file_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot atomically replace database: %s", strerror(errno));
        goto cleanup;
    }
    write_ok = TRUE;

    if (!backup_enabled && !external_commit) {
        db_remove_recorded_backup(candidate_db_id, m->file_path);
        size_t bak_len = strlen(m->file_path) + sizeof(".bak");
        char *bak_path = malloc(bak_len);
        if (bak_path) {
            snprintf(bak_path, bak_len, "%s.bak", m->file_path);
            if (unlink(bak_path) != 0 && errno != ENOENT)
                fprintf(stderr, "DiskPass: warning: cannot remove disabled legacy backup %s: %s\n",
                    bak_path, strerror(errno));
            free(bak_path);
        }
    }

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

    if (g_db_external_commit_hook &&
        g_db_external_commit_hook(m->file_path, err_msg, err_msg_sz) != 0) {
        goto cleanup;
    }

    keep_rollback = FALSE;


    db_remove_recorded_backup(candidate_db_id, m->file_path);

    char snapshot_err[256];
    if (db_file_snapshot(m->file_path, &m->file_snapshot, snapshot_err, sizeof(snapshot_err)) != 0)
        fprintf(stderr, "DiskPass: warning: saved snapshot unavailable; reopen before saving again\n");
    m->is_pqc_encrypted = save_with_pqc;
    g_strlcpy(m->db_id, candidate_db_id, sizeof(m->db_id));
    m->generation = candidate_generation;
    g_strlcpy(m->previous_commit, candidate_previous, sizeof(m->previous_commit));
    g_strlcpy(m->commit, candidate_commit, sizeof(m->commit));
    m->commit_version = 2;
    m->has_commit_chain = TRUE;
    db_history_trim(m);
    if (!db_write_rollback_state(m)) {
        fprintf(stderr, "DiskPass: warning: database saved but local rollback state could not be updated\n");
        m->rollback_state_verified = FALSE;
    } else {
        m->rollback_state_verified = TRUE;
    }
    rc = 0;
cleanup:
    if (rc != 0) m->require_pqc = original_require_pqc;
    if (keep_rollback) {
        if (rename(rollback_path, m->file_path) == 0) {
            keep_rollback = FALSE;

            db_remove_recorded_backup(m->db_id, m->file_path);
            carrier_fsync_parent(m->file_path);
            char snapshot_err[256];
            (void)db_file_snapshot(m->file_path, &m->file_snapshot, snapshot_err, sizeof(snapshot_err));
        } else {
            m->file_snapshot.valid = FALSE;


            snprintf(err_msg, err_msg_sz,
                "Mounted save and rollback failed; stop and recover encrypted database from %s", rollback_path);
        }
    }
    if (rollback_path && !keep_rollback) unlink(rollback_path);
    g_free(rollback_path);
    if (lock_fd >= 0) close(lock_fd);
    if (fd >= 0) close(fd);
    if (!write_ok && tmp_path) unlink(tmp_path);
    if (root) { db_json_zero_strings(root); cJSON_Delete(root); }
    if (j_schema) { db_json_zero_strings(j_schema); cJSON_Delete(j_schema); }
    if (j_entries) { db_json_zero_strings(j_entries); cJSON_Delete(j_entries); }
    if (j_filters) { db_json_zero_strings(j_filters); cJSON_Delete(j_filters); }
    if (j_history) { db_json_zero_strings(j_history); cJSON_Delete(j_history); }
    if (json_str) { sodium_memzero(json_str, json_len ? json_len : strlen(json_str)); secure_json_free(json_str); }
    if (enc) { sodium_memzero(enc, strlen(enc)); free(enc); }
    if (opaque_blob) { sodium_memzero(opaque_blob, opaque_len); free(opaque_blob); }
    free(tmp_path);
    sodium_memzero(candidate_commit, sizeof(candidate_commit));
    sodium_memzero(candidate_previous, sizeof(candidate_previous));
    return rc;
}

static db_manager_t *db_manager_open(const char *path, const char *forced_key,
    gboolean defer_chainless_consent, gboolean force_fresh_pinentry,
    char *err_msg, size_t err_msg_sz) {
    if (!path || !path[0]) {
        snprintf(err_msg, err_msg_sz, "Invalid database path");
        return NULL;
    }
    if (!db_path_has_dpdb_extension(path)) {
        snprintf(err_msg, err_msg_sz, "DiskPass database files must use the .dpdb extension");
        return NULL;
    }
    db_manager_t *m = calloc(1, sizeof(db_manager_t));
    if (!m) { snprintf(err_msg, err_msg_sz, "alloc failed"); return NULL; }
    db_manager_init(m);
    m->defer_chainless_consent = defer_chainless_consent;
    m->force_fresh_pinentry = force_fresh_pinentry;
    if (db_init_gpg(m, err_msg, err_msg_sz) != 0) { db_manager_clear(m); free(m); return NULL; }
    m->file_path = xstrdup(path);

    if (db_file_snapshot(path, &m->file_snapshot, err_msg, err_msg_sz) != 0 || !m->file_snapshot.exists) {
        snprintf(err_msg, err_msg_sz, "Cannot snapshot existing database safely");
        db_manager_clear(m); free(m); return NULL;
    }
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    if (db_read_raw_file(path, &raw, &raw_len, err_msg, err_msg_sz) != 0) {
        db_manager_clear(m); free(m); return NULL;
    }
    if (forced_key && forced_key[0]) m->recipient = xstrdup(forced_key);
    char *json_str = NULL;
    int opaque_rc = db_open_opaque_container(m, raw, raw_len, &json_str, err_msg, err_msg_sz);
    sodium_memzero(raw, raw_len); free(raw); raw = NULL;
    if (opaque_rc < 0) {
        db_manager_clear(m); free(m); return NULL;
    }
    if (opaque_rc > 0) {
        int rc = db_load_json(m, json_str, err_msg, err_msg_sz);
        sec_strfree(json_str);
        if (rc != 0 || db_snapshot_check(path, &m->file_snapshot, err_msg, err_msg_sz) != 0) { db_manager_clear(m); free(m); return NULL; }
        return m;
    }

    secure_free_string(&m->recipient);
    char *legacy_recipient = NULL;
    char *enc_data = NULL;
    if (db_read_file(path, &legacy_recipient, &enc_data, err_msg, err_msg_sz) != 0) {
        db_manager_clear(m); free(m); return NULL;
    }
    if (!legacy_recipient) {
        if (!forced_key || !forced_key[0]) {
            snprintf(err_msg, err_msg_sz, "This database hides its outer fingerprint; select the OpenPGP key explicitly");
            free(enc_data); db_manager_clear(m); free(m); return NULL;
        }
        m->recipient = xstrdup(forced_key);
    } else {
        m->recipient = legacy_recipient;
        legacy_recipient = NULL;
        if (forced_key && g_ascii_strcasecmp(forced_key, m->recipient) != 0) {
            snprintf(err_msg, err_msg_sz, "%s", i18n("key_mismatch"));
            free(enc_data); db_manager_clear(m); free(m); return NULL;
        }
    }
    json_str = db_gpg_decrypt(m, enc_data, enc_data ? strlen(enc_data) : 0, err_msg, err_msg_sz);
    if (enc_data) { sodium_memzero(enc_data, strlen(enc_data)); free(enc_data); }
    if (!json_str) { db_manager_clear(m); free(m); return NULL; }
    int rc = db_load_json(m, json_str, err_msg, err_msg_sz);
    sec_strfree(json_str);
    if (rc != 0 || db_snapshot_check(path, &m->file_snapshot, err_msg, err_msg_sz) != 0) { db_manager_clear(m); free(m); return NULL; }
    return m;
}

static db_manager_t *db_manager_create(const char *path, const char *recipient,
    const char *lang, char *err_msg, size_t err_msg_sz) {
    if (!path || !path[0]) {
        snprintf(err_msg, err_msg_sz, "Invalid database path");
        return NULL;
    }
    if (!db_path_has_dpdb_extension(path)) {
        snprintf(err_msg, err_msg_sz, "DiskPass database files must use the .dpdb extension");
        return NULL;
    }
    db_manager_t *m = calloc(1, sizeof(db_manager_t));
    if (!m) { snprintf(err_msg, err_msg_sz, "alloc failed"); return NULL; }
    db_manager_init(m);
    if (db_file_snapshot(path, &m->file_snapshot, err_msg, err_msg_sz) != 0) {
        db_manager_clear(m); free(m); return NULL;
    }
    if (!recipient) { snprintf(err_msg, err_msg_sz, "%s", i18n("no_recipient")); db_manager_clear(m); free(m); return NULL; }
    if (db_init_gpg(m, err_msg, err_msg_sz) != 0) { db_manager_clear(m); free(m); return NULL; }
    m->file_path = xstrdup(path);
    m->recipient = xstrdup(recipient);
    m->require_pqc = TRUE;
    m->salt = sodium_malloc(32); m->noise_key = sodium_malloc(32);
    if (!m->salt || !m->noise_key) { db_manager_clear(m); free(m); return NULL; }
    m->salt_len = 32; m->noise_key_len = 32;
    randombytes_buf(m->salt, 32);
    randombytes_buf(m->noise_key, 32);

    stego_secret_set(m, m->noise_key, m->noise_key_len);
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
    int history_before = 0;
    if (db_history_mark(m, "database_created", "", &history_before, err_msg, err_msg_sz) != 0 ||
        db_save(m, err_msg, err_msg_sz) != 0) {
        db_manager_clear(m); free(m); return NULL;
    }
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


static gboolean db_index_shape_valid(const char *files) {
    if (!files || !files[0]) return TRUE;

    size_t total_len = strnlen(files, (size_t)DB_MAX_INDEX_BYTES + 1U);
    if (total_len > DB_MAX_INDEX_BYTES) return FALSE;

    size_t lines = 0;
    const char *p = files;
    const char *limit = files + total_len;

    while (p < limit) {
        const char *end = memchr(p, '\n', (size_t)(limit - p));
        if (!end) end = limit;
        size_t line_len = (size_t)(end - p);

        if (line_len != 0) {
            if (++lines > DB_MAX_INDEX_FILES || line_len > DB_MAX_INDEX_LINE_BYTES)
                return FALSE;

            const char *tab = memchr(p, '\t', line_len);
            const char *path_end = tab ? tab : end;
            if (path_end == p) return FALSE;

            if (tab) {
                if (memchr(tab + 1, '\t', (size_t)(end - tab - 1)) != NULL)
                    return FALSE;
                long long parsed_size = 0;
                if (!db_parse_size_span(tab + 1, end, &parsed_size))
                    return FALSE;
            }

            unsigned depth = 0;
            gboolean component = FALSE;
            for (const char *q = p; q < path_end; q++) {
                if ((unsigned char)*q == '\r') return FALSE;
                if (*q == '/') {
                    component = FALSE;
                    continue;
                }
                if (!component) {
                    component = TRUE;
                    if (++depth > DB_MAX_INDEX_DEPTH) return FALSE;
                }
            }
            if (depth == 0) return FALSE;
        }

        p = end < limit ? end + 1 : limit;
    }

    return TRUE;
}

static fs_node_t *fs_build_tree(const char *files) {
    fs_node_t *root = fs_node_new("", TRUE);
    if (!files || !files[0] || !db_index_shape_valid(files)) return root;

    size_t nodes = 0;
    gboolean truncated = FALSE;
    const char *p = files;
    size_t total_len = strlen(files);
    const char *limit = files + total_len;

    while (p < limit && !truncated) {
        const char *end = memchr(p, '\n', (size_t)(limit - p));
        if (!end) end = limit;
        size_t line_len = (size_t)(end - p);
        if (line_len == 0) {
            p = end < limit ? end + 1 : limit;
            continue;
        }

        char *line = g_strndup(p, line_len);
        if (!line) break;
        long long sz = -1;
        char *tab = strchr(line, '\t');
        if (tab) {
            *tab = '\0';
            (void)db_parse_size_span(tab + 1, tab + 1 + strlen(tab + 1), &sz);
        }

        char **parts = g_strsplit(line, "/", -1);
        if (!parts) {
            secure_g_free_string(&line);
            break;
        }
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
                if (nodes >= DB_MAX_TREE_RENDER_NODES) {
                    truncated = TRUE;
                    break;
                }
                child = fs_node_new(parts[i], !is_last);
                cur->children = g_list_prepend(cur->children, child);
                g_hash_table_insert(cur->children_index, child->name, child);
                nodes++;
            }
            if (is_last) child->size = sz;
            cur = child;
        }
        g_strfreev(parts);
        secure_g_free_string(&line);
        p = end < limit ? end + 1 : limit;
    }

    GQueue *q = g_queue_new();
    if (!q) return root;
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

        int raw_dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (raw_dirfd < 0) {
            secure_g_free_string(&dir);
            continue;
        }
        DIR *d = fdopendir(raw_dirfd);
        if (!d) {
            close(raw_dirfd);
            secure_g_free_string(&dir);
            continue;
        }

        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            const char *name = de->d_name;
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
            gboolean skip = FALSE;
            for (int i = 0; skip_names[i]; i++) {
                if (strcmp(name, skip_names[i]) == 0) { skip = TRUE; break; }
            }
            if (skip) continue;

            struct stat st;
            if (fstatat(dirfd(d), name, &st, AT_SYMLINK_NOFOLLOW) != 0)
                continue;
            char *full = g_build_filename(dir, name, NULL);
            if (!full) continue;

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
                    need > DB_MAX_INDEX_LINE_BYTES ||
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
        closedir(d);
        secure_g_free_string(&dir);
    }

    while (!g_queue_is_empty(queue)) {
        char *pending = g_queue_pop_head(queue);
        secure_g_free_string(&pending);
    }
    g_queue_free(queue);

    if (!exceeded && !db_index_shape_valid(s->str)) exceeded = TRUE;
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
    int rotational;
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
    cJSON *dev = NULL;
    cJSON_ArrayForEach(dev, arr) {
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
            if (db_json_size_valid(j_size)) {
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

            d->rotational = -1;
            cJSON *j_rota = cJSON_GetObjectItem(dev, "rota");
            if (j_rota && cJSON_IsBool(j_rota))
                d->rotational = cJSON_IsTrue(j_rota) ? 1 : 0;
            else if (j_rota && cJSON_IsNumber(j_rota))
                d->rotational = j_rota->valueint ? 1 : 0;

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
        "-o", "PATH,UUID,SIZE,FSTYPE,MOUNTPOINT,MODEL,TRAN,TYPE,LABEL,ROTA",
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

static const char *transport_to_type(const char *tran, int rotational) {
    if (tran) {
        if (strcasecmp(tran, "nvme") == 0) return "NVMe";
        if (strcasecmp(tran, "mmc") == 0) return "SD";
        if (strcasecmp(tran, "usb") == 0) {
            if (rotational == 1) return "HDD_External";
            return "USB";
        }
    }
    if (rotational == 1) return "HDD";
    if (rotational == 0) return "SSD";
    return NULL;
}

static void proc_mount_unescape(char *s) {
    if (!s) return;
    char *src = s, *dst = s;
    while (*src) {
        if (src[0] == '\\' && src[1] && src[2] && src[3] &&
            src[1] >= '0' && src[1] <= '7' &&
            src[2] >= '0' && src[2] <= '7' && src[3] >= '0' && src[3] <= '7') {
            *dst++ = (char)(((src[1] - '0') << 6) | ((src[2] - '0') << 3) | (src[3] - '0'));
            src += 4;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static char *find_device_for_path(const char *path) {
    char *real = realpath(path, NULL);
    const char *use = real ? real : path;
    FILE *f = fopen("/proc/self/mounts", "r");
    if (!f) { free(real); return NULL; }
    char line[4096];
    char *best_dev = NULL;
    size_t best_len = 0;
    size_t path_len = strlen(use);
    while (fgets(line, sizeof(line), f)) {
        char dev[2048], mnt[2048];
        if (sscanf(line, "%2047s %2047s", dev, mnt) != 2) continue;
        proc_mount_unescape(dev);
        proc_mount_unescape(mnt);
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

    gchar *smartctl = NULL;
    if (g_file_test("/usr/sbin/smartctl", G_FILE_TEST_IS_EXECUTABLE))
        smartctl = g_strdup("/usr/sbin/smartctl");
    else if (g_file_test("/usr/bin/smartctl", G_FILE_TEST_IS_EXECUTABLE))
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
        if (db_json_size_valid(bytes)) {
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
            cJSON *row = NULL;
            cJSON_ArrayForEach(row, table) {
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
    char *printed = cJSON_PrintUnformatted(result);
    db_json_zero_strings(result);
    cJSON_Delete(result);
    if (!printed) return NULL;
    char *final = xstrdup(printed);
    secure_json_free(printed);
    return final;
}

typedef struct {
    db_entry_t *entry;
    char *old_files;
    char *old_smart;
    long long old_last_snapshot;
    int old_file_count;
    long long old_indexed_bytes;
    gboolean active;
} db_snapshot_backup_t;

static void db_snapshot_backup_commit(db_snapshot_backup_t *b) {
    if (!b || !b->active) return;
    secure_free_string(&b->old_files);
    secure_free_string(&b->old_smart);
    memset(b, 0, sizeof(*b));
}

static void db_snapshot_backup_rollback(db_snapshot_backup_t *b) {
    if (!b || !b->active || !b->entry) return;
    secure_free_string(&b->entry->files);
    secure_free_string(&b->entry->smart);
    b->entry->files = b->old_files;
    b->entry->smart = b->old_smart;
    b->entry->last_snapshot = b->old_last_snapshot;
    b->entry->file_count = b->old_file_count;
    b->entry->indexed_bytes = b->old_indexed_bytes;
    b->old_files = NULL;
    b->old_smart = NULL;
    memset(b, 0, sizeof(*b));
}

static int db_set_entry_snapshot_nosave(db_manager_t *m, const char *label,
    const char *files, const char *smart_json, db_snapshot_backup_t *backup,
    char *err_msg, size_t err_msg_sz)
{
    if (backup) memset(backup, 0, sizeof(*backup));
    if (!m || !label || !files || !db_index_shape_valid(files) ||
        (smart_json && strlen(smart_json) > 2 * 1024 * 1024)) {
        snprintf(err_msg, err_msg_sz, "Index scan failed or exceeded safety limits; previous snapshot was kept");
        return -1;
    }
    for (int i = 0; i < m->entry_count; i++) {
        if (strcmp(m->entries[i].label, label) == 0) {
            char *new_files = (files && files[0]) ? xstrdup(files) : NULL;
            char *new_smart = (smart_json && smart_json[0]) ? xstrdup(smart_json) : NULL;
            db_entry_t *e = &m->entries[i];

            if (backup) {
                backup->entry = e;
                backup->old_files = e->files;
                backup->old_smart = e->smart;
                backup->old_last_snapshot = e->last_snapshot;
                backup->old_file_count = e->file_count;
                backup->old_indexed_bytes = e->indexed_bytes;
                backup->active = TRUE;
            } else {
                secure_free_string(&e->files);
                secure_free_string(&e->smart);
            }

            e->files = new_files;
            e->smart = new_smart;
            e->last_snapshot = (long long)time(NULL);
            db_entry_refresh_index_stats(e);
            return 0;
        }
    }
    snprintf(err_msg, err_msg_sz, "Database entry was not found");
    return -1;
}

static int db_set_entry_snapshot(db_manager_t *m, const char *label,
    const char *files, const char *smart_json,
    char *err_msg, size_t err_msg_sz)
{
    db_snapshot_backup_t backup;
    if (db_set_entry_snapshot_nosave(m, label, files, smart_json, &backup,
            err_msg, err_msg_sz) != 0)
        return -1;
    int history_before = m->history_count;
    const db_entry_t *hist_entry = NULL;
    for (int i = 0; i < m->entry_count; i++)
        if (m->entries[i].label && strcmp(m->entries[i].label, label) == 0) { hist_entry = &m->entries[i]; break; }
    if (db_history_mark(m, "snapshot_updated", db_history_entry_target(hist_entry),
            &history_before, err_msg, err_msg_sz) != 0) {
        db_snapshot_backup_rollback(&backup);
        return -1;
    }
    if (db_save(m, err_msg, err_msg_sz) != 0) {
        db_history_restore_count(m, history_before);
        db_snapshot_backup_rollback(&backup);
        return -1;
    }
    db_snapshot_backup_commit(&backup);
    return 0;
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
            int history_before = m->history_count;
            if (db_history_mark(m, "smart_updated", db_history_entry_target(&m->entries[i]),
                    &history_before, err_msg, err_msg_sz) != 0) {
                secure_free_string(&m->entries[i].smart);
                m->entries[i].smart = old;
                return -1;
            }
            if (db_save(m, err_msg, err_msg_sz) != 0) {
                db_history_restore_count(m, history_before);
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


        if (new_cap <= m->entry_cap) {
            snprintf(err_msg, err_msg_sz, "Database entry limit reached");
            return -1;
        }
        db_entry_t *ne = realloc(m->entries, (size_t)new_cap * sizeof(db_entry_t));
        if (!ne) { snprintf(err_msg, err_msg_sz, "alloc failed"); return -1; }
        memset(ne + m->entry_cap, 0, (size_t)(new_cap - m->entry_cap) * sizeof(db_entry_t));
        m->entries = ne; m->entry_cap = new_cap;
    }
    db_entry_t *e = &m->entries[m->entry_count];
    db_entry_init(e);
    e->label = db_encode_label(m, type, size, content_tag, cipher, dsalt);
    if (!e->label) {
        snprintf(err_msg, err_msg_sz, "Cannot encode invalid tag fields");
        return -1;
    }
    for (int i = 0; i < m->entry_count; i++) {
        if (m->entries[i].label && strcmp(m->entries[i].label, e->label) == 0) {
            db_entry_clear(e);
            memset(e, 0, sizeof(*e));
            snprintf(err_msg, err_msg_sz,
                "Generated label already exists; regenerate the salt and try again");
            return -1;
        }
    }
    e->type = xstrdup(type); e->size = xstrdup(size); e->cipher = xstrdup(cipher);
    e->content_tag = xstrdup(content_tag); e->dsalt = xstrdup(dsalt);
    e->tag_full = xstrdup(tag_full ? tag_full : "");
    if (dpass && dpass[0]) e->dpass = sec_strdup(dpass);
    if (notes) e->notes = xstrdup(notes);
    if (alias && alias[0]) e->alias = xstrdup(alias);
    if (uuid && uuid[0]) e->uuid = xstrdup(uuid);
    m->entry_count++;
    int history_before = m->history_count;
    if (db_history_mark(m, "entry_added", db_history_entry_target(e),
            &history_before, err_msg, err_msg_sz) != 0) {
        m->entry_count--;
        db_entry_clear(&m->entries[m->entry_count]);
        memset(&m->entries[m->entry_count], 0, sizeof(db_entry_t));
        return -1;
    }
    if (db_save(m, err_msg, err_msg_sz) != 0) {
        db_history_restore_count(m, history_before);
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
            int history_before = m->history_count;
            if (db_history_mark(m, "entry_removed", db_history_entry_target(&removed),
                    &history_before, err_msg, err_msg_sz) != 0) {
                memmove(&m->entries[i+1], &m->entries[i],
                    (size_t)(m->entry_count - i) * sizeof(db_entry_t));
                m->entries[i] = removed;
                m->entry_count++;
                return -1;
            }
            if (db_save(m, err_msg, err_msg_sz) != 0) {
                db_history_restore_count(m, history_before);
                memmove(&m->entries[i+1], &m->entries[i],
                    (size_t)(m->entry_count - i) * sizeof(db_entry_t));
                m->entries[i] = removed;
                m->entry_count++;
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
            int history_before = m->history_count;
            if (db_history_mark(m, "entry_updated", db_history_entry_target(&m->entries[i]),
                    &history_before, err_msg, err_msg_sz) != 0) {
                if (m->entries[i].dpass) sec_strfree(m->entries[i].dpass);
                secure_free_string(&m->entries[i].notes);
                secure_free_string(&m->entries[i].alias);
                m->entries[i].dpass = old_pass;
                m->entries[i].notes = old_notes;
                m->entries[i].alias = old_alias;
                return -1;
            }
            if (db_save(m, err_msg, err_msg_sz) != 0) {
                db_history_restore_count(m, history_before);
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
    gboolean has_secret;
    gboolean has_secret_sign;
    gboolean has_secret_encrypt;
    gboolean can_encrypt;
} gpg_key_info_t;
