#ifndef DISKPASS_H
#define DISKPASS_H

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

extern const char ALPHABET[];
extern const size_t ALPHABET_LEN;
extern const char *SCHEMA_PARTS[];
extern const int SCHEMA_COUNT;
extern const int PART_LENGTHS[];
extern const int FULL_PART_LENGTHS[];

typedef struct { const char *name; const char *code; } map_entry_t;
typedef struct { const char *type; const char **sizes; } type_size_assoc_t;
typedef struct { const char *key; const char *ru; const char *en; } i18n_entry_t;

extern const map_entry_t TYPE_MAP[];
extern const int TYPE_MAP_N;
extern const map_entry_t SIZE_MAP[];
extern const int SIZE_MAP_N;
extern const map_entry_t CIPHER_MAP[];
extern const int CIPHER_MAP_N;
extern const type_size_assoc_t TYPE_SIZE_MAP[];
extern const int TYPE_SIZE_MAP_N;

extern char g_lang[8];
const char *i18n(const char *key);

const char *map_encode(const char *part_name, const char *value);
const char *map_decode(const char *part_name, const char *code);
const char **get_sizes_for_type(const char *type_name);

void *sec_alloc(size_t n);
void sec_free(void *p, size_t n);
char *sec_strdup(const char *s);
void sec_strfree(char *s);
char *xstrdup(const char *s);
void secure_free_string(char **s);

char *generate_salt(int length);
char *generate_password(int length);
char calculate_block_salt(const uint8_t *noise_key, size_t key_len,
    const uint8_t *salt, size_t salt_len,
    int part_index, const char *val_str);
void secure_shuffle(const char **arr, int n);

typedef struct {
    char *label, *type, *size, *cipher, *content_tag, *dsalt, *tag_full, *dpass, *notes, *alias;
} db_entry_t;

void db_entry_init(db_entry_t *e);
void db_entry_clear(db_entry_t *e);

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

void db_manager_init(db_manager_t *m);
void db_manager_clear(db_manager_t *m);

typedef struct { char *fingerprint; char *uid; } gpg_key_info_t;
gpg_key_info_t *gpg_list_keys(gpgme_ctx_t ctx, int secret_only, int *out_count);
void gpg_free_key_list(gpg_key_info_t *list, int count);

int db_init_gpg(db_manager_t *m, char *err_msg, size_t err_msg_sz);
int db_read_file(const char *path, char **out_recipient, char **out_enc_data,
    char *err_msg, size_t err_msg_sz);
char *db_gpg_decrypt(db_manager_t *m, const char *enc_data, size_t enc_len,
    char *err_msg, size_t err_msg_sz);
char *db_gpg_encrypt(db_manager_t *m, const char *plaintext, size_t pt_len,
    char *err_msg, size_t err_msg_sz);
char *hex_encode(const uint8_t *data, size_t len);
uint8_t *hex_decode(const char *hex, size_t *out_len);
int db_load_json(db_manager_t *m, const char *json_str, char *err_msg, size_t err_msg_sz);
int db_save(db_manager_t *m, char *err_msg, size_t err_msg_sz);
db_manager_t *db_manager_open(const char *path, const char *forced_key,
    char *err_msg, size_t err_msg_sz);
db_manager_t *db_manager_create(const char *path, const char *recipient,
    const char *lang, char *err_msg, size_t err_msg_sz);

typedef struct {
    char part_name[32], block[8], val[8], decoded[64];
    char schar, expected_schar;
} parsed_block_t;

char *db_encode_label(db_manager_t *m, const char *type, const char *size,
    const char *content_tag, const char *cipher, const char *dsalt);
int db_parse_label(db_manager_t *m, const char *label,
    parsed_block_t *out_blocks, int *out_count,
    char *err_msg, size_t err_msg_sz);
char *build_label_tooltip(db_manager_t *m, const char *label);

int db_add_entry(db_manager_t *m, const char *type, const char *size,
    const char *cipher, const char *content_tag, const char *dsalt,
    const char *tag_full, const char *dpass, const char *notes,
    const char *alias,
    char *err_msg, size_t err_msg_sz);
int db_remove_entry(db_manager_t *m, const char *label, char *err_msg, size_t err_msg_sz);
int db_update_entry(db_manager_t *m, const char *label,
    const char *new_dpass, const char *new_notes,
    const char *new_alias,
    char *err_msg, size_t err_msg_sz);

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
    guint idle_timer_id;
} AppData;

extern AppData g_app;
extern GdkPixbuf *icon_pb;

void update_ui_text(void);
void refresh_entry_list(void);
void clear_details(void);
void show_entry_details(int idx);
void clipboard_copy_secure(const char *text);
void populate_gpg_keys(GtkComboBoxText *combo, int secret_only, GtkWidget *err_label);

void build_welcome(void);
void build_setup(void);
void build_unlock(void);
void build_main(void);
void load_css(void);
void setup_accelerators(GtkWidget *win);

void graceful_shutdown(int sig);

#endif
