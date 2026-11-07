
#include <setjmp.h>
#include <jpeglib.h>

#define STEGO_JPEG_MAX_BYTES (256ULL * 1024ULL * 1024ULL)
#define STEGO_JPEG_MAX_PIXELS 48000000ULL
#define STEGO_MP3_MAX_TAG_BYTES (128ULL * 1024ULL * 1024ULL)
#define STEGO_MP3_MAX_COVER_BYTES (96ULL * 1024ULL * 1024ULL)

typedef struct {
    struct jpeg_error_mgr pub;
    jmp_buf jump;
    char message[JMSG_LENGTH_MAX];
} dp_jpeg_error_t;

static void dp_jpeg_error_exit(j_common_ptr cinfo) {
    dp_jpeg_error_t *err = (dp_jpeg_error_t *)cinfo->err;
    if (err && err->pub.format_message)
        (*err->pub.format_message)(cinfo, err->message);
    longjmp(err->jump, 1);
}

static gboolean stego_path_is_jpeg(const char *path) {
    if (!path) return FALSE;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return FALSE;
    unsigned char h[3] = {0};
    gboolean ok = pread(fd, h, sizeof(h), 0) == (ssize_t)sizeof(h) &&
        h[0] == 0xFF && h[1] == 0xD8 && h[2] == 0xFF;
    close(fd);
    return ok;
}

static gboolean stego_path_is_mp3(const char *path) {
    if (!path) return FALSE;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return FALSE;
    unsigned char h[10] = {0};
    ssize_t n = pread(fd, h, sizeof(h), 0);
    close(fd);
    if (n >= 3 && memcmp(h, "ID3", 3) == 0) return TRUE;
    if (n >= 2 && h[0] == 0xFF && (h[1] & 0xE0U) == 0xE0U) return TRUE;
    return FALSE;
}

static int stego_pread_all(int fd, void *buf, size_t len, uint64_t offset) {
    unsigned char *p = (unsigned char *)buf;
    size_t done = 0;
    while (done < len) {
        if (offset > (uint64_t)LLONG_MAX || done > (size_t)LLONG_MAX ||
            offset + (uint64_t)done > (uint64_t)LLONG_MAX)
            return -1;
        ssize_t n = pread(fd, p + done, len - done, (off_t)(offset + (uint64_t)done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        done += (size_t)n;
    }
    return 0;
}

static gboolean stego_mp3_audio_header_valid(const unsigned char h[4]) {
    uint32_t v = ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) |
        ((uint32_t)h[2] << 8) | (uint32_t)h[3];
    unsigned sync = (v >> 21) & 0x7FFU;
    unsigned version = (v >> 19) & 0x3U;
    unsigned layer = (v >> 17) & 0x3U;
    unsigned bitrate = (v >> 12) & 0xFU;
    unsigned sample_rate = (v >> 10) & 0x3U;
    return sync == 0x7FFU && version != 0x1U && layer == 0x1U &&
        bitrate != 0xFU && sample_rate != 0x3U;
}

static gboolean stego_mp3_audio_at_fd(int fd, uint64_t offset, uint64_t file_size) {
    if (fd < 0 || offset > file_size || file_size - offset < 4 || offset > (uint64_t)LLONG_MAX)
        return FALSE;
    unsigned char h[4];
    return stego_pread_all(fd, h, sizeof(h), offset) == 0 && stego_mp3_audio_header_valid(h);
}

static uint16_t stego_load_u16be(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t stego_load_u32be(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static gboolean stego_memory_image_dimensions_safe(const unsigned char *data, size_t len,
    char *err_msg, size_t err_msg_sz)
{
    if (!data || len < 8) {
        snprintf(err_msg, err_msg_sz, "Cover image is truncated");
        return FALSE;
    }

    uint64_t w = 0, h = 0;
    static const unsigned char pngsig[8] = {0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A};
    if (len >= 24 && memcmp(data, pngsig, sizeof(pngsig)) == 0) {
        if (memcmp(data + 12, "IHDR", 4) != 0) {
            snprintf(err_msg, err_msg_sz, "PNG cover has no valid IHDR");
            return FALSE;
        }
        w = stego_load_u32be(data + 16);
        h = stego_load_u32be(data + 20);
    } else if (len >= 4 && data[0] == 0xFF && data[1] == 0xD8) {
        size_t pos = 2;
        while (pos + 1 < len) {
            while (pos < len && data[pos] != 0xFF) pos++;
            if (pos >= len) break;
            while (pos < len && data[pos] == 0xFF) pos++;
            if (pos >= len) break;
            unsigned marker = data[pos++];
            if (marker == 0xD8 || marker == 0xD9 || marker == 0x01 ||
                (marker >= 0xD0 && marker <= 0xD7))
                continue;
            if (pos + 2 > len) break;
            uint16_t seglen = stego_load_u16be(data + pos);
            if (seglen < 2 || (size_t)seglen > len - pos) break;
            gboolean sof = (marker >= 0xC0 && marker <= 0xCF &&
                marker != 0xC4 && marker != 0xC8 && marker != 0xCC);
            if (sof) {
                if (seglen < 7) break;
                h = stego_load_u16be(data + pos + 3);
                w = stego_load_u16be(data + pos + 5);
                break;
            }
            pos += seglen;
        }
    } else {
        snprintf(err_msg, err_msg_sz, "Cover is not a supported PNG/JPEG image");
        return FALSE;
    }

    if (w == 0 || h == 0 || w > G_MAXINT || h > G_MAXINT ||
        w > UINT64_MAX / h || w * h > STEGO_MAX_PIXELS) {
        snprintf(err_msg, err_msg_sz,
            "Cover decoded dimensions exceed the steganography safety limit");
        return FALSE;
    }
    return TRUE;
}

static uint16_t stego_jpeg_canon_coef(JCOEF v, gboolean ac) {
    int x = (int)v;
    int sign = x < 0;
    unsigned a = (unsigned)(x < 0 ? -x : x);
    if (ac && a >= 2U) a &= ~1U;
    if (a > 0x7FFFU) a = 0x7FFFU;
    return (uint16_t)((sign ? 0x8000U : 0U) | a);
}

static gboolean stego_jpeg_analyze_mode(j_decompress_ptr src, jvirt_barray_ptr *coef_arrays,
    unsigned char seed[STEGO_SEED_BYTES], uint64_t *out_slots, gboolean keyed,
    char *err_msg, size_t err_msg_sz)
{
    if (!src || !coef_arrays || !seed || !out_slots) return FALSE;

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
        snprintf(err_msg, err_msg_sz, "Cannot initialize JPEG steganography hash");
        return FALSE;
    }
    static const unsigned char public_ctx[] = "DiskPass JPEG DCT bootstrap seed v3";
    static const unsigned char legacy_ctx[] = "DiskPass JPEG DCT steganography seed v2";
    const unsigned char *ctx = keyed ? legacy_ctx : public_ctx;
    size_t ctx_len = keyed ? sizeof(legacy_ctx) - 1 : sizeof(public_ctx) - 1;
    crypto_generichash_update(&st, ctx, ctx_len);
    unsigned char meta[24] = {0};
    db_store_u64le(meta, (uint64_t)src->image_width);
    db_store_u64le(meta + 8, (uint64_t)src->image_height);
    meta[16] = (unsigned char)src->num_components;
    crypto_generichash_update(&st, meta, sizeof(meta));

    uint64_t slots = 0;
    unsigned char buf[8192];
    size_t used = 0;
    for (int ci = 0; ci < src->num_components; ci++) {
        jpeg_component_info *comp = &src->comp_info[ci];
        unsigned char cm[16] = {0};
        cm[0] = (unsigned char)ci;
        cm[1] = (unsigned char)comp->h_samp_factor;
        cm[2] = (unsigned char)comp->v_samp_factor;
        cm[3] = (unsigned char)comp->quant_tbl_no;
        uint32_t wb = (uint32_t)comp->width_in_blocks, hb = (uint32_t)comp->height_in_blocks;
        cm[4] = (unsigned char)wb; cm[5] = (unsigned char)(wb >> 8); cm[6] = (unsigned char)(wb >> 16); cm[7] = (unsigned char)(wb >> 24);
        cm[8] = (unsigned char)hb; cm[9] = (unsigned char)(hb >> 8); cm[10] = (unsigned char)(hb >> 16); cm[11] = (unsigned char)(hb >> 24);
        crypto_generichash_update(&st, cm, sizeof(cm));
        if (comp->quant_table) {
            for (int q = 0; q < DCTSIZE2; q++) {
                uint16_t v = comp->quant_table->quantval[q];
                unsigned char qv[2] = {(unsigned char)v, (unsigned char)(v >> 8)};
                crypto_generichash_update(&st, qv, sizeof(qv));
            }
        }
        for (JDIMENSION row = 0; row < comp->height_in_blocks; row++) {
            JBLOCKARRAY blocks = (*src->mem->access_virt_barray)((j_common_ptr)src,
                coef_arrays[ci], row, 1, FALSE);
            for (JDIMENSION col = 0; col < comp->width_in_blocks; col++) {
                JCOEFPTR block = blocks[0][col];
                for (int k = 0; k < DCTSIZE2; k++) {
                    int x = (int)block[k];
                    unsigned a = (unsigned)(x < 0 ? -x : x);
                    if (k != 0 && a >= 2U && a <= 0x7FFFU) slots++;
                    uint16_t canon = stego_jpeg_canon_coef(block[k], k != 0);
                    buf[used++] = (unsigned char)canon;
                    buf[used++] = (unsigned char)(canon >> 8);
                    if (used >= sizeof(buf) - 1) {
                        crypto_generichash_update(&st, buf, used);
                        used = 0;
                    }
                }
            }
        }
    }
    if (used) crypto_generichash_update(&st, buf, used);
    sodium_memzero(buf, sizeof(buf));
    if (slots < (uint64_t)STEGO_HEADER_BYTES * 8U) {
        sodium_memzero(secret_snapshot, sizeof(secret_snapshot));
        snprintf(err_msg, err_msg_sz, "JPEG has too few usable AC DCT coefficients for steganography");
        return FALSE;
    }
    crypto_generichash_final(&st, seed, STEGO_SEED_BYTES);
    sodium_memzero(secret_snapshot, sizeof(secret_snapshot));
    *out_slots = slots;
    return TRUE;
}

static gboolean stego_jpeg_analyze(j_decompress_ptr src, jvirt_barray_ptr *coef_arrays,
    unsigned char seed[STEGO_SEED_BYTES], uint64_t *out_slots,
    char *err_msg, size_t err_msg_sz)
{
    return stego_jpeg_analyze_mode(src, coef_arrays, seed, out_slots, FALSE,
        err_msg, err_msg_sz);
}

static gboolean stego_jpeg_analyze_legacy(j_decompress_ptr src, jvirt_barray_ptr *coef_arrays,
    unsigned char seed[STEGO_SEED_BYTES], uint64_t *out_slots,
    char *err_msg, size_t err_msg_sz)
{
    return stego_jpeg_analyze_mode(src, coef_arrays, seed, out_slots, TRUE,
        err_msg, err_msg_sz);
}

static void stego_jpeg_rw_range(j_decompress_ptr src, jvirt_barray_ptr *coef_arrays,
    uint64_t slots, uint64_t start_slot, uint64_t first_bit,
    unsigned char *data, size_t len, gboolean write_mode)
{


    if (!write_mode) memset(data, 0, len);
    uint64_t last_bit = first_bit + (uint64_t)len * 8U;
    uint64_t slot_index = 0;
    for (int ci = 0; ci < src->num_components; ci++) {
        jpeg_component_info *comp = &src->comp_info[ci];
        for (JDIMENSION row = 0; row < comp->height_in_blocks; row++) {
            JBLOCKARRAY blocks = (*src->mem->access_virt_barray)((j_common_ptr)src,
                coef_arrays[ci], row, 1, write_mode ? TRUE : FALSE);
            for (JDIMENSION col = 0; col < comp->width_in_blocks; col++) {
                JCOEFPTR block = blocks[0][col];
                for (int k = 1; k < DCTSIZE2; k++) {
                    int v = (int)block[k];
                    unsigned a = (unsigned)(v < 0 ? -v : v);
                    if (a < 2U || a > 0x7FFFU) continue;
                    uint64_t logical = slot_index >= start_slot
                        ? slot_index - start_slot
                        : slots - start_slot + slot_index;
                    if (logical >= first_bit && logical < last_bit) {
                        uint64_t bidx = logical - first_bit;
                        size_t byte_i = (size_t)(bidx >> 3);
                        unsigned bit_i = (unsigned)(bidx & 7U);
                        if (write_mode) {
                            unsigned wanted = (data[byte_i] >> bit_i) & 1U;
                            if ((a & 1U) != wanted) {
                                if (a & 1U) a--; else a++;
                                block[k] = (JCOEF)(v < 0 ? -(int)a : (int)a);
                            }
                        } else {
                            data[byte_i] |= (unsigned char)((a & 1U) << bit_i);
                        }
                    }
                    slot_index++;
                }
            }
        }
    }
}

static gboolean stego_jpeg_decode_header(j_decompress_ptr src, jvirt_barray_ptr *coef_arrays,
    uint64_t slots, const unsigned char seed[STEGO_SEED_BYTES], unsigned char expected_version,
    uint64_t *payload_len, unsigned char payload_hash[STEGO_HASH_BYTES])
{
    unsigned char enc[STEGO_HEADER_BYTES], plain[STEGO_HEADER_BYTES], mask[STEGO_HEADER_BYTES];
    unsigned char check[STEGO_CHECK_BYTES];
    uint64_t start = db_load_u64le(seed) % slots;
    memset(enc, 0, sizeof(enc));
    stego_jpeg_rw_range(src, coef_arrays, slots, start, 0, enc, sizeof(enc), FALSE);
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
    }
    sodium_memzero(enc, sizeof(enc));
    sodium_memzero(plain, sizeof(plain));
    sodium_memzero(mask, sizeof(mask));
    sodium_memzero(check, sizeof(check));
    return ok;
}

static int stego_jpeg_write_atomic(j_decompress_ptr src, jvirt_barray_ptr *coef_arrays,
    const char *output_path, char *err_msg, size_t err_msg_sz)
{
    char *tmp = NULL;
    int fd = -1;
    FILE * volatile fp = NULL;
    struct jpeg_compress_struct dst;
    dp_jpeg_error_t jerr;
    volatile gboolean created = FALSE;
    volatile int rc = -1;
    memset(&dst, 0, sizeof(dst)); memset(&jerr, 0, sizeof(jerr));
    if (carrier_create_temp(output_path, &tmp, &fd, err_msg, err_msg_sz) != 0) return -1;
    fp = fdopen(fd, "wb");
    if (!fp) {
        snprintf(err_msg, err_msg_sz, "Cannot open temporary JPEG stream: %s", strerror(errno));
        close(fd); fd = -1; goto cleanup;
    }
    fd = -1;
    dst.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = dp_jpeg_error_exit;
    if (setjmp(jerr.jump)) {
        snprintf(err_msg, err_msg_sz, "Cannot encode stego JPEG: %s",
            jerr.message[0] ? jerr.message : "libjpeg error");
        goto cleanup;
    }
    jpeg_create_compress(&dst); created = TRUE;
    jpeg_stdio_dest(&dst, fp);
    jpeg_copy_critical_parameters(src, &dst);
    dst.write_JFIF_header = FALSE;
    dst.write_Adobe_marker = FALSE;
    jpeg_write_coefficients(&dst, coef_arrays);
    for (jpeg_saved_marker_ptr m = src->marker_list; m; m = m->next)
        jpeg_write_marker(&dst, m->marker, m->data, m->data_length);
    jpeg_finish_compress(&dst);
    jpeg_destroy_compress(&dst); created = FALSE;
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot sync stego JPEG: %s", strerror(errno));
        goto cleanup;
    }
    if (fclose(fp) != 0) { fp = NULL; snprintf(err_msg, err_msg_sz, "Cannot close stego JPEG: %s", strerror(errno)); goto cleanup; }
    fp = NULL;
    if (rename(tmp, output_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot atomically install stego JPEG: %s", strerror(errno));
        goto cleanup;
    }
    carrier_fsync_parent(output_path);
    rc = 0;
cleanup:
    if (created) jpeg_destroy_compress(&dst);
    if (fp) fclose(fp);
    if (fd >= 0) close(fd);
    if (rc != 0 && tmp) unlink(tmp);
    free(tmp);
    return rc;
}

static void stego_jpeg_add_capacity_texture(GdkPixbuf *pb)
{
    if (!pb) return;
    int w = gdk_pixbuf_get_width(pb);
    int h = gdk_pixbuf_get_height(pb);
    int channels = gdk_pixbuf_get_n_channels(pb);
    /* Artificial pixel noise has a strong statistical signature and can make
     * an enlarged image easier to classify as manipulated. Do not add it;
     * this routine remains as a no-op for existing callers. */
    (void)w;
    (void)h;
    (void)channels;
}

static int stego_jpeg_make_enlarged_cover(const char *carrier_path,
    const char *output_hint, uint64_t payload_bytes, uint64_t current_slots,
    char **out_path, char *err_msg, size_t err_msg_sz)
{
    if (!carrier_path || !output_hint || !out_path) return -1;
    *out_path = NULL;
    if (g_strcmp0(g_getenv("DISKPASS_STEGO_NO_UPSCALE"), "1") == 0) {
        snprintf(err_msg, err_msg_sz,
            "JPEG is too small and automatic enlargement is disabled");
        return -1;
    }

    unsigned percent = 100;
    if (!stego_embedding_percent(&percent, err_msg, err_msg_sz)) return -1;
    GdkPixbuf *src = stego_load_image_safe_limit(carrier_path, STEGO_JPEG_MAX_PIXELS, err_msg, err_msg_sz);
    if (!src) return -1;

    int w = gdk_pixbuf_get_width(src), h = gdk_pixbuf_get_height(src);
    if (w <= 0 || h <= 0) {
        g_object_unref(src);
        snprintf(err_msg, err_msg_sz, "JPEG has invalid decoded dimensions");
        return -1;
    }

    long double required_bits = ((long double)payload_bytes + (long double)STEGO_HEADER_BYTES) * 8.0L;
    required_bits *= 100.0L / (long double)percent;
    long double factor;
    if (current_slots > 0) factor = sqrtl(required_bits / (long double)current_slots);
    else factor = 2.0L;


    factor *= 1.35L;
    if (factor < 1.20L) factor = 1.20L;

    long double nwl = ceill((long double)w * factor);
    long double nhl = ceill((long double)h * factor);
    if (nwl > (long double)G_MAXINT || nhl > (long double)G_MAXINT ||
        nwl < 1.0L || nhl < 1.0L) {
        g_object_unref(src);
        snprintf(err_msg, err_msg_sz,
            "JPEG would need invalid dimensions to hold this database");
        return -1;
    }

    long double area = nwl * nhl;
    if (area > (long double)STEGO_JPEG_MAX_PIXELS) {
        long double cur_area = (long double)w * (long double)h;
        long double max_factor = sqrtl((long double)STEGO_JPEG_MAX_PIXELS / cur_area);
        if (max_factor <= 1.0L) {
            g_object_unref(src);
            snprintf(err_msg, err_msg_sz,
                "JPEG is too small for this database within the safe DCT carrier limit");
            return -1;
        }
        nwl = floorl((long double)w * max_factor);
        nhl = floorl((long double)h * max_factor);
        if (nwl < 1.0L || nhl < 1.0L || nwl * nhl > (long double)STEGO_JPEG_MAX_PIXELS) {
            g_object_unref(src);
            snprintf(err_msg, err_msg_sz, "Cannot calculate safe enlarged JPEG dimensions");
            return -1;
        }
    }

    GdkPixbuf *scaled = gdk_pixbuf_scale_simple(src, (int)nwl, (int)nhl, GDK_INTERP_BILINEAR);
    g_object_unref(src);
    if (!scaled) {
        snprintf(err_msg, err_msg_sz, "Cannot enlarge JPEG carrier");
        return -1;
    }
    stego_jpeg_add_capacity_texture(scaled);

    gchar *encoded = NULL;
    gsize encoded_len = 0;
    GError *gerr = NULL;
    if (!gdk_pixbuf_save_to_buffer(scaled, &encoded, &encoded_len, "jpeg", &gerr,
            "quality", "100", NULL)) {
        snprintf(err_msg, err_msg_sz, "Cannot encode enlarged JPEG: %s",
            gerr && gerr->message ? gerr->message : "JPEG encoder error");
        g_clear_error(&gerr);
        g_object_unref(scaled);
        return -1;
    }
    g_object_unref(scaled);

    if (!encoded || encoded_len == 0 || (uint64_t)encoded_len > STEGO_JPEG_MAX_BYTES) {
        if (encoded) { sodium_memzero(encoded, encoded_len); g_free(encoded); }
        snprintf(err_msg, err_msg_sz, "Enlarged JPEG exceeds the safety size limit");
        return -1;
    }

    char *tmp = NULL;
    int fd = -1;
    if (carrier_create_temp(output_hint, &tmp, &fd, err_msg, err_msg_sz) != 0) {
        sodium_memzero(encoded, encoded_len); g_free(encoded);
        return -1;
    }
    gboolean ok = write_all_fd(fd, encoded, encoded_len) == 0 && fsync(fd) == 0;
    int saved_errno = errno;
    if (close(fd) != 0) { ok = FALSE; saved_errno = errno; }
    sodium_memzero(encoded, encoded_len); g_free(encoded);
    if (!ok) {
        snprintf(err_msg, err_msg_sz, "Cannot write enlarged JPEG: %s", strerror(saved_errno));
        unlink(tmp); free(tmp);
        return -1;
    }
    *out_path = tmp;
    return 0;
}

static int carrier_attach_dpdb_jpeg_impl(const char *carrier_path, const char *db_path,
    const char *output_path, gboolean allow_enlarge, char *err_msg, size_t err_msg_sz)
{
    int dfd = -1, cfd = -1;
    uint64_t db_size = 0, carrier_size = 0, slots = 0;
    FILE * volatile fp = NULL;
    struct jpeg_decompress_struct src;
    dp_jpeg_error_t jerr;
    jvirt_barray_ptr *coef_arrays = NULL;
    volatile gboolean created = FALSE;
    volatile int rc = -1;
    unsigned char seed[STEGO_SEED_BYTES], payload_hash[STEGO_HASH_BYTES];
    unsigned char header[STEGO_HEADER_BYTES], mask[STEGO_HEADER_BYTES], check[STEGO_CHECK_BYTES];
    unsigned char * volatile payload = NULL;
    memset(&src, 0, sizeof(src)); memset(&jerr, 0, sizeof(jerr));

    if (!carrier_path || !db_path || !output_path ||
        !carrier_paths_distinct(carrier_path, output_path) ||
        !carrier_paths_distinct(db_path, output_path)) {
        snprintf(err_msg, err_msg_sz, "Output JPEG must be different from the source JPEG and database");
        return -1;
    }
    if (!(g_str_has_suffix(output_path, ".jpg") || g_str_has_suffix(output_path, ".JPG") ||
          g_str_has_suffix(output_path, ".jpeg") || g_str_has_suffix(output_path, ".JPEG"))) {
        snprintf(err_msg, err_msg_sz, "JPEG DCT steganography output must use .jpg or .jpeg");
        return -1;
    }
    if (carrier_open_regular(db_path, DB_MAX_FILE_BYTES, &dfd, &db_size, err_msg, err_msg_sz) != 0) goto cleanup;
    if (!db_path_has_dpdb_extension(db_path) || !carrier_dpdb_layout_at_fd(dfd, 0, db_size)) {
        snprintf(err_msg, err_msg_sz, "Only valid DiskPass .dpdb databases can be hidden"); goto cleanup;
    }
    if (carrier_open_regular(carrier_path, STEGO_JPEG_MAX_BYTES, &cfd, &carrier_size, err_msg, err_msg_sz) != 0) goto cleanup;
    (void)carrier_size;
    int stream_fd = fcntl(cfd, F_DUPFD_CLOEXEC, 3);
    if (stream_fd < 0) { snprintf(err_msg, err_msg_sz, "Cannot duplicate JPEG descriptor: %s", strerror(errno)); goto cleanup; }
    fp = fdopen(stream_fd, "rb");
    if (!fp) { close(stream_fd); snprintf(err_msg, err_msg_sz, "Cannot open JPEG stream: %s", strerror(errno)); goto cleanup; }
    src.err = jpeg_std_error(&jerr.pub); jerr.pub.error_exit = dp_jpeg_error_exit;
    if (setjmp(jerr.jump)) {
        snprintf(err_msg, err_msg_sz, "Cannot parse JPEG: %s", jerr.message[0] ? jerr.message : "libjpeg error");
        goto cleanup;
    }
    jpeg_create_decompress(&src); created = TRUE;
    for (int m = 0; m < 16; m++) jpeg_save_markers(&src, JPEG_APP0 + m, 0xFFFF);
    jpeg_save_markers(&src, JPEG_COM, 0xFFFF);
    jpeg_stdio_src(&src, fp);
    if (jpeg_read_header(&src, TRUE) != JPEG_HEADER_OK) { snprintf(err_msg, err_msg_sz, "Invalid JPEG header"); goto cleanup; }
    if (src.image_width == 0 || src.image_height == 0 || src.num_components <= 0 ||
        (uint64_t)src.image_width > UINT64_MAX / (uint64_t)src.image_height ||
        (uint64_t)src.image_width * (uint64_t)src.image_height > STEGO_JPEG_MAX_PIXELS) {
        snprintf(err_msg, err_msg_sz, "JPEG decoded dimensions exceed the steganography safety limit");
        goto cleanup;
    }
    coef_arrays = jpeg_read_coefficients(&src);
    if (!coef_arrays || !stego_jpeg_analyze(&src, coef_arrays, seed, &slots, err_msg, err_msg_sz)) goto cleanup;


    if (!g_atomic_int_get(&g_stego_replace_existing_payload)) {
        gboolean has_payload = stego_jpeg_decode_header(&src, coef_arrays, slots, seed,
            STEGO_VERSION, NULL, NULL);
        if (!has_payload) {
            unsigned char legacy_seed[STEGO_SEED_BYTES];
            uint64_t legacy_slots = 0;
            if (stego_jpeg_analyze_legacy(&src, coef_arrays, legacy_seed, &legacy_slots,
                    err_msg, err_msg_sz) && legacy_slots == slots)
                has_payload = stego_jpeg_decode_header(&src, coef_arrays, slots, legacy_seed,
                    STEGO_LEGACY_VERSION, NULL, NULL);
            sodium_memzero(legacy_seed, sizeof(legacy_seed));
        }
        if (has_payload) {
            snprintf(err_msg, err_msg_sz, "The selected JPEG already appears to contain a DiskPass stego payload");
            goto cleanup;
        }
    }
    if (!stego_embedding_budget(slots, db_size, err_msg, err_msg_sz)) {
        if (allow_enlarge) {
            char *grown = NULL;
            char grow_err[384] = "";
            if (stego_jpeg_make_enlarged_cover(carrier_path, output_path, db_size, slots,
                    &grown, grow_err, sizeof(grow_err)) == 0 && grown) {
                if (created) { jpeg_destroy_decompress(&src); created = FALSE; }
                if (fp) { fclose(fp); fp = NULL; }
                if (cfd >= 0) { close(cfd); cfd = -1; }
                if (dfd >= 0) { close(dfd); dfd = -1; }
                sodium_memzero(seed, sizeof(seed));
                int retry = carrier_attach_dpdb_jpeg_impl(grown, db_path, output_path, FALSE,
                    err_msg, err_msg_sz);
                unlink(grown); free(grown);
                return retry;
            }
            if (grow_err[0]) snprintf(err_msg, err_msg_sz, "%s", grow_err);
        }
        goto cleanup;
    }
    uint64_t capacity = slots / 8U;
    if (capacity < STEGO_HEADER_BYTES || db_size > capacity - STEGO_HEADER_BYTES) {
        uint64_t usable = capacity > STEGO_HEADER_BYTES ? capacity - STEGO_HEADER_BYTES : 0;
        snprintf(err_msg, err_msg_sz,
            "JPEG DCT capacity %.2f MiB is smaller than database %.2f MiB; use a larger or higher-detail JPEG",
            (double)usable / (1024.0 * 1024.0), (double)db_size / (1024.0 * 1024.0));
        goto cleanup;
    }
    if (stego_hash_fd(dfd, db_size, payload_hash, err_msg, err_msg_sz) != 0) goto cleanup;
    if (db_size > SIZE_MAX - STEGO_HEADER_BYTES) { snprintf(err_msg, err_msg_sz, "Database is too large for JPEG embedding"); goto cleanup; }
    payload = sodium_malloc((size_t)db_size + STEGO_HEADER_BYTES);
    if (!payload) { snprintf(err_msg, err_msg_sz, "Out of secure memory for JPEG embedding"); goto cleanup; }
    memset(header, 0, sizeof(header));
    db_store_u64le(header, db_size); memcpy(header + 8, payload_hash, STEGO_HASH_BYTES);
    header[40] = STEGO_VERSION; randombytes_buf(header + 41, 15);
    stego_header_check(seed, header, check); memcpy(header + STEGO_HEADER_BYTES - STEGO_CHECK_BYTES, check, STEGO_CHECK_BYTES);
    stego_header_mask(seed, mask); for (size_t i = 0; i < sizeof(header); i++) header[i] ^= mask[i];
    memcpy((void *)payload, header, STEGO_HEADER_BYTES);
    uint64_t off = 0;
    while (off < db_size) {
        ssize_t n = pread(dfd, (unsigned char *)payload + STEGO_HEADER_BYTES + off, (size_t)(db_size - off), (off_t)off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { snprintf(err_msg, err_msg_sz, "Cannot read database for JPEG steganography"); goto cleanup; }
        off += (uint64_t)n;
    }
    uint64_t start = db_load_u64le(seed) % slots;
    stego_jpeg_rw_range(&src, coef_arrays, slots, start, 0, (unsigned char *)payload,
        (size_t)db_size + STEGO_HEADER_BYTES, TRUE);
    if (stego_jpeg_write_atomic(&src, coef_arrays, output_path, err_msg, err_msg_sz) != 0) goto cleanup;
    rc = 0;
cleanup:
    if (payload) { sodium_memzero((void *)payload, (size_t)db_size + STEGO_HEADER_BYTES); sodium_free((void *)payload); }
    if (created) jpeg_destroy_decompress(&src);
    if (fp) fclose(fp);
    if (cfd >= 0) close(cfd);
    if (dfd >= 0) close(dfd);
    sodium_memzero(seed, sizeof(seed)); sodium_memzero(payload_hash, sizeof(payload_hash));
    sodium_memzero(header, sizeof(header)); sodium_memzero(mask, sizeof(mask)); sodium_memzero(check, sizeof(check));
    return rc;
}

static int carrier_attach_dpdb_jpeg(const char *carrier_path, const char *db_path,
    const char *output_path, char *err_msg, size_t err_msg_sz)
{
    return carrier_attach_dpdb_jpeg_impl(carrier_path, db_path, output_path, TRUE,
        err_msg, err_msg_sz);
}

static int carrier_extract_dpdb_jpeg(const char *jpeg_path, const char *output_db_path,
    char *err_msg, size_t err_msg_sz)
{
    int cfd = -1, ofd = -1;
    volatile int verify_fd = -1;
    uint64_t carrier_size = 0, slots = 0;
    volatile uint64_t payload_len = 0;
    FILE * volatile fp = NULL;
    struct jpeg_decompress_struct src;
    dp_jpeg_error_t jerr;
    jvirt_barray_ptr *coef_arrays = NULL;
    volatile gboolean created = FALSE;
    char *tmp = NULL;
    volatile int rc = -1;
    unsigned char seed[STEGO_SEED_BYTES], expected_hash[STEGO_HASH_BYTES], actual_hash[STEGO_HASH_BYTES];
    unsigned char * volatile payload = NULL;
    memset(&src, 0, sizeof(src)); memset(&jerr, 0, sizeof(jerr));
    if (!jpeg_path || !output_db_path || !carrier_paths_distinct(jpeg_path, output_db_path) ||
        !db_path_has_dpdb_extension(output_db_path)) {
        snprintf(err_msg, err_msg_sz, "Extracted database must be a separate .dpdb file"); return -1;
    }
    if (carrier_open_regular(jpeg_path, STEGO_JPEG_MAX_BYTES, &cfd, &carrier_size, err_msg, err_msg_sz) != 0) goto cleanup;
    (void)carrier_size;
    int stream_fd = fcntl(cfd, F_DUPFD_CLOEXEC, 3);
    if (stream_fd < 0) { snprintf(err_msg, err_msg_sz, "Cannot duplicate JPEG descriptor: %s", strerror(errno)); goto cleanup; }
    fp = fdopen(stream_fd, "rb");
    if (!fp) { close(stream_fd); snprintf(err_msg, err_msg_sz, "Cannot open JPEG stream"); goto cleanup; }
    src.err = jpeg_std_error(&jerr.pub); jerr.pub.error_exit = dp_jpeg_error_exit;
    if (setjmp(jerr.jump)) { snprintf(err_msg, err_msg_sz, "Cannot parse JPEG: %s", jerr.message); goto cleanup; }
    jpeg_create_decompress(&src); created = TRUE; jpeg_stdio_src(&src, fp);
    if (jpeg_read_header(&src, TRUE) != JPEG_HEADER_OK) { snprintf(err_msg, err_msg_sz, "Invalid JPEG header"); goto cleanup; }
    if (src.image_width == 0 || src.image_height == 0 || src.num_components <= 0 ||
        (uint64_t)src.image_width > UINT64_MAX / (uint64_t)src.image_height ||
        (uint64_t)src.image_width * (uint64_t)src.image_height > STEGO_JPEG_MAX_PIXELS) {
        snprintf(err_msg, err_msg_sz, "JPEG decoded dimensions exceed the steganography safety limit");
        goto cleanup;
    }
    coef_arrays = jpeg_read_coefficients(&src);
    if (!coef_arrays || !stego_jpeg_analyze(&src, coef_arrays, seed, &slots, err_msg, err_msg_sz)) goto cleanup;
    uint64_t decoded_payload_len = 0;
    gboolean found = stego_jpeg_decode_header(&src, coef_arrays, slots, seed,
        STEGO_VERSION, &decoded_payload_len, expected_hash);
    if (!found) {
        unsigned char legacy_seed[STEGO_SEED_BYTES];
        uint64_t legacy_slots = 0;
        if (stego_jpeg_analyze_legacy(&src, coef_arrays, legacy_seed, &legacy_slots,
                err_msg, err_msg_sz) && legacy_slots == slots) {
            found = stego_jpeg_decode_header(&src, coef_arrays, slots, legacy_seed,
                STEGO_LEGACY_VERSION, &decoded_payload_len, expected_hash);
            if (found) memcpy(seed, legacy_seed, sizeof(seed));
        }
        sodium_memzero(legacy_seed, sizeof(legacy_seed));
    }
    if (!found) {
        snprintf(err_msg, err_msg_sz, "No valid DiskPass DCT payload was found in this JPEG"); goto cleanup;
    }
    payload_len = decoded_payload_len;
    if (payload_len > SIZE_MAX) { snprintf(err_msg, err_msg_sz, "Hidden database is too large for this build"); goto cleanup; }
    payload = sodium_malloc((size_t)payload_len);
    if (!payload) { snprintf(err_msg, err_msg_sz, "Out of secure memory while extracting JPEG payload"); goto cleanup; }
    uint64_t start = db_load_u64le(seed) % slots;
    stego_jpeg_rw_range(&src, coef_arrays, slots, start, (uint64_t)STEGO_HEADER_BYTES * 8U,
        (unsigned char *)payload, (size_t)payload_len, FALSE);
    crypto_generichash(actual_hash, STEGO_HASH_BYTES, (const unsigned char *)payload, (size_t)payload_len, NULL, 0);
    if (sodium_memcmp(actual_hash, expected_hash, STEGO_HASH_BYTES) != 0) {
        snprintf(err_msg, err_msg_sz, "JPEG steganographic payload integrity check failed"); goto cleanup;
    }
    if (carrier_create_temp(output_db_path, &tmp, &ofd, err_msg, err_msg_sz) != 0) goto cleanup;
    if (write_all_fd(ofd, (const void *)payload, (size_t)payload_len) != 0 || fsync(ofd) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot write extracted database: %s", strerror(errno)); goto cleanup;
    }
    if (close(ofd) != 0) {
        ofd = -1;
        snprintf(err_msg, err_msg_sz, "Cannot close extracted database: %s", strerror(errno)); goto cleanup;
    }
    ofd = -1;
    verify_fd = open(tmp, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (verify_fd < 0 || !carrier_dpdb_layout_at_fd(verify_fd, 0, payload_len)) {
        snprintf(err_msg, err_msg_sz, "Extracted JPEG payload is not a recognized DiskPass .dpdb container"); goto cleanup;
    }
    close(verify_fd); verify_fd = -1;
    if (rename(tmp, output_db_path) != 0) { snprintf(err_msg, err_msg_sz, "Cannot install extracted database: %s", strerror(errno)); goto cleanup; }
    carrier_fsync_parent(output_db_path); rc = 0;
cleanup:
    if (verify_fd >= 0) close(verify_fd);
    if (ofd >= 0) close(ofd);
    if (rc != 0 && tmp) unlink(tmp);
    free(tmp);
    if (payload) { sodium_memzero((void *)payload, (size_t)payload_len); sodium_free((void *)payload); }
    if (created) jpeg_destroy_decompress(&src);
    if (fp) fclose(fp);
    if (cfd >= 0) close(cfd);
    sodium_memzero(seed, sizeof(seed)); sodium_memzero(expected_hash, sizeof(expected_hash)); sodium_memzero(actual_hash, sizeof(actual_hash));
    return rc;
}

typedef struct {
    unsigned version;
    uint64_t tag_size;
    uint64_t frame_header_off;
    uint64_t frame_data_off;
    uint64_t frame_data_len;
    uint64_t image_off;
    uint64_t image_len;
    uint64_t mime_start;
    uint64_t mime_end;
    gboolean image_is_jpeg;
    gboolean image_is_png;
} stego_mp3_apic_t;

static gboolean id3_synchsafe_decode4(const unsigned char p[4], uint32_t *out) {
    if ((p[0] | p[1] | p[2] | p[3]) & 0x80U) return FALSE;
    *out = ((uint32_t)p[0] << 21) | ((uint32_t)p[1] << 14) | ((uint32_t)p[2] << 7) | p[3];
    return TRUE;
}

static void id3_synchsafe_encode4(unsigned char p[4], uint32_t v) {
    p[0] = (unsigned char)((v >> 21) & 0x7F); p[1] = (unsigned char)((v >> 14) & 0x7F);
    p[2] = (unsigned char)((v >> 7) & 0x7F); p[3] = (unsigned char)(v & 0x7F);
}

static uint32_t load_u32be_local(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void store_u32be_local(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16); p[2] = (unsigned char)(v >> 8); p[3] = (unsigned char)v;
}

static gboolean id3_frame_id_ok(const unsigned char *p) {
    for (int i = 0; i < 4; i++) if (!((p[i] >= 'A' && p[i] <= 'Z') || (p[i] >= '0' && p[i] <= '9'))) return FALSE;
    return TRUE;
}

static gboolean stego_mp3_find_apic(const unsigned char *tag, size_t tag_total,
    stego_mp3_apic_t *out, gboolean *out_absent, char *err_msg, size_t err_msg_sz)
{
    if (out_absent) *out_absent = FALSE;
    if (!tag || tag_total < 10 || !out || memcmp(tag, "ID3", 3) != 0) return FALSE;
    unsigned ver = tag[3];
    if (ver != 3 && ver != 4) { snprintf(err_msg, err_msg_sz, "MP3 steganography supports ID3v2.3 and ID3v2.4 tags"); return FALSE; }
    if (tag[5] & 0x80U) { snprintf(err_msg, err_msg_sz, "ID3 tag-wide unsynchronisation is not supported for safe APIC rewriting"); return FALSE; }
    if (tag[5] & 0x40U) { snprintf(err_msg, err_msg_sz, "ID3 extended headers are not supported for MP3 steganography"); return FALSE; }
    if (ver == 4 && (tag[5] & 0x10U)) { snprintf(err_msg, err_msg_sz, "ID3v2.4 footer tags are not supported for MP3 steganography"); return FALSE; }
    uint32_t tag_size32 = 0;
    if (!id3_synchsafe_decode4(tag + 6, &tag_size32) || (uint64_t)tag_size32 + 10U > tag_total) {
        snprintf(err_msg, err_msg_sz, "Malformed ID3 tag size"); return FALSE;
    }
    size_t limit = 10U + (size_t)tag_size32;
    size_t pos = 10;
    while (pos + 10 <= limit) {
        if (tag[pos] == 0 && tag[pos+1] == 0 && tag[pos+2] == 0 && tag[pos+3] == 0) break;
        if (!id3_frame_id_ok(tag + pos)) break;
        uint32_t frame_size = 0;
        if (ver == 4) {
            if (!id3_synchsafe_decode4(tag + pos + 4, &frame_size)) { snprintf(err_msg, err_msg_sz, "Malformed ID3v2.4 frame size"); return FALSE; }
        } else frame_size = load_u32be_local(tag + pos + 4);
        if ((uint64_t)pos + 10U + frame_size > limit) { snprintf(err_msg, err_msg_sz, "ID3 frame exceeds tag boundary"); return FALSE; }
        if (memcmp(tag + pos, "APIC", 4) == 0) {
            unsigned f2 = tag[pos + 9];
            if ((ver == 3 && (f2 & 0xE0U)) || (ver == 4 && (f2 & 0x4FU))) {
                snprintf(err_msg, err_msg_sz, "Compressed/encrypted/unsynchronised APIC frames are not supported"); return FALSE;
            }
            size_t d = pos + 10;
            size_t end = d + frame_size;
            if (frame_size < 8 || d >= end) { snprintf(err_msg, err_msg_sz, "APIC frame is too short"); return FALSE; }
            unsigned enc = tag[d];
            size_t mime_start = d + 1, mime_end = mime_start;
            while (mime_end < end && tag[mime_end] != 0) mime_end++;
            if (mime_end >= end || mime_end + 2 >= end) { snprintf(err_msg, err_msg_sz, "Malformed APIC MIME field"); return FALSE; }
            size_t desc = mime_end + 2;
            if (enc == 0 || enc == 3) {
                while (desc < end && tag[desc] != 0) desc++;
                if (desc >= end) { snprintf(err_msg, err_msg_sz, "Malformed APIC description"); return FALSE; }
                desc++;
            } else if (enc == 1 || enc == 2) {
                while (desc + 1 < end && !(tag[desc] == 0 && tag[desc+1] == 0)) desc += 2;
                if (desc + 1 >= end) { snprintf(err_msg, err_msg_sz, "Malformed UTF-16 APIC description"); return FALSE; }
                desc += 2;
            } else { snprintf(err_msg, err_msg_sz, "Unsupported APIC text encoding"); return FALSE; }
            if (desc >= end) { snprintf(err_msg, err_msg_sz, "APIC frame has no image data"); return FALSE; }
            gboolean jpeg = end - desc >= 3 && tag[desc] == 0xFF && tag[desc+1] == 0xD8 && tag[desc+2] == 0xFF;
            static const unsigned char pngsig[8] = {0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A};
            gboolean png = end - desc >= 8 && memcmp(tag + desc, pngsig, 8) == 0;
            if (!jpeg && !png) { snprintf(err_msg, err_msg_sz, "MP3 APIC cover must be JPEG or PNG"); return FALSE; }
            memset(out, 0, sizeof(*out)); out->version = ver; out->tag_size = tag_size32;
            out->frame_header_off = pos; out->frame_data_off = d; out->frame_data_len = frame_size;
            out->image_off = desc; out->image_len = end - desc; out->mime_start = mime_start; out->mime_end = mime_end;
            out->image_is_jpeg = jpeg; out->image_is_png = png; return TRUE;
        }
        pos += 10U + frame_size;
    }
    if (out_absent) *out_absent = TRUE;
    snprintf(err_msg, err_msg_sz, "MP3 has no usable ID3 APIC cover image");
    return FALSE;
}

static GdkPixbuf *stego_pixbuf_from_memory(const unsigned char *data, size_t len,
    char *err_msg, size_t err_msg_sz)
{
    if (!stego_memory_image_dimensions_safe(data, len, err_msg, err_msg_sz)) return NULL;
    GdkPixbufLoader *loader = gdk_pixbuf_loader_new();
    if (!loader) { snprintf(err_msg, err_msg_sz, "Cannot create image decoder"); return NULL; }
    GError *e = NULL;
    if (!gdk_pixbuf_loader_write(loader, data, len, &e) || !gdk_pixbuf_loader_close(loader, &e)) {
        snprintf(err_msg, err_msg_sz, "Cannot decode cover art: %s", e && e->message ? e->message : "decode error");
        g_clear_error(&e); g_object_unref(loader); return NULL;
    }
    GdkPixbuf *pb = gdk_pixbuf_loader_get_pixbuf(loader);
    if (pb) g_object_ref(pb);
    g_object_unref(loader);
    if (!pb) snprintf(err_msg, err_msg_sz, "Cover art did not decode to pixels");
    return pb;
}

static GdkPixbuf *stego_pixbuf_scale_for_payload(GdkPixbuf *pb, uint64_t payload_bytes,
    char *err_msg, size_t err_msg_sz)
{
    uint64_t slots = 0;
    if (!stego_pixbuf_layout(pb, &slots, err_msg, err_msg_sz)) return NULL;
    uint64_t need_bits = (payload_bytes + STEGO_HEADER_BYTES) * 8U;
    if (slots >= need_bits) return g_object_ref(pb);
    if (g_strcmp0(g_getenv("DISKPASS_STEGO_NO_UPSCALE"), "1") == 0) {
        snprintf(err_msg, err_msg_sz, "Cover is too small and automatic enlargement is disabled");
        return NULL;
    }
    int w = gdk_pixbuf_get_width(pb), h = gdk_pixbuf_get_height(pb);
    long double factor = sqrtl((long double)need_bits / (long double)slots) * 1.04L;
    long double nwl = ceill((long double)w * factor);
    long double nhl = ceill((long double)h * factor);
    if (nwl < 1.0L || nhl < 1.0L || nwl > (long double)G_MAXINT || nhl > (long double)G_MAXINT ||
        nwl * nhl > (long double)STEGO_MAX_PIXELS) {
        snprintf(err_msg, err_msg_sz, "Cover would need unsafe dimensions to hold this database"); return NULL;
    }
    int nw = (int)nwl, nh = (int)nhl;
    GdkPixbuf *scaled = gdk_pixbuf_scale_simple(pb, nw, nh, GDK_INTERP_BILINEAR);
    if (!scaled) snprintf(err_msg, err_msg_sz, "Cannot enlarge cover for steganography");
    return scaled;
}

static GdkPixbuf *stego_pixbuf_new_for_payload(uint64_t payload_bytes,
    char *err_msg, size_t err_msg_sz)
{
    unsigned percent = 100;
    if (!stego_embedding_percent(&percent, err_msg, err_msg_sz)) return NULL;
    if (payload_bytes > UINT64_MAX - STEGO_HEADER_BYTES) {
        snprintf(err_msg, err_msg_sz, "Database is too large for an MP3 cover");
        return NULL;
    }
    uint64_t total_bytes = payload_bytes + STEGO_HEADER_BYTES;
    if (total_bytes > UINT64_MAX / 8U) {
        snprintf(err_msg, err_msg_sz, "Database is too large for an MP3 cover");
        return NULL;
    }
    uint64_t need_bits = total_bytes * 8U;
    long double slots_ld = ceill((long double)need_bits * 100.0L / (long double)percent);
    if (slots_ld < 1.0L || slots_ld > (long double)UINT64_MAX) {
        snprintf(err_msg, err_msg_sz, "Database is too large for an MP3 cover");
        return NULL;
    }
    uint64_t need_slots = (uint64_t)slots_ld;
    uint64_t need_pixels = need_slots / 3U + (need_slots % 3U != 0);
    if (need_pixels == 0 || need_pixels > STEGO_MAX_PIXELS) {
        uint64_t max_bits = ((STEGO_MAX_PIXELS * 3U) / 100U) * percent +
            (((STEGO_MAX_PIXELS * 3U) % 100U) * percent) / 100U;
        uint64_t max_bytes = max_bits / 8U;
        if (max_bytes > STEGO_HEADER_BYTES) max_bytes -= STEGO_HEADER_BYTES;
        else max_bytes = 0;
        snprintf(err_msg, err_msg_sz,
            "Database is too large for an automatically generated MP3 cover; safe limit is about %.2f MiB",
            (double)max_bytes / (1024.0 * 1024.0));
        return NULL;
    }
    uint64_t width = (uint64_t)ceill(sqrtl((long double)need_pixels));
    if (width == 0 || width > (uint64_t)G_MAXINT) {
        snprintf(err_msg, err_msg_sz, "Cannot calculate MP3 cover dimensions");
        return NULL;
    }
    uint64_t height = need_pixels / width + (need_pixels % width != 0);
    if (height == 0 || height > (uint64_t)G_MAXINT ||
        width > UINT64_MAX / height || width * height > STEGO_MAX_PIXELS) {
        snprintf(err_msg, err_msg_sz, "Cannot calculate safe MP3 cover dimensions");
        return NULL;
    }
    GdkPixbuf *pb = gdk_pixbuf_new(GDK_COLORSPACE_RGB, FALSE, 8, (int)width, (int)height);
    if (!pb) {
        snprintf(err_msg, err_msg_sz, "Cannot allocate generated MP3 cover");
        return NULL;
    }
    gdk_pixbuf_fill(pb, 0x808080FFU);
    return pb;
}

static int stego_pixbuf_embed_db(GdkPixbuf *pb, int dfd, uint64_t db_size,
    char **out_png, gsize *out_png_len, char *err_msg, size_t err_msg_sz)
{
    uint64_t slots = 0; unsigned char seed[STEGO_SEED_BYTES], ph[STEGO_HASH_BYTES];
    unsigned char header[STEGO_HEADER_BYTES], mask[STEGO_HEADER_BYTES], check[STEGO_CHECK_BYTES];
    int rc = -1; GError *e = NULL;
    if (!stego_pixbuf_layout(pb, &slots, err_msg, err_msg_sz) || !stego_seed_from_pixbuf(pb, seed, err_msg, err_msg_sz)) goto done;
    if (!stego_embedding_budget(slots, db_size, err_msg, err_msg_sz)) goto done;
    uint64_t cap = slots / 8U;
    if (cap < STEGO_HEADER_BYTES || db_size > cap - STEGO_HEADER_BYTES) { snprintf(err_msg, err_msg_sz, "Cover image is too small after scaling"); goto done; }
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
        if (has_payload) { snprintf(err_msg, err_msg_sz, "Cover already contains a DiskPass payload"); goto done; }
    }
    if (stego_hash_fd(dfd, db_size, ph, err_msg, err_msg_sz) != 0) goto done;
    memset(header, 0, sizeof(header)); db_store_u64le(header, db_size); memcpy(header+8, ph, STEGO_HASH_BYTES); header[40]=STEGO_IMAGE_VERSION;
    randombytes_buf(header+41, 15); stego_header_check(seed, header, check); memcpy(header+STEGO_HEADER_BYTES-STEGO_CHECK_BYTES, check, STEGO_CHECK_BYTES);
    stego_header_mask(seed, mask); for (size_t i=0;i<sizeof(header);i++) header[i]^=mask[i];
    stego_iter_t it; stego_iter_init(&it, slots, seed); stego_write_bytes(pb, &it, header, sizeof(header));
    unsigned char buf[128*1024]; uint64_t off=0;
    while (off<db_size) {
        size_t want=sizeof(buf); if (db_size-off<want) want=(size_t)(db_size-off);
        ssize_t n=pread(dfd,buf,want,(off_t)off); if(n<0&&errno==EINTR)continue;
        if(n<=0){snprintf(err_msg,err_msg_sz,"Cannot read database for cover steganography");sodium_memzero(buf,sizeof(buf));goto done;}
        stego_write_bytes(pb,&it,buf,(size_t)n); off+=(uint64_t)n;
    }
    sodium_memzero(buf,sizeof(buf));
    if (!gdk_pixbuf_save_to_buffer(pb, out_png, out_png_len, "png", &e, "compression", "9", NULL)) {
        snprintf(err_msg, err_msg_sz, "Cannot encode stego cover PNG: %s", e&&e->message?e->message:"encode error"); g_clear_error(&e); goto done;
    }
    if (!*out_png || *out_png_len == 0 || (uint64_t)*out_png_len > STEGO_MP3_MAX_COVER_BYTES) {
        if (*out_png) { sodium_memzero(*out_png, *out_png_len); g_free(*out_png); *out_png = NULL; }
        *out_png_len = 0;
        snprintf(err_msg, err_msg_sz, "Encoded stego cover exceeds the safety limit");
        goto done;
    }
    rc=0;
done:
    sodium_memzero(seed,sizeof(seed)); sodium_memzero(ph,sizeof(ph)); sodium_memzero(header,sizeof(header)); sodium_memzero(mask,sizeof(mask)); sodium_memzero(check,sizeof(check));
    return rc;
}

static int stego_pixbuf_extract_db(GdkPixbuf *pb, const char *output_db_path,
    char *err_msg, size_t err_msg_sz)
{
    uint64_t slots=0,payload_len=0; unsigned char seed[STEGO_SEED_BYTES], expected[STEGO_HASH_BYTES], actual[STEGO_HASH_BYTES];
    stego_iter_t it; char *tmp=NULL; int ofd=-1,vfd=-1,rc=-1; crypto_generichash_state hs;
    sodium_memzero(&hs, sizeof(hs));
    if (!stego_pixbuf_layout(pb,&slots,err_msg,err_msg_sz)||!stego_seed_from_pixbuf(pb,seed,err_msg,err_msg_sz)) goto done;
    gboolean found = stego_decode_header(pb,slots,seed,STEGO_IMAGE_VERSION,&payload_len,expected,&it);
    if (!found) {
        unsigned char legacy_seed[STEGO_SEED_BYTES];
        if (stego_seed_from_pixbuf_legacy(pb,legacy_seed,err_msg,err_msg_sz)) {
            found = stego_decode_header(pb,slots,legacy_seed,STEGO_IMAGE_LEGACY_VERSION,&payload_len,expected,&it);
            if (found) memcpy(seed, legacy_seed, sizeof(seed));
        }
        sodium_memzero(legacy_seed, sizeof(legacy_seed));
    }
    if (!found) { snprintf(err_msg,err_msg_sz,"No valid DiskPass payload was found in the cover"); goto done; }
    if (carrier_create_temp(output_db_path,&tmp,&ofd,err_msg,err_msg_sz)!=0) goto done;
    crypto_generichash_init(&hs,NULL,0,STEGO_HASH_BYTES);
    unsigned char buf[128*1024]; uint64_t left=payload_len;
    while(left){size_t take=sizeof(buf);if(left<take)take=(size_t)left;stego_read_bytes(pb,&it,buf,take);crypto_generichash_update(&hs,buf,take);if(write_all_fd(ofd,buf,take)!=0){snprintf(err_msg,err_msg_sz,"Cannot write extracted database");sodium_memzero(buf,sizeof(buf));goto done;}left-=take;}
    sodium_memzero(buf,sizeof(buf)); crypto_generichash_final(&hs,actual,STEGO_HASH_BYTES);
    if(sodium_memcmp(expected,actual,STEGO_HASH_BYTES)!=0){snprintf(err_msg,err_msg_sz,"Cover payload integrity check failed");goto done;}
    if(fsync(ofd)!=0){snprintf(err_msg,err_msg_sz,"Cannot sync extracted database");goto done;}
    if(close(ofd)!=0){ofd=-1;snprintf(err_msg,err_msg_sz,"Cannot close extracted database: %s",strerror(errno));goto done;}ofd=-1;
    vfd=open(tmp,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(vfd<0||!carrier_dpdb_layout_at_fd(vfd,0,payload_len)){snprintf(err_msg,err_msg_sz,"Extracted cover payload is not a recognized DiskPass .dpdb");goto done;}close(vfd);vfd=-1;
    if(rename(tmp,output_db_path)!=0){snprintf(err_msg,err_msg_sz,"Cannot install extracted database: %s",strerror(errno));goto done;}carrier_fsync_parent(output_db_path);rc=0;
done:
    if (vfd >= 0) close(vfd);
    if (ofd >= 0) close(ofd);
    if (rc != 0 && tmp) unlink(tmp);
    free(tmp);
    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(expected, sizeof(expected));
    sodium_memzero(actual, sizeof(actual));


    sodium_memzero(&hs, sizeof(hs));
    return rc;
}

static int carrier_attach_dpdb_mp3(const char *mp3_path, const char *db_path,
    const char *output_path, char *err_msg, size_t err_msg_sz)
{
    int mfd = -1, dfd = -1, ofd = -1;
    uint64_t msize = 0, db_size = 0, audio_off = 0;
    unsigned char hdr[10] = {0};
    unsigned char *tag = NULL;
    char *tmp = NULL, *png = NULL;
    gsize png_len = 0;
    GdkPixbuf *cover = NULL, *work = NULL;
    int rc = -1;
    size_t tag_total = 0;
    uint32_t tag_size = 0;
    unsigned version = 4;
    gboolean has_id3 = FALSE, apic_found = FALSE, apic_absent = FALSE;
    stego_mp3_apic_t apic;
    memset(&apic, 0, sizeof(apic));

    if (!mp3_path || !db_path || !output_path ||
        !carrier_paths_distinct(mp3_path, output_path) ||
        !carrier_paths_distinct(db_path, output_path)) {
        snprintf(err_msg, err_msg_sz, "Output MP3 must be different from source and database");
        return -1;
    }
    if (!(g_str_has_suffix(output_path, ".mp3") || g_str_has_suffix(output_path, ".MP3"))) {
        snprintf(err_msg, err_msg_sz, "MP3 steganography output must use .mp3");
        return -1;
    }
    if (carrier_open_regular(db_path, DB_MAX_FILE_BYTES, &dfd, &db_size, err_msg, err_msg_sz) != 0) goto done;
    if (!db_path_has_dpdb_extension(db_path) || !carrier_dpdb_layout_at_fd(dfd, 0, db_size)) {
        snprintf(err_msg, err_msg_sz, "Only valid DiskPass .dpdb databases can be hidden");
        goto done;
    }
    if (carrier_open_regular(mp3_path, DB_CARRIER_MAX_BYTES, &mfd, &msize, err_msg, err_msg_sz) != 0) goto done;

    if (msize >= sizeof(hdr) && stego_pread_all(mfd, hdr, sizeof(hdr), 0) == 0 && memcmp(hdr, "ID3", 3) == 0) {
        has_id3 = TRUE;
        if (!id3_synchsafe_decode4(hdr + 6, &tag_size) ||
            tag_size > STEGO_MP3_MAX_TAG_BYTES || 10ULL + tag_size > msize) {
            snprintf(err_msg, err_msg_sz, "MP3 ID3 tag is malformed or too large");
            goto done;
        }
        tag_total = 10U + (size_t)tag_size;
        tag = malloc(tag_total);
        if (!tag) {
            snprintf(err_msg, err_msg_sz, "Out of memory for MP3 tag");
            goto done;
        }
        if (stego_pread_all(mfd, tag, tag_total, 0) != 0) {
            snprintf(err_msg, err_msg_sz, "Cannot read complete MP3 ID3 tag");
            goto done;
        }
        audio_off = tag_total;
        if (!stego_mp3_audio_at_fd(mfd, audio_off, msize)) {
            snprintf(err_msg, err_msg_sz, "MP3 has no valid MPEG Layer III audio frame after ID3");
            goto done;
        }
        apic_found = stego_mp3_find_apic(tag, tag_total, &apic, &apic_absent, err_msg, err_msg_sz);
        if (!apic_found && !apic_absent) goto done;
        if (!apic_found && apic_absent && err_msg && err_msg_sz) err_msg[0] = '\0';
        version = tag[3];
    } else {
        if (!stego_mp3_audio_at_fd(mfd, 0, msize)) {
            snprintf(err_msg, err_msg_sz, "MP3 has neither a supported ID3 tag nor a valid MPEG Layer III frame at file start");
            goto done;
        }
        audio_off = 0;
        apic_absent = TRUE;
        version = 4;
    }

    if (apic_found) {
        if (apic.image_len > STEGO_MP3_MAX_COVER_BYTES) {
            snprintf(err_msg, err_msg_sz, "MP3 cover art is too large");
            goto done;
        }
        cover = stego_pixbuf_from_memory(tag + apic.image_off, (size_t)apic.image_len, err_msg, err_msg_sz);
        if (!cover) goto done;
        work = stego_pixbuf_scale_for_payload(cover, db_size, err_msg, err_msg_sz);
        if (!work) goto done;
    } else {
        work = stego_pixbuf_new_for_payload(db_size, err_msg, err_msg_sz);
        if (!work) goto done;
    }

    if (stego_pixbuf_embed_db(work, dfd, db_size, &png, &png_len, err_msg, err_msg_sz) != 0) goto done;

    if (apic_found) {
        size_t prefix_desc = (size_t)apic.image_off - (size_t)(apic.mime_end + 1);
        if (png_len > SIZE_MAX - prefix_desc - 1U - sizeof("image/png")) {
            snprintf(err_msg, err_msg_sz, "Stego cover is too large for ID3");
            goto done;
        }
        size_t new_frame_len = 1U + sizeof("image/png") + prefix_desc + png_len;
        if (new_frame_len > 0x0FFFFFFFU) {
            snprintf(err_msg, err_msg_sz, "Stego cover is too large for ID3");
            goto done;
        }
        int64_t delta = (int64_t)new_frame_len - (int64_t)apic.frame_data_len;
        int64_t new_tag_size64 = (int64_t)apic.tag_size + delta;
        if (new_tag_size64 < 0 || new_tag_size64 > 0x0FFFFFFF ||
            (uint64_t)new_tag_size64 > STEGO_MP3_MAX_TAG_BYTES) {
            snprintf(err_msg, err_msg_sz, "Rewritten ID3 tag would exceed DiskPass safety limits");
            goto done;
        }
        if (delta > 0 && (uint64_t)delta > DB_CARRIER_MAX_BYTES - msize) {
            snprintf(err_msg, err_msg_sz, "Stego MP3 would exceed the carrier size limit");
            goto done;
        }
        if (carrier_create_temp(output_path, &tmp, &ofd, err_msg, err_msg_sz) != 0) goto done;

        unsigned char newhdr[10];
        memcpy(newhdr, hdr, sizeof(newhdr));
        id3_synchsafe_encode4(newhdr + 6, (uint32_t)new_tag_size64);
        if (write_all_fd(ofd, newhdr, sizeof(newhdr)) != 0) goto write_fail;

        size_t fh = (size_t)apic.frame_header_off;
        if (fh < 10 || fh > tag_total - 10 || write_all_fd(ofd, tag + 10, fh - 10) != 0) goto write_fail;
        unsigned char framehdr[10];
        memcpy(framehdr, tag + fh, sizeof(framehdr));
        if (apic.version == 4) id3_synchsafe_encode4(framehdr + 4, (uint32_t)new_frame_len);
        else store_u32be_local(framehdr + 4, (uint32_t)new_frame_len);
        if (write_all_fd(ofd, framehdr, sizeof(framehdr)) != 0) goto write_fail;

        unsigned char enc = tag[apic.frame_data_off];
        static const char mime[] = "image/png";
        if (write_all_fd(ofd, &enc, 1) != 0 ||
            write_all_fd(ofd, (const unsigned char *)mime, sizeof(mime)) != 0) goto write_fail;
        size_t desc_start = (size_t)apic.mime_end + 1;
        if (write_all_fd(ofd, tag + desc_start, prefix_desc) != 0 ||
            write_all_fd(ofd, (unsigned char *)png, png_len) != 0) goto write_fail;
        size_t old_frame_end = (size_t)apic.frame_data_off + (size_t)apic.frame_data_len;
        if (old_frame_end > tag_total ||
            write_all_fd(ofd, tag + old_frame_end, tag_total - old_frame_end) != 0) goto write_fail;
    } else {
        static const char mime[] = "image/png";
        if (png_len > SIZE_MAX - 13U) {
            snprintf(err_msg, err_msg_sz, "Generated MP3 cover is too large for ID3");
            goto done;
        }
        size_t frame_data_len = 1U + sizeof(mime) + 1U + 1U + png_len;
        if (frame_data_len > 0x0FFFFFFFU || frame_data_len > UINT32_MAX) {
            snprintf(err_msg, err_msg_sz, "Generated MP3 cover is too large for ID3");
            goto done;
        }
        uint64_t frame_total = 10ULL + (uint64_t)frame_data_len;
        uint64_t old_tag_size = has_id3 ? (uint64_t)tag_size : 0;
        uint64_t new_tag_size = old_tag_size + frame_total;
        if (new_tag_size > 0x0FFFFFFFULL || new_tag_size > STEGO_MP3_MAX_TAG_BYTES) {
            snprintf(err_msg, err_msg_sz, "Generated ID3 tag would exceed DiskPass safety limits");
            goto done;
        }
        uint64_t added = frame_total + (has_id3 ? 0ULL : 10ULL);
        if (added > DB_CARRIER_MAX_BYTES - msize) {
            snprintf(err_msg, err_msg_sz, "Stego MP3 would exceed the carrier size limit");
            goto done;
        }
        if (carrier_create_temp(output_path, &tmp, &ofd, err_msg, err_msg_sz) != 0) goto done;

        unsigned char newhdr[10] = {'I','D','3',4,0,0,0,0,0,0};
        if (has_id3) memcpy(newhdr, hdr, sizeof(newhdr));
        newhdr[3] = (unsigned char)version;
        id3_synchsafe_encode4(newhdr + 6, (uint32_t)new_tag_size);
        if (write_all_fd(ofd, newhdr, sizeof(newhdr)) != 0) goto write_fail;

        unsigned char framehdr[10] = {'A','P','I','C',0,0,0,0,0,0};
        if (version == 4) id3_synchsafe_encode4(framehdr + 4, (uint32_t)frame_data_len);
        else store_u32be_local(framehdr + 4, (uint32_t)frame_data_len);
        if (write_all_fd(ofd, framehdr, sizeof(framehdr)) != 0) goto write_fail;

        unsigned char enc = 0, picture_type = 3, desc_zero = 0;
        if (write_all_fd(ofd, &enc, 1) != 0 ||
            write_all_fd(ofd, (const unsigned char *)mime, sizeof(mime)) != 0 ||
            write_all_fd(ofd, &picture_type, 1) != 0 ||
            write_all_fd(ofd, &desc_zero, 1) != 0 ||
            write_all_fd(ofd, (unsigned char *)png, png_len) != 0) goto write_fail;
        if (has_id3 && write_all_fd(ofd, tag + 10, tag_total - 10) != 0) goto write_fail;
    }

    {
        unsigned char buf[256 * 1024];
        uint64_t off = audio_off;
        while (off < msize) {
            size_t want = sizeof(buf);
            if (msize - off < want) want = (size_t)(msize - off);
            ssize_t n = pread(mfd, buf, want, (off_t)off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0 || write_all_fd(ofd, buf, (size_t)n) != 0) {
                sodium_memzero(buf, sizeof(buf));
                goto write_fail;
            }
            off += (uint64_t)n;
        }
        sodium_memzero(buf, sizeof(buf));
    }

    if (fsync(ofd) != 0) goto write_fail;
    if (close(ofd) != 0) { ofd = -1; goto write_fail; }
    ofd = -1;
    if (rename(tmp, output_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot install stego MP3: %s", strerror(errno));
        goto done;
    }
    carrier_fsync_parent(output_path);
    rc = 0;
    goto done;

write_fail:
    snprintf(err_msg, err_msg_sz, "Cannot write stego MP3: %s", strerror(errno));
done:
    if (ofd >= 0) close(ofd);
    if (rc != 0 && tmp) unlink(tmp);
    free(tmp);
    if (png) { sodium_memzero(png, png_len); g_free(png); }
    if (work) g_object_unref(work);
    if (cover) g_object_unref(cover);
    if (tag) { sodium_memzero(tag, tag_total); free(tag); }
    if (mfd >= 0) close(mfd);
    if (dfd >= 0) close(dfd);
    return rc;
}

static int carrier_extract_dpdb_mp3(const char *mp3_path, const char *output_db_path,
    char *err_msg, size_t err_msg_sz)
{
    int fd=-1;uint64_t size=0;unsigned char hdr[10];unsigned char *tag=NULL;GdkPixbuf *cover=NULL;int rc=-1;size_t tag_total=0;
    if(!mp3_path||!output_db_path||!carrier_paths_distinct(mp3_path,output_db_path)||!db_path_has_dpdb_extension(output_db_path)){snprintf(err_msg,err_msg_sz,"Extracted database must be a separate .dpdb file");return -1;}
    if(carrier_open_regular(mp3_path,DB_CARRIER_MAX_BYTES,&fd,&size,err_msg,err_msg_sz)!=0)goto done;
    if(stego_pread_all(fd,hdr,10,0)!=0||memcmp(hdr,"ID3",3)!=0){snprintf(err_msg,err_msg_sz,"MP3 has no supported ID3 cover tag");goto done;}uint32_t ts=0;if(!id3_synchsafe_decode4(hdr+6,&ts)||ts>STEGO_MP3_MAX_TAG_BYTES||10ULL+ts>size){snprintf(err_msg,err_msg_sz,"Malformed MP3 ID3 tag");goto done;}tag_total=10U+(size_t)ts;tag=malloc(tag_total);if(!tag){snprintf(err_msg,err_msg_sz,"Out of memory for MP3 tag");goto done;}if(stego_pread_all(fd,tag,tag_total,0)!=0){snprintf(err_msg,err_msg_sz,"Cannot read complete MP3 tag");goto done;}if(!stego_mp3_audio_at_fd(fd,tag_total,size)){snprintf(err_msg,err_msg_sz,"MP3 has no valid MPEG Layer III audio frame after ID3");goto done;}stego_mp3_apic_t apic;if(!stego_mp3_find_apic(tag,tag_total,&apic,NULL,err_msg,err_msg_sz))goto done;if(apic.image_len>STEGO_MP3_MAX_COVER_BYTES){snprintf(err_msg,err_msg_sz,"MP3 cover art exceeds the safety limit");goto done;}cover=stego_pixbuf_from_memory(tag+apic.image_off,(size_t)apic.image_len,err_msg,err_msg_sz);if(!cover)goto done;rc=stego_pixbuf_extract_db(cover,output_db_path,err_msg,err_msg_sz);
done: if(cover)g_object_unref(cover);if(tag){sodium_memzero(tag,tag_total);free(tag);}if(fd>=0)close(fd);return rc;
}

#define STEGO_FLAC_MAX_FILE_BYTES DB_CARRIER_MAX_BYTES
#define STEGO_FLAC_MAX_PICTURE_BLOCK 0xFFFFFFU

typedef struct {
    uint64_t header_off;
    uint64_t data_off;
    uint32_t block_len;
    gboolean is_last;
    uint32_t picture_type;
    uint32_t desc_len;
    uint32_t desc_off;
    uint32_t image_off;
    uint32_t image_len;
} stego_flac_picture_t;

static gboolean stego_path_is_flac(const char *path) {
    if (!path) return FALSE;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return FALSE;
    unsigned char h[4];
    gboolean ok = pread(fd, h, sizeof(h), 0) == (ssize_t)sizeof(h) && memcmp(h, "fLaC", 4) == 0;
    close(fd);
    return ok;
}

static uint32_t stego_load_u24be(const unsigned char p[3]) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

static void stego_store_u24be(unsigned char p[3], uint32_t v) {
    p[0] = (unsigned char)(v >> 16); p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)v;
}

static gboolean stego_flac_parse_picture_block(const unsigned char *b, uint32_t len,
    stego_flac_picture_t *pic, char *err_msg, size_t err_msg_sz)
{
    if (!b || !pic || len < 32) return FALSE;
    uint64_t pos = 0;
    uint32_t picture_type = stego_load_u32be(b + pos); pos += 4;
    uint32_t mime_len = stego_load_u32be(b + pos); pos += 4;
    if ((uint64_t)mime_len > len - pos) goto malformed;
    pos += mime_len;
    if (pos + 4 > len) goto malformed;
    uint32_t desc_len = stego_load_u32be(b + pos); pos += 4;
    uint32_t desc_off = (uint32_t)pos;
    if ((uint64_t)desc_len > len - pos) goto malformed;
    pos += desc_len;
    if (pos + 20 > len) goto malformed;
    pos += 16;
    uint32_t image_len = stego_load_u32be(b + pos); pos += 4;
    uint32_t image_off = (uint32_t)pos;
    if (image_len == 0 || (uint64_t)image_len > len - pos || pos + image_len != len) goto malformed;
    pic->picture_type = picture_type;
    pic->desc_len = desc_len;
    pic->desc_off = desc_off;
    pic->image_off = image_off;
    pic->image_len = image_len;
    return TRUE;
malformed:
    snprintf(err_msg, err_msg_sz, "Malformed FLAC PICTURE metadata block");
    return FALSE;
}

static gboolean stego_flac_find_picture(int fd, uint64_t file_size,
    stego_flac_picture_t *out, unsigned char **out_block,
    char *err_msg, size_t err_msg_sz)
{
    if (fd < 0 || file_size < 8 || !out || !out_block) return FALSE;
    unsigned char magic[4];
    if (stego_pread_all(fd, magic, 4, 0) != 0 || memcmp(magic, "fLaC", 4) != 0) {
        snprintf(err_msg, err_msg_sz, "Carrier is not a FLAC file"); return FALSE;
    }
    uint64_t pos = 4;
    for (unsigned blocks = 0; blocks < 256 && pos + 4 <= file_size; blocks++) {
        unsigned char h[4];
        if (stego_pread_all(fd, h, 4, pos) != 0) break;
        gboolean last = (h[0] & 0x80U) != 0;
        unsigned type = h[0] & 0x7FU;
        uint32_t len = stego_load_u24be(h + 1);
        uint64_t data_off = pos + 4;
        if ((uint64_t)len > file_size - data_off) {
            snprintf(err_msg, err_msg_sz, "Malformed FLAC metadata length"); return FALSE;
        }
        if (type == 6U && len > 0) {
            unsigned char *block = malloc(len);
            if (!block) { snprintf(err_msg, err_msg_sz, "Out of memory for FLAC cover metadata"); return FALSE; }
            if (stego_pread_all(fd, block, len, data_off) != 0) {
                free(block); snprintf(err_msg, err_msg_sz, "Cannot read FLAC PICTURE block"); return FALSE;
            }
            stego_flac_picture_t pic = {0};
            if (!stego_flac_parse_picture_block(block, len, &pic, err_msg, err_msg_sz)) {
                sodium_memzero(block, len); free(block); return FALSE;
            }
            pic.header_off = pos; pic.data_off = data_off; pic.block_len = len; pic.is_last = last;
            *out = pic; *out_block = block; return TRUE;
        }
        pos = data_off + len;
        if (last) break;
    }
    snprintf(err_msg, err_msg_sz, "FLAC has no usable PICTURE cover image");
    return FALSE;
}

static int stego_copy_range_fd(int src, int dst, uint64_t off, uint64_t len) {
    unsigned char buf[256 * 1024];
    while (len) {
        size_t want = sizeof(buf); if (len < want) want = (size_t)len;
        ssize_t n = pread(src, buf, want, (off_t)off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || write_all_fd(dst, buf, (size_t)n) != 0) { sodium_memzero(buf, sizeof(buf)); return -1; }
        off += (uint64_t)n; len -= (uint64_t)n;
    }
    sodium_memzero(buf, sizeof(buf)); return 0;
}

static int carrier_attach_dpdb_flac(const char *flac_path, const char *db_path,
    const char *output_path, char *err_msg, size_t err_msg_sz)
{
    int ffd=-1, dfd=-1, ofd=-1, rc=-1; uint64_t fsize=0, db_size=0;
    stego_flac_picture_t pic={0}; unsigned char *block=NULL; GdkPixbuf *cover=NULL,*work=NULL;
    char *png=NULL,*tmp=NULL; gsize png_len=0;
    if(!flac_path||!db_path||!output_path||!carrier_paths_distinct(flac_path,output_path)||!carrier_paths_distinct(db_path,output_path)){
        snprintf(err_msg,err_msg_sz,"Output FLAC must be different from the carrier and database");return -1;}
    if(!stego_output_is_ci(output_path,".flac")){snprintf(err_msg,err_msg_sz,"FLAC steganography output must use .flac");return -1;}
    if(carrier_open_regular(flac_path,STEGO_FLAC_MAX_FILE_BYTES,&ffd,&fsize,err_msg,err_msg_sz)!=0)goto done;
    if(carrier_open_regular(db_path,DB_MAX_FILE_BYTES,&dfd,&db_size,err_msg,err_msg_sz)!=0)goto done;
    if(!db_path_has_dpdb_extension(db_path)||!carrier_dpdb_layout_at_fd(dfd,0,db_size)){snprintf(err_msg,err_msg_sz,"Only valid DiskPass .dpdb databases can be hidden");goto done;}
    if(!stego_flac_find_picture(ffd,fsize,&pic,&block,err_msg,err_msg_sz))goto done;
    if(pic.image_len>STEGO_MP3_MAX_COVER_BYTES){snprintf(err_msg,err_msg_sz,"FLAC cover image exceeds the safety limit");goto done;}
    cover=stego_pixbuf_from_memory(block+pic.image_off,pic.image_len,err_msg,err_msg_sz);if(!cover)goto done;
    work=stego_pixbuf_scale_for_payload(cover,db_size,err_msg,err_msg_sz);if(!work)goto done;
    if(stego_pixbuf_embed_db(work,dfd,db_size,&png,&png_len,err_msg,err_msg_sz)!=0)goto done;
    const char mime[]="image/png"; uint64_t new_len=4ULL+4ULL+(sizeof(mime)-1)+4ULL+pic.desc_len+20ULL+png_len;
    if(new_len>STEGO_FLAC_MAX_PICTURE_BLOCK){snprintf(err_msg,err_msg_sz,"Stego FLAC cover exceeds the 16 MiB metadata-block limit");goto done;}
    if(carrier_create_temp(output_path,&tmp,&ofd,err_msg,err_msg_sz)!=0)goto done;
    if(stego_copy_range_fd(ffd,ofd,0,pic.header_off)!=0)goto write_fail;
    unsigned char bh[4]; bh[0]=(unsigned char)((pic.is_last?0x80U:0U)|6U); stego_store_u24be(bh+1,(uint32_t)new_len);
    if(write_all_fd(ofd,bh,4)!=0)goto write_fail;
    unsigned char u32[4];
    store_u32be_local(u32,pic.picture_type);if(write_all_fd(ofd,u32,4)!=0)goto write_fail;
    store_u32be_local(u32,(uint32_t)(sizeof(mime)-1));if(write_all_fd(ofd,u32,4)!=0||write_all_fd(ofd,(const unsigned char*)mime,sizeof(mime)-1)!=0)goto write_fail;
    store_u32be_local(u32,pic.desc_len);if(write_all_fd(ofd,u32,4)!=0)goto write_fail;
    if(pic.desc_len&&write_all_fd(ofd,block+pic.desc_off,pic.desc_len)!=0)goto write_fail;
    store_u32be_local(u32,(uint32_t)gdk_pixbuf_get_width(work));if(write_all_fd(ofd,u32,4)!=0)goto write_fail;
    store_u32be_local(u32,(uint32_t)gdk_pixbuf_get_height(work));if(write_all_fd(ofd,u32,4)!=0)goto write_fail;
    store_u32be_local(u32,gdk_pixbuf_get_has_alpha(work)?32U:24U);if(write_all_fd(ofd,u32,4)!=0)goto write_fail;
    memset(u32,0,4);if(write_all_fd(ofd,u32,4)!=0)goto write_fail;
    store_u32be_local(u32,(uint32_t)png_len);if(write_all_fd(ofd,u32,4)!=0||write_all_fd(ofd,(unsigned char*)png,png_len)!=0)goto write_fail;
    uint64_t old_end=pic.data_off+pic.block_len;
    if(stego_copy_range_fd(ffd,ofd,old_end,fsize-old_end)!=0)goto write_fail;
    if (fsync(ofd) != 0) goto write_fail;
    if (close(ofd) != 0) { ofd = -1; goto write_fail; }
    ofd = -1;
    if (rename(tmp, output_path) != 0) {
        snprintf(err_msg, err_msg_sz, "Cannot install stego FLAC: %s", strerror(errno));
        goto done;
    }
    carrier_fsync_parent(output_path); rc = 0; goto done;
write_fail:
    snprintf(err_msg, err_msg_sz, "Cannot write stego FLAC: %s", strerror(errno));
done:
    if (ofd >= 0) close(ofd);
    if (rc != 0 && tmp) unlink(tmp);
    free(tmp);
    if (png) { sodium_memzero(png, png_len); g_free(png); }
    if (work) g_object_unref(work);
    if (cover) g_object_unref(cover);
    if (block) { sodium_memzero(block, pic.block_len); free(block); }
    if (ffd >= 0) close(ffd);
    if (dfd >= 0) close(dfd);
    return rc;
}

static int carrier_extract_dpdb_flac(const char *flac_path,const char *output_db_path,
    char *err_msg,size_t err_msg_sz)
{
    int fd=-1,rc=-1;uint64_t size=0;stego_flac_picture_t pic={0};unsigned char *block=NULL;GdkPixbuf *cover=NULL;
    if(!flac_path||!output_db_path||!carrier_paths_distinct(flac_path,output_db_path)||!db_path_has_dpdb_extension(output_db_path)){
        snprintf(err_msg,err_msg_sz,"Extracted database must be a separate .dpdb file");return -1;}
    if(carrier_open_regular(flac_path,STEGO_FLAC_MAX_FILE_BYTES,&fd,&size,err_msg,err_msg_sz)!=0)goto done;
    if(!stego_flac_find_picture(fd,size,&pic,&block,err_msg,err_msg_sz))goto done;
    cover=stego_pixbuf_from_memory(block+pic.image_off,pic.image_len,err_msg,err_msg_sz);if(!cover)goto done;
    rc=stego_pixbuf_extract_db(cover,output_db_path,err_msg,err_msg_sz);
done: if(cover)g_object_unref(cover);if(block){sodium_memzero(block,pic.block_len);free(block);}if(fd>=0)close(fd);return rc;
}

typedef enum {
    CARRIER_KIND_UNKNOWN=0,CARRIER_KIND_JPEG,CARRIER_KIND_MP3,CARRIER_KIND_FLAC,
    CARRIER_KIND_WAV,CARRIER_KIND_IMAGE
} carrier_kind_t;

static carrier_kind_t carrier_detect_kind(const char *path) {
    if(stego_path_is_mp3(path))return CARRIER_KIND_MP3;
    if(stego_path_is_flac(path))return CARRIER_KIND_FLAC;
    if(stego_path_is_jpeg(path))return CARRIER_KIND_JPEG;
    if(stego_path_is_wav(path))return CARRIER_KIND_WAV;
    if (stego_path_is_decodable_image(path)) return CARRIER_KIND_IMAGE;
    return CARRIER_KIND_UNKNOWN;
}

static int carrier_attach_dpdb(const char *carrier_path, const char *db_path,
    const char *output_path, char *err_msg, size_t err_msg_sz)
{
    if (stego_path_is_mp3(carrier_path)) return carrier_attach_dpdb_mp3(carrier_path, db_path, output_path, err_msg, err_msg_sz);
    if (stego_path_is_flac(carrier_path)) return carrier_attach_dpdb_flac(carrier_path, db_path, output_path, err_msg, err_msg_sz);
    if (stego_path_is_jpeg(carrier_path)) return carrier_attach_dpdb_jpeg(carrier_path, db_path, output_path, err_msg, err_msg_sz);
    return carrier_attach_dpdb_base(carrier_path, db_path, output_path, err_msg, err_msg_sz);
}

static int carrier_extract_dpdb(const char *carrier_path, const char *output_db_path,
    char *err_msg, size_t err_msg_sz)
{
    if (stego_path_is_mp3(carrier_path)) return carrier_extract_dpdb_mp3(carrier_path, output_db_path, err_msg, err_msg_sz);
    if (stego_path_is_flac(carrier_path)) return carrier_extract_dpdb_flac(carrier_path, output_db_path, err_msg, err_msg_sz);
    if (stego_path_is_jpeg(carrier_path)) return carrier_extract_dpdb_jpeg(carrier_path, output_db_path, err_msg, err_msg_sz);
    return carrier_extract_dpdb_base(carrier_path, output_db_path, err_msg, err_msg_sz);
}
