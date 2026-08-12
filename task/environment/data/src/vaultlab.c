/*
 * vaultlab - RingVault CTF challenge binary
 * Protocol: length-prefixed binary frames on stdin/stdout.
 * Each frame: 4-byte big-endian length followed by body bytes.
 * Body consists of TLV records: 1-byte type, 2-byte big-endian length, value.
 * The binary loops reading one frame, processing one gate step, writing one
 * reply frame, until the script is exhausted or stdin closes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#define TYPE_AUTH   0x01
#define TYPE_NOTE   0x02
#define TYPE_NEST   0x03
#define TYPE_CLAIM  0x04
#define TYPE_REPLY  0x05
#define TYPE_TICKET 0x06
#define TYPE_CONTINUE 0x07

#define EVT_TICK        1
#define EVT_REINCARNATE 2
#define EVT_TICKET      3
#define EVT_CLAIM       4

#define MAX_FRAME   65536
#define MAX_NONCES  16
#define MAX_SCRIPT  64
#define MAX_FLAG    256
#define SHA256_BLOCK 64
#define SHA256_DIGEST 32

/* ---- embedded schedules keyed by challenge_id ---- */

/* Event codes: 1=tick 2=reincarnate 3=ticket 4=claim */
static const int sa[] = {3, 4};
static const int sb[] = {2, 3, 2, 3, 4};
static const int sg[] = {3, 1, 4};
static const int s_bravo[]   = {1, 3, 2, 3, 1, 4};
static const int s_charlie[] = {2, 1, 3, 2, 3, 1, 4};
static const int s_delta[]   = {1, 2, 3, 1, 2, 3, 1, 4};
static const int s_echo[]    = {1, 2, 3, 2, 1, 3, 1, 4};
static const int s_foxtrot[] = {1, 1, 2, 3, 2, 3, 1, 4};

typedef struct {
    const char *id;
    const int *events;
    int count;
} sched_entry;

static const sched_entry SCHEDULES[] = {
    {"alpha",   sa, 2},
    {"beta",    sb, 5},
    {"gamma",   sg, 3},
    {"bravo",   s_bravo,   6},
    {"charlie", s_charlie, 7},
    {"delta",   s_delta,   8},
    {"echo",    s_echo,    8},
    {"foxtrot", s_foxtrot, 8},
    {NULL, NULL, 0}
};

/* ---- minimal SHA-256 implementation ---- */

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint32_t state[8];
    uint8_t buf[64];
    uint64_t count;
} sha256_ctx;

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(sha256_ctx *ctx) {
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)ctx->buf[i*4] << 24) |
                ((uint32_t)ctx->buf[i*4+1] << 16) |
                ((uint32_t)ctx->buf[i*4+2] << 8) |
                ((uint32_t)ctx->buf[i*4+3]);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
    ctx->count = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buf[ctx->count % 64] = data[i];
        ctx->count++;
        if (ctx->count % 64 == 0) sha256_transform(ctx);
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
    uint64_t bits = ctx->count * 8;
    uint8_t pad = 0x80;
    sha256_update(ctx, &pad, 1);
    pad = 0;
    while (ctx->count % 64 != 56)
        sha256_update(ctx, &pad, 1);
    uint8_t len_be[8];
    for (int i = 0; i < 8; i++)
        len_be[i] = (uint8_t)(bits >> (56 - i*8));
    sha256_update(ctx, len_be, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(ctx->state[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
        out[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/* ---- hex utility ---- */

static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_out) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_out) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        unsigned int hi, lo;
        char ch = hex[i*2];
        if (ch >= '0' && ch <= '9') hi = ch - '0';
        else if (ch >= 'a' && ch <= 'f') hi = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') hi = ch - 'A' + 10;
        else return -1;
        ch = hex[i*2+1];
        if (ch >= '0' && ch <= '9') lo = ch - '0';
        else if (ch >= 'a' && ch <= 'f') lo = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') lo = ch - 'A' + 10;
        else return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(len / 2);
}

static void bytes_to_hex(const uint8_t *data, size_t len, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hx[(data[i] >> 4) & 0x0f];
        out[i*2+1] = hx[data[i] & 0x0f];
    }
    out[len*2] = '\0';
}

/* ---- simple JSON parser (just enough for case.json) ---- */

typedef struct {
    const char *data;
    size_t pos;
    size_t len;
} jparser;

static void jp_skip_ws(jparser *j) {
    while (j->pos < j->len) {
        char c = j->data[j->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') j->pos++;
        else break;
    }
}

static int jp_expect(jparser *j, char c) {
    jp_skip_ws(j);
    if (j->pos < j->len && j->data[j->pos] == c) { j->pos++; return 1; }
    return 0;
}

static int jp_read_string(jparser *j, char *buf, size_t bufsz) {
    jp_skip_ws(j);
    if (j->pos >= j->len || j->data[j->pos] != '"') return -1;
    j->pos++;
    size_t out = 0;
    while (j->pos < j->len && j->data[j->pos] != '"') {
        if (j->data[j->pos] == '\\') {
            j->pos++;
            if (j->pos >= j->len) return -1;
        }
        if (out < bufsz - 1) buf[out++] = j->data[j->pos];
        j->pos++;
    }
    if (j->pos >= j->len) return -1;
    j->pos++;
    buf[out] = '\0';
    return (int)out;
}

static long jp_read_int(jparser *j) {
    jp_skip_ws(j);
    long val = 0;
    int neg = 0;
    if (j->pos < j->len && j->data[j->pos] == '-') { neg = 1; j->pos++; }
    while (j->pos < j->len && j->data[j->pos] >= '0' && j->data[j->pos] <= '9') {
        val = val * 10 + (j->data[j->pos] - '0');
        j->pos++;
    }
    return neg ? -val : val;
}

/* ---- case state ---- */

typedef struct {
    int slot;
    int gen;
    int nest_required;
    uint8_t key[32];
    char scope[128];
    char nonces[MAX_NONCES][128];
    int nonce_count;
    int nonce_idx;
    uint8_t vault_blob[MAX_FLAG];
    int vault_blob_len;
    char decoy_flag[MAX_FLAG];
    int script[MAX_SCRIPT];
    int script_count;
    int script_pos;
    uint8_t ticket[16];
    int has_ticket;
    char phase[16];
    int locked;
    char challenge_id[64];
} case_state;

static int load_case(const char *case_dir, case_state *st) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/case.json", case_dir);
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return -1; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *json = malloc(fsize + 1);
    if (!json) { fclose(f); return -1; }
    if (fread(json, 1, fsize, f) != (size_t)fsize) {
        free(json); fclose(f); return -1;
    }
    json[fsize] = '\0';
    fclose(f);

    memset(st, 0, sizeof(*st));
    strcpy(st->phase, "run");

    jparser jp = { json, 0, (size_t)fsize };
    jp_expect(&jp, '{');

    char key[128], val[4096];
    while (1) {
        jp_skip_ws(&jp);
        if (jp.pos >= jp.len) break;
        if (jp.data[jp.pos] == '}') break;
        if (jp.data[jp.pos] == ',') { jp.pos++; continue; }

        if (jp_read_string(&jp, key, sizeof(key)) < 0) break;
        jp_expect(&jp, ':');

        if (strcmp(key, "slot") == 0) {
            st->slot = (int)jp_read_int(&jp);
        } else if (strcmp(key, "gen") == 0) {
            st->gen = (int)jp_read_int(&jp);
        } else if (strcmp(key, "nest_required") == 0) {
            st->nest_required = (int)jp_read_int(&jp);
        } else if (strcmp(key, "key_hex") == 0) {
            jp_read_string(&jp, val, sizeof(val));
            hex_to_bytes(val, st->key, 32);
        } else if (strcmp(key, "scope") == 0) {
            jp_read_string(&jp, st->scope, sizeof(st->scope));
        } else if (strcmp(key, "decoy_flag") == 0) {
            jp_read_string(&jp, st->decoy_flag, sizeof(st->decoy_flag));
        } else if (strcmp(key, "vault_blob_hex") == 0) {
            jp_read_string(&jp, val, sizeof(val));
            st->vault_blob_len = hex_to_bytes(val, st->vault_blob, MAX_FLAG);
        } else if (strcmp(key, "nonces") == 0) {
            jp_expect(&jp, '[');
            st->nonce_count = 0;
            while (1) {
                jp_skip_ws(&jp);
                if (jp.pos >= jp.len || jp.data[jp.pos] == ']') break;
                if (jp.data[jp.pos] == ',') { jp.pos++; continue; }
                jp_read_string(&jp, st->nonces[st->nonce_count], 128);
                st->nonce_count++;
            }
            jp_expect(&jp, ']');
        } else if (strcmp(key, "challenge_id") == 0) {
            jp_read_string(&jp, st->challenge_id, sizeof(st->challenge_id));
        } else {
            jp_skip_ws(&jp);
            if (jp.pos < jp.len && jp.data[jp.pos] == '"') {
                jp_read_string(&jp, val, sizeof(val));
            } else if (jp.pos < jp.len && jp.data[jp.pos] == '[') {
                int depth = 1; jp.pos++;
                while (jp.pos < jp.len && depth > 0) {
                    if (jp.data[jp.pos] == '[') depth++;
                    else if (jp.data[jp.pos] == ']') depth--;
                    jp.pos++;
                }
            } else if (jp.pos < jp.len && jp.data[jp.pos] == '{') {
                int depth = 1; jp.pos++;
                while (jp.pos < jp.len && depth > 0) {
                    if (jp.data[jp.pos] == '{') depth++;
                    else if (jp.data[jp.pos] == '}') depth--;
                    jp.pos++;
                }
            } else {
                while (jp.pos < jp.len && jp.data[jp.pos] != ',' && jp.data[jp.pos] != '}')
                    jp.pos++;
            }
        }
    }
    free(json);

    int found = 0;
    for (int i = 0; SCHEDULES[i].id != NULL; i++) {
        if (strcmp(st->challenge_id, SCHEDULES[i].id) == 0) {
            st->script_count = SCHEDULES[i].count;
            for (int j = 0; j < SCHEDULES[i].count; j++)
                st->script[j] = SCHEDULES[i].events[j];
            found = 1;
            break;
        }
    }
    if (!found) { fprintf(stderr, "unknown challenge\n"); return -1; }
    return 0;
}

/* ---- protocol framing ---- */

static int read_frame(uint8_t *buf, size_t bufsz, size_t *out_len) {
    uint8_t hdr[4];
    if (fread(hdr, 1, 4, stdin) != 4) return -1;
    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
    if (len > bufsz) return -1;
    if (len > 0 && fread(buf, 1, len, stdin) != len) return -1;
    *out_len = len;
    return 0;
}

static void write_frame(const uint8_t *body, size_t len) {
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(len >> 24);
    hdr[1] = (uint8_t)(len >> 16);
    hdr[2] = (uint8_t)(len >> 8);
    hdr[3] = (uint8_t)(len);
    fwrite(hdr, 1, 4, stdout);
    if (len > 0) fwrite(body, 1, len, stdout);
    fflush(stdout);
}

static size_t encode_tlv(uint8_t *buf, uint8_t typ, const uint8_t *val, size_t vlen) {
    buf[0] = typ;
    buf[1] = (uint8_t)(vlen >> 8);
    buf[2] = (uint8_t)(vlen & 0xff);
    memcpy(buf + 3, val, vlen);
    return 3 + vlen;
}

static void write_reply_decoy(case_state *st) {
    uint8_t buf[MAX_FRAME];
    size_t dlen = strlen(st->decoy_flag);
    size_t tlen = encode_tlv(buf, TYPE_REPLY, (const uint8_t*)st->decoy_flag, dlen);
    write_frame(buf, tlen);
}

/* ---- crypto ---- */

static void compute_tag(const uint8_t *key, const uint8_t *material, size_t mlen, uint8_t out[32]) {
    uint8_t tmp[4096];
    size_t tlen = 0;
    memcpy(tmp, key, 32); tlen += 32;
    tmp[tlen++] = '|';
    memcpy(tmp + tlen, material, mlen); tlen += mlen;
    sha256(tmp, tlen, out);
}

static void issue_ticket(case_state *st) {
    uint8_t material[512];
    size_t mlen = 0;
    memcpy(material, st->key, 32); mlen += 32;
    memcpy(material + mlen, "|ticket|", 8); mlen += 8;
    char num[32];
    int n = snprintf(num, sizeof(num), "%d", st->slot);
    memcpy(material + mlen, num, n); mlen += n;
    material[mlen++] = '|';
    n = snprintf(num, sizeof(num), "%d", st->gen);
    memcpy(material + mlen, num, n); mlen += n;
    material[mlen++] = '|';
    size_t nlen = strlen(st->nonces[st->nonce_idx]);
    memcpy(material + mlen, st->nonces[st->nonce_idx], nlen); mlen += nlen;

    uint8_t hash[32];
    sha256(material, mlen, hash);
    memcpy(st->ticket, hash, 16);
    st->has_ticket = 1;
}

static void vault_keystream(case_state *st, uint8_t ks[32]) {
    char ticket_hex[33];
    bytes_to_hex(st->ticket, 16, ticket_hex);

    uint8_t material[512];
    size_t mlen = 0;
    memcpy(material, st->key, 32); mlen += 32;
    material[mlen++] = '|';
    char num[32];
    int n = snprintf(num, sizeof(num), "%d", st->slot);
    memcpy(material + mlen, num, n); mlen += n;
    material[mlen++] = '|';
    n = snprintf(num, sizeof(num), "%d", st->gen);
    memcpy(material + mlen, num, n); mlen += n;
    material[mlen++] = '|';
    size_t slen = strlen(st->scope);
    memcpy(material + mlen, st->scope, slen); mlen += slen;
    material[mlen++] = '|';
    memcpy(material + mlen, ticket_hex, 32); mlen += 32;
    memcpy(material + mlen, "|open", 5); mlen += 5;

    sha256(material, mlen, ks);
}

static void decrypt_flag(case_state *st, char *out) {
    uint8_t ks[32];
    vault_keystream(st, ks);
    for (int i = 0; i < st->vault_blob_len; i++) {
        out[i] = (char)(st->vault_blob[i] ^ ks[i % 32]);
    }
    out[st->vault_blob_len] = '\0';
}

/* ---- TLV parsing ---- */

typedef struct {
    uint8_t type;
    const uint8_t *val;
    size_t vlen;
} tlv_record;

static int parse_tlvs(const uint8_t *body, size_t blen, tlv_record *recs, int max_recs) {
    int count = 0;
    size_t off = 0;
    while (off < blen && count < max_recs) {
        if (off + 3 > blen) return count;
        uint8_t typ = body[off];
        uint16_t vlen = ((uint16_t)body[off+1] << 8) | body[off+2];
        off += 3;
        if (off + vlen > blen) return count;
        recs[count].type = typ;
        recs[count].val = body + off;
        recs[count].vlen = vlen;
        count++;
        off += vlen;
    }
    return count;
}

/* ---- script advance ---- */

static void advance_to_gate(case_state *st) {
    while (st->script_pos < st->script_count) {
        int ev = st->script[st->script_pos];
        if (ev == EVT_TICK) {
            st->gen++;
            st->script_pos++;
        } else if (ev == EVT_REINCARNATE) {
            st->gen++;
            st->nonce_idx++;
            if (st->nonce_idx >= st->nonce_count)
                st->nonce_idx = st->nonce_count - 1;
            st->has_ticket = 0;
            st->script_pos++;
        } else if (ev == EVT_TICKET) {
            strcpy(st->phase, "ticket");
            return;
        } else if (ev == EVT_CLAIM) {
            strcpy(st->phase, "claim");
            return;
        } else {
            st->script_pos++;
        }
    }
    strcpy(st->phase, "done");
}

/* ---- unwrap nesting ---- */

static const uint8_t *unwrap_nested(const uint8_t *body, size_t blen, int depth, size_t *out_len) {
    const uint8_t *cur = body;
    size_t clen = blen;
    for (int d = 0; d < depth; d++) {
        tlv_record recs[32];
        int n = parse_tlvs(cur, clen, recs, 32);
        int found = 0;
        for (int i = 0; i < n; i++) {
            if (recs[i].type == TYPE_NEST) {
                cur = recs[i].val;
                clen = recs[i].vlen;
                found = 1;
                break;
            }
        }
        if (!found) return NULL;
    }
    *out_len = clen;
    return cur;
}

/* ---- continue checking ---- */

static void check_continue(case_state *st, const uint8_t *body, size_t blen) {
    tlv_record recs[32];
    int n = parse_tlvs(body, blen, recs, 32);

    const uint8_t *cont_tag = NULL;
    size_t cont_len = 0;

    for (int i = 0; i < n; i++) {
        if (recs[i].type == TYPE_CONTINUE) {
            cont_tag = recs[i].val;
            cont_len = recs[i].vlen;
            break;
        }
    }

    if (!cont_tag || cont_len != 32) {
        st->locked = 1;
        write_reply_decoy(st);
        return;
    }

    char ticket_hex[33];
    bytes_to_hex(st->ticket, 16, ticket_hex);
    char mat_str[512];
    int mlen = snprintf(mat_str, sizeof(mat_str), "cont|%d|%d|%s|%s",
                        st->slot, st->gen, st->nonces[st->nonce_idx], ticket_hex);

    uint8_t computed[32];
    compute_tag(st->key, (const uint8_t*)mat_str, (size_t)mlen, computed);

    if (memcmp(computed, cont_tag, 32) != 0) {
        st->locked = 1;
        write_reply_decoy(st);
        return;
    }

    st->script_pos++;
    strcpy(st->phase, "run");

    uint8_t buf[128];
    size_t tlen = encode_tlv(buf, TYPE_NOTE, (const uint8_t*)"acked", 5);
    write_frame(buf, tlen);
}

/* ---- claim checking ---- */

static void check_claim(case_state *st, const uint8_t *body, size_t blen) {
    if (!st->has_ticket) { st->locked = 1; write_reply_decoy(st); return; }

    const uint8_t *inner = body;
    size_t ilen = blen;

    if (st->nest_required > 0) {
        size_t ulen = 0;
        inner = unwrap_nested(body, blen, st->nest_required, &ulen);
        if (!inner) { st->locked = 1; write_reply_decoy(st); return; }
        ilen = ulen;
        tlv_record top[32];
        int tn = parse_tlvs(body, blen, top, 32);
        if (tn > 0 && top[0].type != TYPE_NEST) { st->locked = 1; write_reply_decoy(st); return; }
    }

    tlv_record recs[32];
    int n = parse_tlvs(inner, ilen, recs, 32);

    const uint8_t *auth_tag = NULL; size_t auth_len = 0;
    const uint8_t *claim_scope = NULL; size_t claim_len = 0;
    const uint8_t *ticket_val = NULL; size_t ticket_len = 0;

    for (int i = 0; i < n; i++) {
        if (recs[i].type == TYPE_AUTH) { auth_tag = recs[i].val; auth_len = recs[i].vlen; }
        else if (recs[i].type == TYPE_CLAIM) { claim_scope = recs[i].val; claim_len = recs[i].vlen; }
        else if (recs[i].type == TYPE_TICKET) { ticket_val = recs[i].val; ticket_len = recs[i].vlen; }
    }

    if (!auth_tag || !claim_scope || !ticket_val) { st->locked = 1; write_reply_decoy(st); return; }

    size_t scope_len = strlen(st->scope);
    if (claim_len != scope_len || memcmp(claim_scope, st->scope, scope_len) != 0) {
        st->locked = 1; write_reply_decoy(st); return;
    }
    if (ticket_len != 16 || memcmp(ticket_val, st->ticket, 16) != 0) {
        st->locked = 1; write_reply_decoy(st); return;
    }

    char ticket_hex[33];
    bytes_to_hex(st->ticket, 16, ticket_hex);
    char mat_str[512];
    int mlen = snprintf(mat_str, sizeof(mat_str), "%d|%d|%s|%s|%s",
                        st->slot, st->gen, st->scope,
                        st->nonces[st->nonce_idx], ticket_hex);

    uint8_t computed[32];
    compute_tag(st->key, (const uint8_t*)mat_str, (size_t)mlen, computed);

    if (st->nest_required == 0) {
        if (auth_len < 4) { st->locked = 1; write_reply_decoy(st); return; }
        if (memcmp(computed, auth_tag, auth_len) != 0) { st->locked = 1; write_reply_decoy(st); return; }
    } else {
        if (auth_len != 32) { st->locked = 1; write_reply_decoy(st); return; }
        if (memcmp(computed, auth_tag, 32) != 0) { st->locked = 1; write_reply_decoy(st); return; }
    }

    char flag[MAX_FLAG];
    decrypt_flag(st, flag);

    uint8_t buf[MAX_FRAME];
    size_t flen = strlen(flag);
    size_t tlen = encode_tlv(buf, TYPE_REPLY, (const uint8_t*)flag, flen);
    write_frame(buf, tlen);
}

/* ---- main step loop ---- */

static void process_step(case_state *st, const uint8_t *body, size_t blen) {
    if (st->locked) {
        write_reply_decoy(st);
        return;
    }

    if (strcmp(st->phase, "continue") == 0) {
        check_continue(st, body, blen);
        return;
    }

    advance_to_gate(st);

    if (strcmp(st->phase, "ticket") == 0) {
        tlv_record recs[32];
        int n = parse_tlvs(body, blen, recs, 32);
        const uint8_t *auth_tag = NULL; size_t auth_len = 0;
        int has_note = 0;
        for (int i = 0; i < n; i++) {
            if (recs[i].type == TYPE_AUTH) { auth_tag = recs[i].val; auth_len = recs[i].vlen; }
            else if (recs[i].type == TYPE_NOTE) { has_note = 1; }
        }
        if (!auth_tag || !has_note) {
            st->locked = 1;
            write_reply_decoy(st);
            return;
        }

        char mat_str[512];
        int mlen = snprintf(mat_str, sizeof(mat_str), "%d|%d|%s|%s|request",
                            st->slot, st->gen, st->scope, st->nonces[st->nonce_idx]);
        uint8_t computed[32];
        compute_tag(st->key, (const uint8_t*)mat_str, (size_t)mlen, computed);

        int auth_ok = 0;
        if (st->nest_required == 0) {
            if (auth_len >= 4 && memcmp(computed, auth_tag, auth_len) == 0) auth_ok = 1;
        } else {
            if (auth_len == 32 && memcmp(computed, auth_tag, 32) == 0) auth_ok = 1;
        }
        if (!auth_ok) {
            st->locked = 1;
            write_reply_decoy(st);
            return;
        }

        issue_ticket(st);
        strcpy(st->phase, "continue");
        uint8_t buf[128];
        size_t tlen = encode_tlv(buf, TYPE_TICKET, st->ticket, 16);
        tlen += encode_tlv(buf + tlen, TYPE_NOTE, (const uint8_t*)"ok", 2);
        write_frame(buf, tlen);
        return;
    }

    if (strcmp(st->phase, "claim") == 0) {
        check_claim(st, body, blen);
        st->script_pos++;
        strcpy(st->phase, "run");
        return;
    }

    write_reply_decoy(st);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: vaultlab CASE_DIR\n");
        return 1;
    }

    case_state st;
    if (load_case(argv[1], &st) != 0) return 1;

    uint8_t frame_buf[MAX_FRAME];
    size_t frame_len;

    while (read_frame(frame_buf, MAX_FRAME, &frame_len) == 0) {
        process_step(&st, frame_buf, frame_len);
        if (strcmp(st.phase, "done") == 0) break;
    }

    return 0;
}
