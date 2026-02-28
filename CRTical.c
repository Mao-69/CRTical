/*
 * CRTical.c — RSA CRT dp-leak recovery tool
 *
 * Recovers an RSA private key from a leaked dp value (CRT exponent),
 * then decrypts a ciphertext file using RSA-OAEP (SHA-256).
 *
 * Supports:
 *   - Reading dp as raw hex (--dphex)
 *   - Reading dp from base64url-encoded, zlib-compressed chunks (--chunks)
 *   - Parsing chunks out of a .jsonl crash log (--jsonl)
 *
 * Build:
 *   gcc -O2 -o unseal unseal.c -lssl -lcrypto -lz -lgmp
 *
 * Usage:
 *   unseal --pub pub.pem --dphex <hex> --cipher enc.bin
 *   unseal --pub pub.pem --chunks <b64> <b64> ... --cipher enc.bin
 *   unseal --pub pub.pem --jsonl crash.jsonl --cipher enc.bin
 *
 * Dependencies:
 *   OpenSSL (libssl, libcrypto), zlib, GMP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>         /* RSA_PKCS1_OAEP_PADDING constant */
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <zlib.h>
#include <gmp.h>

/* ------------------------------------------------------------------ */
/* Utilities                                                            */
/* ------------------------------------------------------------------ */

static void die(const char *msg)
{
    fprintf(stderr, "[-] %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void die_ssl(const char *msg)
{
    fprintf(stderr, "[-] %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

/* Hex-dump the first `bytes` bytes of a file */
static void hex_preview(const char *path, size_t bytes)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return; }

    uint8_t buf[16];
    size_t  total = 0;

    printf("\n--- Hex Preview: %s ---\n", path);
    while (total < bytes) {
        size_t n = fread(buf, 1, 16, f);
        if (n == 0) break;
        printf("%08zx  ", total);
        for (size_t i = 0; i < 16; i++) {
            if (i < n) printf("%02x ", buf[i]);
            else       printf("   ");
            if (i == 7) printf(" ");
        }
        printf("  ");
        for (size_t i = 0; i < n; i++)
            printf("%c", (buf[i] >= 32 && buf[i] <= 126) ? buf[i] : '.');
        printf("\n");
        total += n;
    }
    printf("-------------------\n\n");
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* Base64url decode                                                     */
/* ------------------------------------------------------------------ */

/* Returns standard base64 char for a url-safe one */
static int b64url_to_std(unsigned char c)
{
    if (c == '-') return '+';
    if (c == '_') return '/';
    return c;
}

/*
 * Decode a base64url string (no padding required) into *out.
 * *out is malloc'd; caller frees.  Returns decoded length or -1.
 */
static ssize_t base64url_decode(const char *src, size_t src_len,
                                 uint8_t **out)
{
    /* Convert to standard base64 and add padding */
    size_t pad = (4 - src_len % 4) % 4;
    size_t std_len = src_len + pad;
    char  *std = malloc(std_len + 1);
    if (!std) return -1;

    for (size_t i = 0; i < src_len; i++)
        std[i] = (char)b64url_to_std((unsigned char)src[i]);
    for (size_t i = 0; i < pad; i++)
        std[src_len + i] = '=';
    std[std_len] = '\0';

    /* Use OpenSSL BIO to decode */
    BIO *b64bio  = BIO_new(BIO_f_base64());
    BIO *membio  = BIO_new_mem_buf(std, (int)std_len);
    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64bio, membio);

    size_t  buf_sz = std_len;   /* decoded is always shorter */
    uint8_t *buf   = malloc(buf_sz);
    if (!buf) { BIO_free_all(b64bio); free(std); return -1; }

    int n = BIO_read(b64bio, buf, (int)buf_sz);
    BIO_free_all(b64bio);
    free(std);

    if (n < 0) { free(buf); return -1; }
    *out = buf;
    return (ssize_t)n;
}

/* ------------------------------------------------------------------ */
/* Zlib inflate                                                         */
/* ------------------------------------------------------------------ */

/*
 * Inflate (decompress) `src` of length `src_len` into a newly allocated
 * buffer.  Returns decompressed length or -1.
 */
static ssize_t zlib_inflate(const uint8_t *src, size_t src_len,
                              uint8_t **out)
{
    size_t  buf_sz = src_len * 10 + 4096; /* initial guess */
    uint8_t *buf   = malloc(buf_sz);
    if (!buf) return -1;

    z_stream zs;
    memset(&zs, 0, sizeof zs);
    zs.next_in  = (Bytef *)src;
    zs.avail_in = (uInt)src_len;

    if (inflateInit(&zs) != Z_OK) { free(buf); return -1; }

    zs.next_out  = buf;
    zs.avail_out = (uInt)buf_sz;

    int ret;
    while ((ret = inflate(&zs, Z_NO_FLUSH)) == Z_OK) {
        if (zs.avail_out == 0) {
            buf_sz *= 2;
            uint8_t *tmp = realloc(buf, buf_sz);
            if (!tmp) { inflateEnd(&zs); free(buf); return -1; }
            buf = tmp;
            zs.next_out  = buf + zs.total_out;
            zs.avail_out = (uInt)(buf_sz - zs.total_out);
        }
    }

    inflateEnd(&zs);
    if (ret != Z_STREAM_END) { free(buf); return -1; }

    *out = buf;
    return (ssize_t)zs.total_out;
}

/* ------------------------------------------------------------------ */
/* Chunks → dp (mpz_t)                                                 */
/* ------------------------------------------------------------------ */

/*
 * Concatenate chunks, base64url-decode, zlib-inflate, interpret hex → dp.
 */
static int chunks_to_dp(char **chunks, int nchunks, mpz_t dp_out)
{
    /* Concatenate all chunk strings */
    size_t total_len = 0;
    for (int i = 0; i < nchunks; i++)
        total_len += strlen(chunks[i]);

    char *cat = malloc(total_len + 1);
    if (!cat) return 0;
    cat[0] = '\0';
    for (int i = 0; i < nchunks; i++)
        strcat(cat, chunks[i]);

    /* Base64url decode */
    uint8_t *decoded = NULL;
    ssize_t  dec_len = base64url_decode(cat, total_len, &decoded);
    free(cat);
    if (dec_len < 0) { fprintf(stderr, "[-] base64url decode failed\n"); return 0; }

    /* Zlib inflate */
    uint8_t *inflated = NULL;
    ssize_t  inf_len  = zlib_inflate(decoded, (size_t)dec_len, &inflated);
    free(decoded);
    if (inf_len < 0) { fprintf(stderr, "[-] zlib inflate failed\n"); return 0; }

    printf("[+] Inflated dp blob: %zd bytes\n", inf_len);

    /* Convert raw bytes → hex string → mpz_t */
    char *hexstr = malloc(inf_len * 2 + 1);
    if (!hexstr) { free(inflated); return 0; }
    for (ssize_t i = 0; i < inf_len; i++)
        sprintf(hexstr + i * 2, "%02x", inflated[i]);
    hexstr[inf_len * 2] = '\0';

    mpz_set_str(dp_out, hexstr, 16);

    free(hexstr);
    free(inflated);
    return 1;
}

/* ------------------------------------------------------------------ */
/* JSONL crash-log parser                                               */
/* ------------------------------------------------------------------ */

/*
 * Naively scan a .jsonl file for lines containing "chunk" (or "dp_chunk",
 * "b64chunk", etc.) and extract the quoted base64url value.
 *
 * Expected line format (flexible):
 *   {"chunk": "eJwBgAB__..."} 
 *   {"type":"dp_chunk","value":"eJwBgAB__..."}
 *
 * We simply look for every JSON string value that looks like a base64url
 * chunk (contains only [A-Za-z0-9_\-] and is longer than 16 chars).
 */
#define MAX_JSONL_CHUNKS 64

static int parse_jsonl(const char *path, char *chunks_out[], int *nchunks_out)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }

    int   n    = 0;
    char  line[65536];

    while (fgets(line, sizeof line, f) && n < MAX_JSONL_CHUNKS) {
        /* Scan for quoted strings */
        char *p = line;
        while ((p = strchr(p, '"')) != NULL) {
            p++;                        /* skip opening quote */
            char *end = strchr(p, '"');
            if (!end) break;

            size_t len = (size_t)(end - p);
            if (len < 16) { p = end + 1; continue; }

            /* Check all chars are base64url safe */
            int ok = 1;
            for (size_t i = 0; i < len && ok; i++) {
                unsigned char c = (unsigned char)p[i];
                if (!( (c >= 'A' && c <= 'Z') ||
                       (c >= 'a' && c <= 'z') ||
                       (c >= '0' && c <= '9') ||
                       c == '-' || c == '_' ))
                    ok = 0;
            }

            if (ok) {
                chunks_out[n] = malloc(len + 1);
                if (!chunks_out[n]) break;
                memcpy(chunks_out[n], p, len);
                chunks_out[n][len] = '\0';
                printf("[+] Extracted chunk[%d]: %.32s...\n", n, chunks_out[n]);
                n++;
            }
            p = end + 1;
        }
    }

    fclose(f);
    *nchunks_out = n;
    return n > 0;
}

/* ------------------------------------------------------------------ */
/* Recover p via dp-leak GCD attack                                    */
/* ------------------------------------------------------------------ */

/*
 * Given public key (n, e) and dp = d mod (p-1), we know:
 *   e*dp ≡ 1 (mod p-1)  →  e*dp - 1 = k*(p-1) for some small k
 *
 * So gcd(n, e*dp - 1 + delta) may equal p for small corrections delta.
 *
 * The function stores the result in p_out and returns 1 on success.
 */
static int recover_p(const char *n_hex, const char *e_hex,
                     const mpz_t dp_gmp, long max_delta,
                     mpz_t p_out)
{
    mpz_t n, e, base, k, g, tmp;
    mpz_inits(n, e, base, k, g, tmp, NULL);

    mpz_set_str(n, n_hex, 16);
    mpz_set_str(e, e_hex, 16);

    /* base = e * dp - 1 */
    mpz_mul(base, e, dp_gmp);
    mpz_sub_ui(base, base, 1);

    printf("[+] Searching for factor (max_delta=±%ld)...\n", max_delta);

    int found = 0;
    for (long delta = -max_delta; delta < max_delta; delta++) {
        if (delta >= 0)
            mpz_add_ui(k, base, (unsigned long)delta);
        else {
            mpz_set(k, base);
            mpz_sub_ui(k, k, (unsigned long)(-delta));
        }

        mpz_gcd(g, n, k);

        if (mpz_cmp_ui(g, 1) > 0 && mpz_cmp(g, n) < 0) {
            printf("[+] Factor found! delta=%ld, p bits=%d\n",
                   delta, (int)mpz_sizeinbase(g, 2));
            mpz_set(p_out, g);
            found = 1;
            break;
        }

        if (delta % 100000 == 0 && delta != 0)
            printf("    ... delta=%ld\n", delta);
    }

    mpz_clears(n, e, base, k, g, tmp, NULL);
    return found;
}

/* ------------------------------------------------------------------ */
/* Build RSA private key from p                                        */
/* ------------------------------------------------------------------ */

/*
 * Build an RSA EVP_PKEY from the public key and recovered prime p.
 * Uses the OpenSSL 3.x EVP_PKEY_fromdata API — zero deprecated calls.
 *
 * n_hex / e_hex are lower-case hex strings obtained from BN_bn2hex earlier.
 */
static EVP_PKEY *build_private_key(const char *n_hex, const char *e_hex,
                                    const mpz_t p_gmp)
{
    BN_CTX *ctx = BN_CTX_new();

    /* Load n and e */
    BIGNUM *n_bn = NULL, *e_bn = NULL;
    BN_hex2bn(&n_bn, n_hex);
    BN_hex2bn(&e_bn, e_hex);

    /* p from GMP */
    char   *p_hex_str = mpz_get_str(NULL, 16, p_gmp);
    BIGNUM *p_bn = NULL;
    BN_hex2bn(&p_bn, p_hex_str);
    free(p_hex_str);

    /* q = n / p */
    BIGNUM *q_bn = BN_new();
    BN_div(q_bn, NULL, n_bn, p_bn, ctx);

    /* phi = (p-1)*(q-1) */
    BIGNUM *p1  = BN_new(), *q1  = BN_new();
    BIGNUM *phi = BN_new();
    BN_sub(p1, p_bn, BN_value_one());
    BN_sub(q1, q_bn, BN_value_one());
    BN_mul(phi, p1, q1, ctx);

    /* d = e^-1 mod phi */
    BIGNUM *d  = BN_new();
    BN_mod_inverse(d, e_bn, phi, ctx);

    /* CRT parameters */
    BIGNUM *dp_bn = BN_new(), *dq_bn = BN_new(), *qi_bn = BN_new();
    BN_mod(dp_bn, d, p1, ctx);
    BN_mod(dq_bn, d, q1, ctx);
    BN_mod_inverse(qi_bn, q_bn, p_bn, ctx);

    BN_free(p1); BN_free(q1); BN_free(phi);
    BN_CTX_free(ctx);

    /* ---- Build key via OSSL_PARAM_BLD (OpenSSL 3 native) ---- */
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) die("OSSL_PARAM_BLD_new");

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N,    n_bn)  ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E,    e_bn)  ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D,    d)     ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p_bn) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q_bn) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp_bn) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq_bn) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qi_bn))
        die("OSSL_PARAM_BLD_push_BN");

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) die("OSSL_PARAM_BLD_to_param");

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!kctx) die("EVP_PKEY_CTX_new_from_name");

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata_init(kctx) <= 0)
        die_ssl("EVP_PKEY_fromdata_init");
    if (EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
        die_ssl("EVP_PKEY_fromdata");

    EVP_PKEY_CTX_free(kctx);
    OSSL_PARAM_free(params);

    BN_free(n_bn); BN_free(e_bn); BN_free(d);
    BN_free(p_bn); BN_free(q_bn);
    BN_free(dp_bn); BN_free(dq_bn); BN_free(qi_bn);

    return pkey;
}

/* ------------------------------------------------------------------ */
/* RSA-OAEP decrypt                                                    */
/* ------------------------------------------------------------------ */

static int decrypt_file(EVP_PKEY *priv_key,
                        const char *cipher_path,
                        const char *out_path)
{
    /* Read ciphertext */
    FILE *f = fopen(cipher_path, "rb");
    if (!f) { perror(cipher_path); return 0; }
    fseek(f, 0, SEEK_END);
    long ct_len = ftell(f);
    rewind(f);
    uint8_t *ct = malloc((size_t)ct_len);
    if (!ct) { fclose(f); return 0; }
    fread(ct, 1, (size_t)ct_len, f);
    fclose(f);

    /* Decrypt */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!pctx) { free(ct); die_ssl("EVP_PKEY_CTX_new"); }

    if (EVP_PKEY_decrypt_init(pctx) <= 0)    die_ssl("decrypt_init");
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        die_ssl("set_rsa_padding");
    if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0)
        die_ssl("set_rsa_oaep_md");
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0)
        die_ssl("set_rsa_mgf1_md");

    size_t pt_len = 0;
    EVP_PKEY_decrypt(pctx, NULL, &pt_len, ct, (size_t)ct_len); /* get size */

    uint8_t *pt = malloc(pt_len);
    if (!pt) { EVP_PKEY_CTX_free(pctx); free(ct); return 0; }

    if (EVP_PKEY_decrypt(pctx, pt, &pt_len, ct, (size_t)ct_len) <= 0) {
        fprintf(stderr, "[-] Decryption failed:\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        free(ct); free(pt);
        return 0;
    }

    EVP_PKEY_CTX_free(pctx);
    free(ct);

    /* Write plaintext */
    f = fopen(out_path, "wb");
    if (!f) { perror(out_path); free(pt); return 0; }
    fwrite(pt, 1, pt_len, f);
    fclose(f);
    free(pt);

    printf("[+] Decryption complete → %s\n", out_path);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Usage                                                                */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s --pub <pub.pem> --dphex <hex>         --cipher <file> [--out <file>] [--max-delta N]\n"
        "  %s --pub <pub.pem> --chunks <b64> [...]  --cipher <file> [--out <file>] [--max-delta N]\n"
        "  %s --pub <pub.pem> --jsonl  <file>       --cipher <file> [--out <file>] [--max-delta N]\n"
        "\n"
        "Options:\n"
        "  --pub        Path to RSA public key PEM\n"
        "  --dphex      dp exponent as hex string\n"
        "  --chunks     One or more base64url-encoded, zlib-compressed dp chunks\n"
        "  --jsonl      Path to a .jsonl crash log containing dp chunks\n"
        "  --cipher     Path to RSA-OAEP encrypted blob to decrypt\n"
        "  --out        Output file for decrypted data (default: decrypted.bin)\n"
        "  --save-pem   Save recovered private key PEM (default: recovered_private.pem)\n"
        "  --max-delta  Max correction range for GCD scan (default: 1048576)\n"
        "  --no-decrypt Only recover key, skip decryption\n"
        "\nBuild: gcc -O2 -o unseal unseal.c -lssl -lcrypto -lz -lgmp\n",
        prog, prog, prog);
    exit(1);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    const char *pub_path    = NULL;
    const char *dphex       = NULL;
    const char *jsonl_path  = NULL;
    const char *cipher_path = NULL;
    const char *out_path    = "decrypted.bin";
    const char *pem_out     = "recovered_private.pem";
    long        max_delta   = 1L << 20;
    int         no_decrypt  = 0;

    /* Collect chunk pointers from argv */
    char *chunks[MAX_JSONL_CHUNKS];
    int   nchunks = 0;
    int   in_chunks = 0;   /* flag: are we consuming --chunks args */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pub") == 0 && i+1 < argc) {
            pub_path = argv[++i]; in_chunks = 0;
        } else if (strcmp(argv[i], "--dphex") == 0 && i+1 < argc) {
            dphex = argv[++i]; in_chunks = 0;
        } else if (strcmp(argv[i], "--jsonl") == 0 && i+1 < argc) {
            jsonl_path = argv[++i]; in_chunks = 0;
        } else if (strcmp(argv[i], "--cipher") == 0 && i+1 < argc) {
            cipher_path = argv[++i]; in_chunks = 0;
        } else if (strcmp(argv[i], "--out") == 0 && i+1 < argc) {
            out_path = argv[++i]; in_chunks = 0;
        } else if (strcmp(argv[i], "--save-pem") == 0 && i+1 < argc) {
            pem_out = argv[++i]; in_chunks = 0;
        } else if (strcmp(argv[i], "--max-delta") == 0 && i+1 < argc) {
            max_delta = atol(argv[++i]); in_chunks = 0;
        } else if (strcmp(argv[i], "--no-decrypt") == 0) {
            no_decrypt = 1; in_chunks = 0;
        } else if (strcmp(argv[i], "--chunks") == 0) {
            in_chunks = 1;
        } else if (in_chunks && argv[i][0] != '-') {
            if (nchunks < MAX_JSONL_CHUNKS)
                chunks[nchunks++] = argv[i];
        } else {
            fprintf(stderr, "[-] Unknown argument: %s\n", argv[i]);
            usage(argv[0]);
        }
    }

    if (!pub_path) usage(argv[0]);
    if (!dphex && nchunks == 0 && !jsonl_path) usage(argv[0]);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* ---- Load public key ---- */
    FILE *fpub = fopen(pub_path, "r");
    if (!fpub) { perror(pub_path); exit(1); }
    EVP_PKEY *pub_key = PEM_read_PUBKEY(fpub, NULL, NULL, NULL);
    fclose(fpub);
    if (!pub_key) die_ssl("PEM_read_PUBKEY");

    /* ---- Extract n, e as hex strings (OpenSSL 3 native) ---- */
    BIGNUM *n_bn = NULL, *e_bn = NULL;
    if (!EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_RSA_N, &n_bn))
        die_ssl("EVP_PKEY_get_bn_param(n)");
    if (!EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_RSA_E, &e_bn))
        die_ssl("EVP_PKEY_get_bn_param(e)");

    char *n_hex_str = BN_bn2hex(n_bn);
    char *e_hex_str = BN_bn2hex(e_bn);
    printf("[+] Public key loaded, n bits: %d\n", BN_num_bits(n_bn));
    BN_free(n_bn);
    BN_free(e_bn);

    /* ---- Obtain dp ---- */
    mpz_t dp;
    mpz_init(dp);

    if (dphex) {
        mpz_set_str(dp, dphex, 16);
        printf("[+] dp loaded from --dphex\n");
    } else if (jsonl_path) {
        char *jchunks[MAX_JSONL_CHUNKS];
        int   jnchunks = 0;
        if (!parse_jsonl(jsonl_path, jchunks, &jnchunks)) {
            fprintf(stderr, "[-] No valid chunks found in %s\n", jsonl_path);
            exit(1);
        }
        printf("[+] Extracted %d chunk(s) from %s\n", jnchunks, jsonl_path);
        if (!chunks_to_dp(jchunks, jnchunks, dp)) {
            fprintf(stderr, "[-] Failed to decode chunks\n");
            exit(1);
        }
        for (int i = 0; i < jnchunks; i++) free(jchunks[i]);
        printf("[+] dp recovered from JSONL chunks\n");
    } else {
        if (!chunks_to_dp(chunks, nchunks, dp)) {
            fprintf(stderr, "[-] Failed to decode chunks\n");
            exit(1);
        }
        printf("[+] dp recovered from chunks\n");
    }

    /* ---- Recover p ---- */
    mpz_t p;
    mpz_init(p);
    if (!recover_p(n_hex_str, e_hex_str, dp, max_delta, p)) {
        fprintf(stderr, "[-] Could not recover p within delta range\n");
        mpz_clears(dp, p, NULL);
        EVP_PKEY_free(pub_key);
        exit(1);
    }
    mpz_clear(dp);

    /* ---- Build private key ---- */
    printf("[+] Building private key...\n");
    EVP_PKEY *priv_key = build_private_key(n_hex_str, e_hex_str, p);
    OPENSSL_free(n_hex_str);
    OPENSSL_free(e_hex_str);
    mpz_clear(p);
    EVP_PKEY_free(pub_key);

    if (!priv_key) die("build_private_key returned NULL");

    /* ---- Save private key PEM ---- */
    FILE *fpem = fopen(pem_out, "w");
    if (!fpem) { perror(pem_out); exit(1); }
    PEM_write_PrivateKey(fpem, priv_key, NULL, NULL, 0, NULL, NULL);
    fclose(fpem);
    printf("[+] Private key written to %s\n", pem_out);

    /* ---- Decrypt ---- */
    if (!no_decrypt) {
        if (!cipher_path) {
            fprintf(stderr, "[-] No --cipher provided; use --no-decrypt to skip\n");
            EVP_PKEY_free(priv_key);
            exit(1);
        }
        if (decrypt_file(priv_key, cipher_path, out_path))
            hex_preview(out_path, 10 * 16);
    }

    EVP_PKEY_free(priv_key);
    printf("[+] Done.\n");
    return 0;
}