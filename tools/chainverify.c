/* chainverify: verify many served chains against one CA file, three ways.
 *
 *   modern     OpenSSL 1.1.0+ default: search the trust store first
 *   nofirst    trusted-first off (the default before OpenSSL 1.1.0), but
 *              alternative-chain search on (OpenSSL 1.0.1n / 1.0.2b and later)
 *   strict     trusted-first off and alternative chains off: follow only the
 *              chain the server sent, then look for its issuer in the store
 *
 * Usage: chainverify CAFILE EPOCH < list-of-chain-files
 * Each chain file is PEM, leaf first, as the server sent it.
 * Output, one line per file:
 *   file \t modern \t anchor \t nofirst \t anchor \t strict \t anchor
 * where each result is "ok" or the OpenSSL error string, and anchor is the
 * subject CN (or O) of the trust anchor the verified chain ended at.
 *
 * Build: cc -O2 -o chainverify chainverify.c -lcrypto
 */
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void name_of(X509 *c, char *buf, size_t n) {
    X509_NAME *nm = X509_get_subject_name(c);
    buf[0] = '\0';
    if (X509_NAME_get_text_by_NID(nm, NID_commonName, buf, (int)n) < 0)
        X509_NAME_get_text_by_NID(nm, NID_organizationName, buf, (int)n);
    for (char *p = buf; *p; p++)
        if (*p == '\t' || *p == '\n') *p = ' ';
}

static void run(X509_STORE *st, STACK_OF(X509) *chain, time_t t, int mode, char *res, char *anchor) {
    X509 *leaf = sk_X509_value(chain, 0);
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    for (int i = 1; i < sk_X509_num(chain); i++) sk_X509_push(untrusted, sk_X509_value(chain, i));
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, st, leaf, untrusted);
    X509_VERIFY_PARAM *p = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_time(p, t);
    X509_VERIFY_PARAM_set_purpose(p, X509_PURPOSE_SSL_SERVER);
    if (mode >= 1) X509_VERIFY_PARAM_clear_flags(p, X509_V_FLAG_TRUSTED_FIRST);
    if (mode >= 2) X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_NO_ALT_CHAINS);
    int ok = X509_verify_cert(ctx);
    anchor[0] = '-';
    anchor[1] = '\0';
    if (ok == 1) {
        strcpy(res, "ok");
        STACK_OF(X509) *built = X509_STORE_CTX_get0_chain(ctx);
        name_of(sk_X509_value(built, sk_X509_num(built) - 1), anchor, 256);
    } else {
        snprintf(res, 256, "%s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }
    X509_STORE_CTX_free(ctx);
    sk_X509_free(untrusted);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s CAFILE EPOCH < files\n", argv[0]);
        return 2;
    }
    X509_STORE *st = X509_STORE_new();
    if (X509_STORE_load_file(st, argv[1]) != 1) {
        fprintf(stderr, "cannot load %s\n", argv[1]);
        return 2;
    }
    time_t t = (time_t)strtoll(argv[2], NULL, 10);
    char path[4096];
    while (fgets(path, sizeof path, stdin)) {
        path[strcspn(path, "\n")] = '\0';
        FILE *f = fopen(path, "r");
        if (!f) continue;
        STACK_OF(X509) *chain = sk_X509_new_null();
        X509 *c;
        while ((c = PEM_read_X509(f, NULL, NULL, NULL)) != NULL) sk_X509_push(chain, c);
        ERR_clear_error();
        fclose(f);
        if (sk_X509_num(chain) == 0) {
            sk_X509_free(chain);
            continue;
        }
        printf("%s", path);
        for (int mode = 0; mode < 3; mode++) {
            char res[256], anchor[256];
            run(st, chain, t, mode, res, anchor);
            printf("\t%s\t%s", res, anchor);
        }
        printf("\n");
        sk_X509_pop_free(chain, X509_free);
    }
    X509_STORE_free(st);
    return 0;
}
