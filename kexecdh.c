/* $OpenBSD: kexecdh.c,v 1.10 2019/01/21 10:40:11 djm Exp $ */
/*
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <openssl/core_names.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

static int
kex_ecdh_dec_key_group(const struct sshbuf *, EVP_PKEY *key,
    int, struct sshbuf **);

int
kex_ecdh_keypair(struct kex *kex)
{
	EVP_PKEY *client_key = NULL;
	struct sshbuf *buf = NULL;
	int r;

	if ((client_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC",
	    OBJ_nid2sn(kex->ec_nid))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_eckey(buf, client_key)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	EVP_PKEY_print_private_fp(stderr, client_key, 8, NULL);
#endif

	kex->ec_client_key = client_key;
	client_key = NULL;	/* owned by the kex */
	kex->client_pub = buf;
	buf = NULL;
 out:
	EVP_PKEY_free(client_key);
	sshbuf_free(buf);
	return r;
}

int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	EVP_PKEY *server_key = NULL;
	struct sshbuf *server_blob = NULL;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if ((server_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC",
	    OBJ_nid2sn(kex->ec_nid))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	EVP_PKEY_print_private_fp(stderr, server_key, 8, NULL);
#endif
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_eckey(server_blob, server_key)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, NULL)) != 0)
		goto out;

	if ((r = kex_ecdh_dec_key_group(client_blob, server_key,
	    kex->ec_nid, shared_secretp)) != 0)
		goto out;
	*server_blobp = server_blob;
	server_blob = NULL;
 out:
	EVP_PKEY_free(server_key);
	sshbuf_free(server_blob);
	return r;
}

static int
kex_ecdh_dec_key_group(const struct sshbuf *ec_blob,
    EVP_PKEY *key, int ec_nid, struct sshbuf **shared_secretp)
{
	OSSL_PARAM *params = NULL;
	OSSL_PARAM_BLD *tmpl = NULL;
	EVP_PKEY *dh_pub = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	struct sshbuf *buf = NULL;
	BIGNUM *shared_secret = NULL;
	u_char *kbuf = NULL, *pub;
	size_t klen = 0, publen;
	int r;

	*shared_secretp = NULL;

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		goto out;
	if ((r = sshbuf_get_string(buf, &pub, &publen)) != 0)
		goto out;
	sshbuf_reset(buf);
	if ((tmpl = OSSL_PARAM_BLD_new()) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	OSSL_PARAM_BLD_push_utf8_string(tmpl, OSSL_PKEY_PARAM_GROUP_NAME,
	    OBJ_nid2sn(ec_nid), 0);
	OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
	    pub, publen);
	if ((params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL ||
	    EVP_PKEY_fromdata_init(ctx) != 1 ||
	    EVP_PKEY_fromdata(ctx, &dh_pub, EVP_PKEY_KEYPAIR, params) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	EVP_PKEY_CTX_free(ctx);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	EVP_PKEY_print_public_fp(stderr, dh_pub, 8, NULL);
#endif
	if ((ctx = EVP_PKEY_CTX_new(key, NULL)) == NULL ||
	    EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, dh_pub) != 1 ||
	    EVP_PKEY_derive(ctx, NULL, &klen) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((kbuf = malloc(klen)) == NULL ||
	    (shared_secret = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_derive(ctx, kbuf, &klen) != 1 ||
	    BN_bin2bn(kbuf, klen, shared_secret) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	if ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
		goto out;
	*shared_secretp = buf;
	buf = NULL;
 out:
	OSSL_PARAM_BLD_free(tmpl);
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	return r;
}

int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	int r;

	r = kex_ecdh_dec_key_group(server_blob, kex->ec_client_key,
	    kex->ec_nid, shared_secretp);
	EVP_PKEY_free(kex->ec_client_key);
	kex->ec_client_key = NULL;
	return r;
}

#else

#include "ssherr.h"

struct kex;
struct sshbuf;
struct sshkey;

int
kex_ecdh_keypair(struct kex *kex)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC) */
