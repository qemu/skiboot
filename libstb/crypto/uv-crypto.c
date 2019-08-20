/* SPDX-License-Identifier: Apache-2.0 */
/*
 * UV Crypto
 *
 * Copyright 2019, IBM Corporation.
 *
 */

#include <lock.h>
#include <skiboot.h>
#include <stdlib.h>
#include <uv-crypto.h>

static mbedtls_hmac_drbg_context uv_drbg_ctx;
static struct lock drbg_lock = LOCK_UNLOCKED;


#define PPC_DARN(t, l) stringify(.long 0x7c0005e6 |\
			(((t) & 0x1f) << 21) |\
			(((l) & 0x3) << 16))

#define DARN_ERR	0xFFFFFFFFFFFFFFFFul

static uint64_t uv_crypto_darn_bytes(void)
{
	uint64_t rnum;
	int i;

	prerror("%s begin\n", __func__);
	/*
	 * Power ISA says 10 attemps should be sufficient for DARN
	 * to succeed. Try upto 64 times before giving up.
	 */
	for (i = 0; i < 64; i++) {
		asm volatile(PPC_DARN(%0, 1) : "=r"(rnum));

		if (rnum != DARN_ERR) {
			break;
		}
	}

	prerror("%s: rnum %llx\n", __func__, rnum);

	if (rnum == DARN_ERR) {
		/** @todo (andmike) Need policy if darn fails */
		abort();
	}

	prerror("%s end\n", __func__);
	return rnum;
}

static int32_t uv_crypto_seed_bytes(void *ctx __unused, unsigned char *buf,
		size_t len)
{
	uint64_t rnum;

	prerror("%s: len=%zd\n", __func__, len);

	while (len > 0 ) {
		size_t cp_len;

		rnum = uv_crypto_darn_bytes();
		assert(rnum != DARN_ERR);

		cp_len = (len < sizeof(rnum)) ? len : sizeof(rnum);
		memcpy(buf, &rnum, cp_len);

		buf += cp_len;
		len -= cp_len;
		prerror("%s: len %zd\n", __func__, len);
	}

	return 0;
}

static int32_t uv_crypto_drbg_init(void)
{
	int32_t rc;
	const mbedtls_md_info_t *md_info;

	prerror("mbedtls_hmac_drbg_init\n");
	mbedtls_hmac_drbg_init(&uv_drbg_ctx);

	prerror("mbedtls_md_info_from_type\n");
	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	assert(md_info);

	prerror("mbedtls_hmac_drbg_seed\n");
	rc = mbedtls_hmac_drbg_seed(&uv_drbg_ctx, md_info,
			uv_crypto_seed_bytes, NULL, NULL, 0);
	prerror("mbedtls_hmac_drbg_seed rc=%d\n",rc);
	if (rc) {
		return rc;
	}

	prerror("mbedtls_hmac_drbg_set_reseed_interval\n");
	mbedtls_hmac_drbg_set_reseed_interval(&uv_drbg_ctx, 1000);

	prerror("mbedtls_hmac_drbg_set_prediction_resistance\n");
	mbedtls_hmac_drbg_set_prediction_resistance(&uv_drbg_ctx,
			MBEDTLS_HMAC_DRBG_PR_OFF);

	prerror("uv_crypto_drbg_init end\n");
	return rc;
}

int32_t uv_crypto_init(void)
{
	int32_t rc;

	rc = uv_crypto_drbg_init();

	return rc;
}

int32_t uv_crypto_rand_bytes(unsigned char *output, size_t output_len)
{
	int32_t rc;

	lock(&drbg_lock);
	rc = mbedtls_hmac_drbg_random(&uv_drbg_ctx, output, output_len);
	unlock(&drbg_lock);

	return rc;
}
