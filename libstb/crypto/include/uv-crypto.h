/* SPDX-License-Identifier: Apache-2.0 */
/*
 * UV Crypto
 *
 * Copyright 2019, IBM Corporation.
 *
 */

#ifndef SVM_UV_CRYPTO_H
#define SVM_UV_CRYPTO_H

#include <stdint.h>
#include <mbedtls/hmac_drbg.h>

/**
 * @brief Generate random bytes.
 *
 * @param output Buffer to fill.
 * @param output_len Length of the buffer.
 *
 * @return 0 on success, else 1 on failure.
 */
extern int uv_crypto_rand_bytes(unsigned char *output, size_t output_len);

/**
 * @brief Init crypto context
 *
 * @return 0 on success, else 1 on failure.
 */
extern int32_t uv_crypto_init(void);

#endif /* SVM_UV_CRYPTO_H */

