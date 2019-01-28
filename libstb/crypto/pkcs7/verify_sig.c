/* Copyright 2013-2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<mbedtls/asn1.h>
#include<mbedtls/config.h>
#include<mbedtls/x509.h>
#include<mbedtls/x509_crt.h>
#include<mbedtls/rsa.h>
#include<mbedtls/pk.h>
#include<mbedtls/md.h>
#include<verify_sig.h>

static int verify(mbedtls_x509_crt *cert, const unsigned char *data,
		  int datalen, const unsigned char *sig, int siglen)
{
	int rc;
	unsigned char hash[32];
	mbedtls_pk_context pk_cxt = cert->pk;
	const mbedtls_md_info_t *md_info =
		mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

	mbedtls_md(md_info, data, datalen, hash);
	rc = mbedtls_pk_verify(&pk_cxt, MBEDTLS_MD_SHA256,hash, 32, sig,
			       siglen);
	printf("rc is %02x\n", rc);

	return rc;
}


int verify_buf(unsigned char *cert_buf, int certlen, unsigned char *data_buf,
	       int datalen, unsigned char *sig_buf, int siglen)
{
	int rc;
	mbedtls_x509_crt cert;

	printf("Load certificate file\n");
	mbedtls_x509_crt_init(&cert);

	rc = mbedtls_x509_crt_parse(&cert, cert_buf, certlen);
	if (rc) {
		printf("rc is %04x\n", rc);
		return rc;
	}

	rc = verify(&cert, data_buf, datalen, sig_buf, siglen);

	return rc;
}
