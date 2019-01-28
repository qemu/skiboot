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
#ifndef SKIBOOT_PKCS7_H
#define SKIBOOT_PKCS7_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/asn1.h>
#include <mbedtls/config.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>

/** define the OID constants **/
#define PKCS7_SIGNED_DATA_OID "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"
#define PKCS7_DATA_OID "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
#define PKCS7_SHA256_OID "\x60\x86\x48\x01\x65\x03\x04\x02\x01"
#define PKCS7_RSAeNCRYPTION_OID "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"


/** define the pkcs7 errors **/
#define PKCS7_UNSUPPORTED_CONTENT_TYPE        0x01
#define PKCS7_INVALID_VALUE                   0x02
#define PKCS7_CERTIFICATE_NOT_FOUND           0x03
#define PKCS7_PARSING_ERROR                   0x04
#define PKCS7_UNSUPPORTED_VERSION             0x05
#define PKCS7_UNSUPPORTED_DIGEST_ALGORITHM    0x06
#define PKCS7_UNSUPPORTED_SIGNING_ALGORITHM   0x07

typedef mbedtls_asn1_buf pkcs7_buf;

typedef mbedtls_asn1_named_data pkcs7_name;

typedef mbedtls_asn1_sequence pkcs7_sequence;

struct pkcs7_signer_info {
	int version;
	mbedtls_x509_buf serial;
	mbedtls_x509_name issuer;
	mbedtls_x509_buf issuer_raw;
	mbedtls_x509_buf alg_identifier;
	mbedtls_x509_buf sig_alg_identifier;
	mbedtls_x509_buf sig;
	struct pkcs7_signer_info *next;
};

struct pkcs7_data {
	pkcs7_buf oid;
	pkcs7_buf data;
};

struct pkcs7;

struct pkcs7_signed_data {
	int version;
	pkcs7_buf digest_alg_identifiers;
	struct pkcs7_data content;
	mbedtls_x509_crt certs;
	mbedtls_x509_crl crl;
	struct pkcs7_signer_info signers;
};

struct pkcs7 {
	pkcs7_buf content_type_oid;
	struct pkcs7_signed_data signed_data;
};

void pkcs7_printf(const unsigned char *buf, size_t buflen);

int pkcs7_parse_message(const unsigned char *buf, const int buflen,
			struct pkcs7 *pkcs7);

#endif
