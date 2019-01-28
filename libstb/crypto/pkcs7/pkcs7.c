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
#include <string.h>
#include <ccan/endian/endian.h>
#include <pkcs7.h>

static int pkcs7_get_next_content_len(unsigned char **p, unsigned char *end,
			       size_t *len)
{
	int rc;

	rc = mbedtls_asn1_get_tag(p, end, len, MBEDTLS_ASN1_CONSTRUCTED
					     | MBEDTLS_ASN1_CONTEXT_SPECIFIC);

	return rc;
}

/**
 * version Version
 * Version ::= INTEGER
 **/
static int pkcs7_get_version(unsigned char **p, unsigned char *end, int *ver)
{
	int rc;

	rc = mbedtls_asn1_get_int(p, end, ver);

	return rc;
}

/**
 * ContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      content
 *              [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 **/
static int pkcs7_get_content_info_type(unsigned char **p, unsigned char *end,
				pkcs7_buf *pkcs7)
{
	size_t len = 0;
	int rc;

	rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
					      | MBEDTLS_ASN1_SEQUENCE);
	if (rc)
		return rc;

	rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OID);
	if (rc)
		return rc;

	pkcs7->tag = MBEDTLS_ASN1_OID;
	pkcs7->len = len;
	pkcs7->p = *p;

	return rc;
}

/**
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * This is from x509.h
 **/
static int pkcs7_get_digest_algorithm(unsigned char **p, unsigned char *end,
			       mbedtls_x509_buf *alg)
{
	int rc;

	rc = mbedtls_asn1_get_alg_null(p, end, alg);

	return rc;
}

/**
 * DigestAlgorithmIdentifiers :: SET of DigestAlgorithmIdentifier
 **/
static int pkcs7_get_digest_algorithm_set(unsigned char **p, unsigned char *end,
				   mbedtls_x509_buf *alg)
{
	size_t len = 0;
	int rc;

	rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
					      | MBEDTLS_ASN1_SET);
	if (rc)
		return rc;

	end = *p + len;

	/** For now, it assumes there is only one digest algorithm specified **/
	rc = mbedtls_asn1_get_alg_null(p, end, alg);
	if (rc)
		return rc;

	return rc;
}

/**
 * certificates :: SET OF ExtendedCertificateOrCertificate,
 * ExtendedCertificateOrCertificate ::= CHOICE {
 *      certificate Certificate -- x509,
 *      extendedCertificate[0] IMPLICIT ExtendedCertificate }
 **/
static int pkcs7_get_certificates(unsigned char **buf, size_t buflen,
		mbedtls_x509_crt *certs)
{
	int rc;

	rc = mbedtls_x509_crt_parse(certs, *buf, buflen);
	if (rc)
		return rc;

	return rc;
}

/**
 * EncryptedDigest ::= OCTET STRING
 **/
static int pkcs7_get_signature(unsigned char **p, unsigned char *end,
		pkcs7_buf *signature)
{
	int rc;
	size_t len = 0;

	rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
	if (rc)
		return rc;

	signature->tag = MBEDTLS_ASN1_OCTET_STRING;
	signature->len = len;
	signature->p = *p;

	return rc;
}

/**
 * SignerInfo ::= SEQUENCE {
 *      version Version;
 *      issuerAndSerialNumber   IssuerAndSerialNumber,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      authenticatedAttributes
 *              [0] IMPLICIT Attributes OPTIONAL,
 *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *      encryptedDigest EncryptedDigest,
 *      unauthenticatedAttributes
 *              [1] IMPLICIT Attributes OPTIONAL,
 **/
static int pkcs7_get_signers_info_set(unsigned char **p, unsigned char *end,
			       struct pkcs7_signer_info *signers_set)
{
	unsigned char *end_set;
	int rc;
	size_t len = 0;

	rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
					      | MBEDTLS_ASN1_SET);
	if (rc) {
		printf("failed\n");
		return rc;
	}

	end_set = *p + len;

	rc = mbedtls_asn1_get_tag(p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
						  | MBEDTLS_ASN1_SEQUENCE);
	if (rc)
		return rc;

	rc = mbedtls_asn1_get_int(p, end_set, &signers_set->version);
	if (rc)
		return rc;

	rc = mbedtls_asn1_get_tag(p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
						  | MBEDTLS_ASN1_SEQUENCE);
	if (rc)
		return rc;

	signers_set->issuer_raw.p = *p;

	rc = mbedtls_asn1_get_tag(p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
						  | MBEDTLS_ASN1_SEQUENCE);
	if (rc)
		return rc;

	rc = mbedtls_x509_get_name(p, *p + len, &signers_set->issuer);
	if (rc)
		return rc;

	signers_set->issuer_raw.len =  *p - signers_set->issuer_raw.p;

	rc = mbedtls_x509_get_serial(p, end_set, &signers_set->serial);
	if (rc)
		return rc;

	rc = pkcs7_get_digest_algorithm(p, end_set,
					&signers_set->alg_identifier);
	if (rc) {
		printf("error getting digest algorithms\n");
		return rc;
	}

	rc = pkcs7_get_digest_algorithm(p, end_set,
					&signers_set->sig_alg_identifier);
	if (rc) {
		printf("error getting signature digest algorithms\n");
		return rc;
	}

	rc = pkcs7_get_signature(p, end, &signers_set->sig);
	signers_set->next = NULL;

	return rc;
}

/**
 * SignedData ::= SEQUENCE {
 *      version Version,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      contentInfo ContentInfo,
 *      certificates
 *              [0] IMPLICIT ExtendedCertificatesAndCertificates
 *                  OPTIONAL,
 *      crls
 *              [0] IMPLICIT CertificateRevocationLists OPTIONAL,
 *      signerInfos SignerInfos }
 */
static int pkcs7_get_signed_data(unsigned char *buf, size_t buflen,
			  struct pkcs7_signed_data *signed_data)
{
	unsigned char *p = buf;
	unsigned char *end = buf + buflen;
	size_t len = 0;
	size_t rc;

	rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
					       | MBEDTLS_ASN1_SEQUENCE);
	if (rc)
		return rc;

	/* get version of signed data */
	rc = pkcs7_get_version(&p, end, &signed_data->version);
	if (rc)
		return rc;
	printf("version is %d\n", signed_data->version);

	/* if version != 1, return invalid version */
	if (signed_data->version != 1) {
		printf("invalid version\n");
		return PKCS7_UNSUPPORTED_VERSION;
	}

	/* get digest algorithm */
	rc = pkcs7_get_digest_algorithm_set(&p, end,
					    &signed_data->digest_alg_identifiers);
	if (rc) {
		printf("error getting digest algorithms\n");
		return rc;
	}

	if (signed_data->digest_alg_identifiers.len != strlen(PKCS7_SHA256_OID))
		return PKCS7_INVALID_VALUE;

	if (memcmp(signed_data->digest_alg_identifiers.p, PKCS7_SHA256_OID,
		   signed_data->digest_alg_identifiers.len)) {
		printf("Digest Algorithm other than SHA256 is not supported\n");
		return PKCS7_UNSUPPORTED_DIGEST_ALGORITHM;
	}

	/* do not expect any content */
	rc = pkcs7_get_content_info_type(&p, end, &signed_data->content.oid);
	if (rc)
		return rc;

	if (memcmp(signed_data->content.oid.p, PKCS7_DATA_OID,
		   signed_data->content.oid.len)) {
		printf("Invalid PKCS7 data\n");
		return PKCS7_INVALID_VALUE;
	}

	p = p + signed_data->content.oid.len;

	rc = pkcs7_get_next_content_len(&p, end, &len);
	if (rc)
		return rc;

	/* get certificates */
	printf("----Loading Signer's certificate----\n");
	printf("\n");

	mbedtls_x509_crt_init(&signed_data->certs);
	rc = pkcs7_get_certificates(&p, len, &signed_data->certs);
	if (rc)
		return rc;

	p = p + len;

	/* get signers info */
	printf("Loading signer's signature\n");
	rc = pkcs7_get_signers_info_set(&p, end, &signed_data->signers);

	return rc;
}

void pkcs7_printf(const unsigned char *buf, size_t buflen)
{
	unsigned int i;
	char *sbuf;
	int j = 0;

	sbuf = malloc(buflen*2 + 1);
	memset(sbuf, 0, buflen*2 + 1);

	for (i = 0; i < buflen; i++)
		j += snprintf(sbuf+j, sizeof(sbuf), "%02x", buf[i]);

	printf("Length of sbuf is %lu\n", strlen(sbuf));
	printf("%s\n", sbuf);
	printf("\n");

	free(sbuf);
}

int pkcs7_parse_message(const unsigned char *buf, const int buflen,
			struct pkcs7 *pkcs7)
{
	unsigned char *start;
	unsigned char *end;
	size_t len = 0;
	int rc;

	/* use internal buffer for parsing */
	start = (unsigned char *)buf;
	end = start + buflen;

	rc = pkcs7_get_content_info_type(&start, end, &(pkcs7->content_type_oid));
	if (rc)
		goto out;

	if (memcmp(pkcs7->content_type_oid.p, PKCS7_SIGNED_DATA_OID,
		   pkcs7->content_type_oid.len)) {
		printf("PKCS7 is not the signed data\n");
		rc =  PKCS7_UNSUPPORTED_CONTENT_TYPE;
		goto out;
	}

	printf("Content type is signedData, continue...\n");

	start = start + pkcs7->content_type_oid.len;

	rc = pkcs7_get_next_content_len(&start, end, &len);
	if (rc)
		goto out;

	rc = pkcs7_get_signed_data(start, len, &(pkcs7->signed_data));
	if (rc)
		goto out;

out:
	return rc;
}
