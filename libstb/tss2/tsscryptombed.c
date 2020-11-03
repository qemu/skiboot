/********************************************************************************/
/*										*/
/*		     TSS Library Dependent Crypto Support			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*		ECC Salt functions written by Bill Martin			*/
/*										*/
/* (c) Copyright IBM Corporation 2019.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* Interface to mbedtls crypto library */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#ifndef TPM_TSS_NORSA
#include <libstb/crypto/mbedtls/include/mbedtls/rsa.h>
#endif
#include <libstb/crypto/mbedtls/include/mbedtls/md.h>
#ifdef TPM_ALG_SHA1
#include <libstb/crypto/mbedtls/include/mbedtls/sha1.h>
#endif
#include <libstb/crypto/mbedtls/include/mbedtls/sha256.h>
#include <libstb/crypto/mbedtls/include/mbedtls/sha512.h>
#include <libstb/crypto/mbedtls/include/mbedtls/aes.h>

/* if no RSA and no ECC, don't need any asymmetric support */
#ifdef TPM_TSS_NORSA
#ifdef TPM_TSS_NOECC
#define TPM_TSS_NOASYM
#endif
#endif

#ifndef TPM_TSS_NOASYM
#include <libstb/crypto/mbedtls/include/mbedtls/pk.h>
#endif

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tsserror.h>

#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>

extern int tssVverbose;
extern int tssVerbose;

/* local prototypes */

static void TSS_Error(int irc);
static TPM_RC TSS_Hash_GetMd(mbedtls_md_type_t *mdType,
			     TPMI_ALG_HASH hashAlg);
#ifndef TPM_TSS_NORSA
static TPM_RC TSS_RsaNew(void **rsaKey);
#endif

/*
  Initialization
*/


#ifndef TPM_TSS_NOASYM
static TPM_RC TSS_PkContextNew(mbedtls_pk_context **ctx);
#endif

/* TSS_PkContextNew() allocates and initializes a mbedtls_pk_context */

#ifndef TPM_TSS_NOASYM

static TPM_RC TSS_PkContextNew(mbedtls_pk_context **ctx) /* freed by caller */
{
    TPM_RC 	rc = 0;

    /* sanity check for the free */
    if (rc == 0) {
	if (*ctx != NULL) {
	    if (tssVerbose) printf("TSS_PkContextNew: Error (fatal), token %p should be NULL\n",
				   *ctx);
            rc = TSS_RC_ALLOC_INPUT;
	}
    }
    /* allocate the mbedtls_pk_context */
    if (rc == 0) {
	rc = TSS_Malloc((unsigned char **)ctx, sizeof(mbedtls_pk_context));
    }
    /* initialize but do not set up the context */
    if (rc == 0) {
	mbedtls_pk_init(*ctx);
    }
    return rc;
}
#endif	/* TPM_TSS_NOASYM */

/* Error trace */

static void TSS_Error(int irc)
{
    int src = 0 - irc;
    if (tssVerbose) printf("mbedtls error -%04x\n", src);
    return;
}

/*
  Digests
*/

/* TSS_Hash_GetMd() maps from a TCG hash algorithm to am mbedtls_md_type_t  */

static TPM_RC TSS_Hash_GetMd(mbedtls_md_type_t *mdType,
			     TPMI_ALG_HASH hashAlg)
{
    TPM_RC		rc = 0;

    if (rc == 0) {
	switch (hashAlg) {
#ifdef TPM_ALG_SHA1
	  case TPM_ALG_SHA1:
	    *mdType = MBEDTLS_MD_SHA1;
	    break;
#endif
#ifdef TPM_ALG_SHA256
	  case TPM_ALG_SHA256:
	    *mdType = MBEDTLS_MD_SHA256;
	    break;
#endif
#ifdef TPM_ALG_SHA384
	  case 	TPM_ALG_SHA384:
	    *mdType = MBEDTLS_MD_SHA384;
	    break;
#endif
#ifdef TPM_ALG_SHA512
	  case 	TPM_ALG_SHA512:
	    *mdType = MBEDTLS_MD_SHA512;
	    break;
#endif
	  default:
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    return rc;
}

/* On call, digest->hashAlg is the desired hash algorithm

   length 0 is ignored, buffer NULL terminates list.
*/

TPM_RC TSS_HMAC_Generate_valist(TPMT_HA *digest,		/* largest size of a digest */
				const TPM2B_KEY *hmacKey,
				va_list ap)
{
    TPM_RC			rc = 0;
    int 			irc = 0;
    int				done = FALSE;
    mbedtls_md_context_t 	ctx;
    mbedtls_md_type_t 		mdType;
    const mbedtls_md_info_t	*mdInfo = NULL;
    int				length;
    uint8_t 			*buffer;

    mbedtls_md_init(&ctx);	/* initialize the context */
    /* map from TPM digest algorithm to mbedtls type */
    if (rc == 0) {
	rc = TSS_Hash_GetMd(&mdType, digest->hashAlg);
    }
    if (rc == 0) {
	mdInfo =  mbedtls_md_info_from_type(mdType);
	if (mdInfo == NULL) {
	    rc = TSS_RC_HMAC;
	}
    }
    if (rc == 0) {
	irc = mbedtls_md_setup(&ctx,		/* freed @1 */
			       mdInfo,
			       1); 		/* flag, hmac used */
	if (irc != 0) {
	    TSS_Error(irc);
	    rc = TSS_RC_HMAC;
	}
    }
    if (rc == 0) {
	irc = mbedtls_md_hmac_starts(&ctx,
				     hmacKey->b.buffer, hmacKey->b.size);	/* HMAC key */
	if (irc != 0) {
	    TSS_Error(irc);
	    rc = TSS_RC_HMAC;
	}
    }
    while ((rc == 0) && !done) {
	length = va_arg(ap, int);		/* first vararg is the length */
	buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
	if (buffer != NULL) {			/* loop until a NULL buffer terminates */
	    if (length < 0) {
		if (tssVerbose) printf("TSS_HMAC_Generate: Length is negative\n");
		rc = TSS_RC_HMAC;
	    }
	    else {
		irc = mbedtls_md_hmac_update(&ctx, buffer, length);
		if (irc != 0) {
		    TSS_Error(irc);
		    if (tssVerbose) printf("TSS_HMAC_Generate: HMAC_Update failed\n");
		    rc = TSS_RC_HMAC;
		}
	    }
	}
	else {
	    done = TRUE;
	}
    }

    if (rc == 0) {
	irc = mbedtls_md_hmac_finish(&ctx, (uint8_t *)&digest->digest);
	if (irc != 0) {
	    TSS_Error(irc);
	    rc = TSS_RC_HMAC;
	}
    }
    mbedtls_md_free(&ctx);	/* @1 */
    return rc;
}

/*
  valist is int length, unsigned char *buffer pairs

  length 0 is ignored, buffer NULL terminates list.
*/

TPM_RC TSS_Hash_Generate_valist(TPMT_HA *digest,		/* largest size of a digest */
				va_list ap)
{
    TPM_RC			rc = 0;
    int				irc = 0;
    int				done = FALSE;
    mbedtls_md_context_t 	ctx;
    mbedtls_md_type_t 		mdType;
    const mbedtls_md_info_t	*mdInfo = NULL;
    int				length;
    uint8_t 			*buffer;

    mbedtls_md_init(&ctx);	/* initialize the context */
    /* map from TPM digest algorithm to mbedtls type */
    if (rc == 0) {
	rc = TSS_Hash_GetMd(&mdType, digest->hashAlg);
    }
    if (rc == 0) {
	mdInfo =  mbedtls_md_info_from_type(mdType);
	if (mdInfo == NULL) {
	    if (tssVerbose) printf("TSS_Hash_Generate: Hash algorithm not found\n");
	    rc = TSS_RC_HASH;
	}
    }
    if (rc == 0) {
	irc = mbedtls_md_setup(&ctx,		/* freed @1 */
			       mdInfo,
			       0); 		/* flag, hash used */
	if (irc != 0) {
	    TSS_Error(irc);
	    if (tssVerbose) printf("TSS_Hash_Generate: mbedtls_md_setup failed\n");
	    rc = TSS_RC_HASH;
	}
    }
    if (rc == 0) {
	irc = mbedtls_md_starts(&ctx);
	if (irc != 0) {
	    TSS_Error(irc);
	    if (tssVerbose) printf("TSS_Hash_Generate: mbedtls_md_starts failed\n");
	    rc = TSS_RC_HASH;
	}
    }
    while ((rc == 0) && !done) {
	length = va_arg(ap, int);		/* first vararg is the length */
	buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
	if (buffer != NULL) {			/* loop until a NULL buffer terminates */
	    if (length < 0) {
		if (tssVerbose) printf("TSS_Hash_Generate: Length is negative\n");
		rc = TSS_RC_HASH;
	    }
	    else {
		/* if (tssVverbose) TSS_PrintAll("TSS_Hash_Generate:", buffer, length); */
		if (length != 0) {
		    irc = mbedtls_md_update(&ctx, buffer, length);
		    if (irc != 0) {
			TSS_Error(irc);
			rc = TSS_RC_HASH;
		    }
		}
	    }
	}
	else {
	    done = TRUE;
	}
    }
    if (rc == 0) {
	irc = mbedtls_md_finish(&ctx, (uint8_t *)&digest->digest);
	if (irc != 0) {
	    TSS_Error(irc);
	    rc = TSS_RC_HASH;
	}
    }
    mbedtls_md_free(&ctx);	/* @1 */
    return rc;
}

/*
  RSA functions
*/

#ifndef TPM_TSS_NORSA

/* NOTE: For mbedtls, TSS_RsaNew() and TSS_RsaFree() are not symmetrical.

   TSS_RsaNew() allocates the inner mbedtls_rsa_context structure.  TSS_RsaNew() should not have
   been public for OpenSSL, and is tetained but deprecated.  It is private for mbedtls.

   TSS_RsaFree(), which is public because it frees the TSS_RSAGeneratePublicTokenI() result, frees
   the outer mbedtls_pk_context structure.
*/


/* TSS_RsaNew() allocates an mbedtls RSA key token.

   This abstracts the crypto library specific allocation.

   For mbedtls, rsaKey is a mbedtls_rsa_context structure.
*/

TPM_RC TSS_RsaNew(void **rsaKey)
{
    TPM_RC  	rc = 0;

    /* sanity check for the free */
    if (rc == 0) {
	if (*rsaKey != NULL) {
            if (tssVerbose) printf("TSS_RsaNew: Error (fatal), token %p should be NULL\n",
				   *rsaKey);
            rc = TSS_RC_ALLOC_INPUT;
	}
    }
    /* construct the private key object */
    if (rc == 0) {
	rc = TSS_Malloc((unsigned char **)rsaKey, sizeof(mbedtls_rsa_context));
    }
    if (rc == 0) {
	mbedtls_rsa_init(*rsaKey, MBEDTLS_RSA_PKCS_V15, 0);
    }
    return rc;
}

/* TSS_RsaFree() frees an mbedtls_pk_context RSA key token.

   For compatibility with other crypto libraries, this is the outer wrapper, not the inner RSA
   structure.

   This abstracts the crypto library specific free.
*/

void TSS_RsaFree(void *rsaKey)
{
    mbedtls_pk_free(rsaKey);
    free(rsaKey);
    return;
}

/* TSS_RSAGeneratePublicTokenI() generates an mbedtls_pk_context RSA public key token from n and e

   Free rsa_pub_key using TSS_RsaFree();
*/

TPM_RC TSS_RSAGeneratePublicTokenI(void **rsa_pub_key,		/* freed by caller */
				   const unsigned char *narr,	/* public modulus */
				   uint32_t nbytes,
				   const unsigned char *earr,	/* public exponent */
				   uint32_t ebytes)
{
    TPM_RC  			rc = 0;
    int 			irc;
    mbedtls_rsa_context 	*rsaCtx = NULL;
    const mbedtls_pk_info_t 	*pkInfo = NULL;

    /* allocate and initialize the mbedtls_pk_context public key token */
    if (rc == 0) {
	rc = TSS_PkContextNew((mbedtls_pk_context **)rsa_pub_key);	/* freed by caller */
    }
    /* allocate and initialize the inner mbedtls_rsa_context */
    if (rc == 0) {
	rc = TSS_RsaNew((void **)&rsaCtx);	/* freed @1 contexts freed with wrapper */
    }
    if (rc == 0) {
	irc = mbedtls_rsa_import_raw(rsaCtx,
				     narr, nbytes,
				     NULL, 0,		/* p */
				     NULL, 0,		/* q */
				     NULL, 0,		/* d */
				     earr, ebytes);
	if (irc != 0) {
	    TSS_Error(irc);
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = mbedtls_rsa_complete(rsaCtx);
	if (irc != 0) {
	    TSS_Error(irc);
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = mbedtls_rsa_check_pubkey(rsaCtx);
	if (irc != 0) {
	    TSS_Error(irc);
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    /* build the mbedtls_pk_context from the mbedtls_rsa_context */
    if (rc == 0) {
	pkInfo = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
	if (pkInfo == NULL) {
	    if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: "
				   "Error in mbedtls_pk_info_from_type()\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    /* set the metadata */
    if (rc == 0) {
	irc = mbedtls_pk_setup(*rsa_pub_key, pkInfo);
	if (irc != 0) {
	    TSS_Error(irc);
	    if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: Error in mbedtls_pk_setup()\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    /* copy the key data */
    if (rc == 0) {
	mbedtls_pk_context *pkCtx = (mbedtls_pk_context *)*rsa_pub_key;
	mbedtls_rsa_context *rsaPkCtx = mbedtls_pk_rsa(*pkCtx);
	memcpy(rsaPkCtx, rsaCtx, sizeof(mbedtls_rsa_context));
    }
    free(rsaCtx);
    return rc;
}

/* TSS_RSAPublicEncrypt() pads 'decrypt_data' to 'encrypt_data_size' and encrypts using the public
   key 'n, e'.
*/

TPM_RC TSS_RSAPublicEncrypt(unsigned char *encrypt_data,    /* encrypted data */
			    size_t encrypt_data_size,       /* size of encrypted data buffer */
			    const unsigned char *decrypt_data,      /* decrypted data */
			    size_t decrypt_data_size,
			    unsigned char *narr,           /* public modulus */
			    uint32_t nbytes,
			    unsigned char *earr,           /* public exponent */
			    uint32_t ebytes,
			    unsigned char *p,		/* encoding parameter */
			    int pl,
			    TPMI_ALG_HASH halg)		/* OAEP hash algorithm */
{
    TPM_RC  		rc = 0;
    int         	irc;
    mbedtls_pk_context	*pkCtx = NULL;
    unsigned char 	*padded_data = NULL;

    if (tssVverbose) printf(" TSS_RSAPublicEncrypt: Input data size %lu\n",
			    (unsigned long)decrypt_data_size);
    /* intermediate buffer for the decrypted but still padded data */
    if (rc == 0) {
        rc = TSS_Malloc(&padded_data, encrypt_data_size);	/* freed @2 */
    }
    /* construct the mbedtls_pk_context public key */
    if (rc == 0) {
	rc = TSS_RSAGeneratePublicTokenI((void **)&pkCtx,	/* freed @1 */
					 narr,      		/* public modulus */
					 nbytes,
					 earr,      		/* public exponent */
					 ebytes);
    }
    if (rc == 0) {
	padded_data[0] = 0x00;
	rc = TSS_RSA_padding_add_PKCS1_OAEP(padded_data,		/* to */
					    encrypt_data_size,		/* to length */
					    decrypt_data,		/* from */
					    decrypt_data_size,		/* from length */
					    p,		/* encoding parameter */
					    pl,		/* encoding parameter length */
					    halg);	/* OAEP hash algorithm */
    }
    if (rc == 0) {
	mbedtls_rsa_context *rsaCtx = NULL;
        if (tssVverbose)
	    printf("  TSS_RSAPublicEncrypt: Padded data size %lu\n",
		   (unsigned long)encrypt_data_size);
        if (tssVverbose) TSS_PrintAll("  TPM_RSAPublicEncrypt: Padded data", padded_data,
				      encrypt_data_size);
        /* encrypt with public key.  Must pad first and then encrypt because the encrypt
           call cannot specify an encoding parameter */
	/* returns the size of the encrypted data.  On error, -1 is returned */
	rsaCtx  = mbedtls_pk_rsa(*pkCtx);		/* get inner RSA key */
	irc = mbedtls_rsa_public(rsaCtx,           	/* key */
				 padded_data,           /* from - the clear text data */
				 encrypt_data);		/* the padded and encrypted data */
	if (irc != 0) {
	    TSS_Error(irc);
	    if (tssVerbose) printf("TSS_RSAPublicEncrypt: Error in mbedtls_rsa_public()\n");
	    rc = TSS_RC_RSA_ENCRYPT;
	}
    }
    if (rc == 0) {
        if (tssVverbose) printf("  TSS_RSAPublicEncrypt: RSA_public_encrypt() success\n");
    }
    TSS_RsaFree(pkCtx);          	/* @1 */
    free(padded_data);                  /* @2 */
    return rc;
}

#endif /* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOECC
#if 0	/* Not implemented for mbedtls */

/* TSS_GeneratePlatformEphemeralKey sets the EC parameters to NIST P256 for generating the ephemeral
   key. Some OpenSSL versions do not come with NIST p256.  */

static TPM_RC TSS_ECC_GeneratePlatformEphemeralKey(CURVE_DATA *eCurveData, EC_KEY *myecc)
{
    TPM_RC      rc = 0;
    BIGNUM 	*p = NULL;
    BIGNUM 	*a = NULL;
    BIGNUM 	*b = NULL;
    BIGNUM 	*x = NULL;
    BIGNUM 	*y = NULL;
    BIGNUM 	*z = NULL;
    EC_POINT    *G = NULL; 	/* generator */

    /* ---------------------------------------------------------- *
     * Set the EC parameters to NISTp256. Openssl versions might  *
     * not have NISTP256 as a possible parameter so we make it    *
     * possible by setting the curve ourselves.                   *
     * ---------------------------------------------------------- */

    /*  NIST P256  from FIPS 186-3 */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: Converting p\n");
	rc = TSS_BN_hex2bn(&p,		/* freed @1 */
			   "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: Converting a\n");
	rc = TSS_BN_hex2bn(&a,		/* freed @2 */
			   "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: Converting b\n");
	rc = TSS_BN_hex2bn(&b,		/* freed @3 */
			   "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: New group\n");
	eCurveData->G = EC_GROUP_new(EC_GFp_mont_method());	/* freed @4 */
	if (eCurveData->G == NULL) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error creating new group\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: Set the curve prime\n");
	if (EC_GROUP_set_curve_GFp(eCurveData->G, p, a, b, eCurveData->ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error seting curve prime\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    if (rc == 0) {
	G = EC_POINT_new(eCurveData->G);			/* freed @5 */
	if (G == NULL ){
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: EC_POINT_new failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	rc = TSS_BN_hex2bn(&x,					/* freed @6 */
			   "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    }
    if (rc == 0) {
	rc = TSS_BN_hex2bn(&y,					/* freed @7 */
			   "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    }
    if (rc == 0) {
	if (EC_POINT_set_affine_coordinates_GFp(eCurveData->G, G, x, y, eCurveData->ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: Error, "
				   "Cannot create TPM public point from coordinates\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    /* sanity check to see if point is on the curve */
    if (rc == 0) {
	if (EC_POINT_is_on_curve(eCurveData->G, G, eCurveData->ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: Error, "
				   "Point not on curve\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    if (rc == 0) {
	rc = TSS_BN_hex2bn(&z,					/* freed @8 */
			   "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    }
    if (rc == 0) {
	if (EC_GROUP_set_generator(eCurveData->G, G, z, BN_value_one()) == 0) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: Error, "
				   "EC_GROUP_set_generator()\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
        }
    }
    if (rc == 0) {
	if (EC_GROUP_check(eCurveData->G, eCurveData->ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: Error, "
				   "EC_GROUP_check()\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
        }
    }
    if (rc == 0) {
	if (EC_KEY_set_group(myecc, eCurveData->G) == 0) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: Error, "
				   "EC_KEY_set_group()\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
        }
    }
    if (rc == 0) {
#if 0
	if (tssVverbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				"Address of eCurveData->G is %p\n", eCurveData->G);
	if (tssVverbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				"Address of eCurveData->CTX is %p\n", eCurveData->ctx);
#endif
	if (tssVverbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				"Set group for key\n");
    }
    /* Create the public/private EC key pair here */
    if (rc == 0) {
	if (EC_KEY_generate_key(myecc) == 0) 	{
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error generating the ECC key.\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    if (rc == 0) {
	if (!EC_KEY_check_key(myecc)) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error on EC_KEY_check_key()\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    if (p != NULL)	BN_clear_free(p);	/* @1 */
    if (a != NULL)	BN_clear_free(a);	/* @2 */
    if (b != NULL) 	BN_clear_free(b);	/* @3 */
    if (rc != 0) {
	EC_GROUP_free(eCurveData->G);	/* @4 */
	EC_POINT_free(G);		/* @5  */
    }
    if (x != NULL)	BN_clear_free(x);	/* @6 */
    if (y != NULL)	BN_clear_free(y);	/* @7 */
    if (z != NULL)	BN_clear_free(z);	/* @8 */

    /* don't free the key info.  This curve was constructed out of parameters, not of the openssl
       library */
    /* EC_KEY_free(myecc) */
    /* EC_POINT_free(G); */
    return rc;
}

#endif

/* TSS_ECC_Salt() returns both the plaintext and excrypted salt, based on the salt key bPublic.

   This is currently hard coded to the TPM_ECC_NIST_P256 curve.
*/

TPM_RC TSS_ECC_Salt(TPM2B_DIGEST 		*salt,
		    TPM2B_ENCRYPTED_SECRET	*encryptedSalt,
		    TPMT_PUBLIC			*publicArea)
{
    TPM_RC		rc = 0;
    salt = salt;
    encryptedSalt = encryptedSalt;
    publicArea = publicArea;
    if (tssVerbose) printf("TSS_ECC_Salt: Unimplemented for mbedtls library\n");
    rc = TSS_RC_COMMAND_UNIMPLEMENTED;
#if 0
    EC_KEY		*myecc = NULL;		/* ephemeral key */
    const BIGNUM	*d_caller; 		/* ephemeral private key */
    const EC_POINT	*callerPointPub; 	/* ephemeral public key */
    EC_POINT		*tpmPointPub = NULL;
    BIGNUM		*p_tpmX = NULL;
    BIGNUM		*bigY = NULL;
    BIGNUM 		*zBn = NULL;
    EC_POINT 		*rPoint = NULL;
    BIGNUM 		*thepoint = NULL;
    BIGNUM		*sharedX = NULL;
    BIGNUM		*yBn = NULL;
    uint32_t		sizeInBytes;
    uint32_t		sizeInBits;
    uint8_t             *sharedXBin = NULL;
    unsigned int	lengthSharedXBin;
    BIGNUM		*p_caller_Xbn = NULL;
    BIGNUM		*p_caller_Ybn = NULL;
    uint8_t		*p_caller_Xbin = NULL;
    uint8_t		*p_caller_Ybin = NULL;
    uint8_t		*p_tpmXbin = NULL;
    unsigned int 	length_p_caller_Xbin;
    unsigned int 	length_p_caller_Ybin;
    unsigned int	length_p_tpmXbin;
    TPM2B_ECC_PARAMETER	sharedX_For_KDFE;
    TPM2B_ECC_PARAMETER	p_caller_X_For_KDFE;
    TPM2B_ECC_PARAMETER	p_tpmX_For_KDFE;
    CURVE_DATA 		eCurveData;

    eCurveData.ctx = NULL;	/* for free */
    eCurveData.G = NULL;	/* this is initialized in TSS_ECC_GeneratePlatformEphemeralKey() at
				   EC_GROUP_new() but gcc -O3 emits a warning that it's
				   uninitialized. */
    /* only NIST P256 is currently supported */
    if (rc == 0) {
	if ((publicArea->parameters.eccDetail.curveID != TPM_ECC_NIST_P256)) {
	    if (tssVerbose)
		printf("TSS_ECC_Salt: ECC curve ID %04x not supported\n",
		       publicArea->parameters.eccDetail.curveID);
	    rc = TSS_RC_BAD_SALT_KEY;
	}
    }
    if (rc == 0) {
	myecc = EC_KEY_new();		/* freed @1 */
	if (myecc == NULL) {
	    if (tssVerbose) printf("TSS_ECC_Salt: EC_KEY_new failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	eCurveData.ctx = BN_CTX_new();	/* freed @16 */
	if (eCurveData.ctx == NULL) {
	    if (tssVerbose) printf("TSS_ECC_Salt: BN_CTX_new failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* Generate the TSS EC ephemeral key pair outside the TPM for the salt. The public part of this
       key is actually the 'encrypted' salt. */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_Salt: "
				"Calling TSS_ECC_GeneratePlatformEphemeralKey\n");
	rc = TSS_ECC_GeneratePlatformEphemeralKey(&eCurveData, myecc);
    }
    if (rc == 0) {
	d_caller = EC_KEY_get0_private_key(myecc);		/* ephemeral private key */
	callerPointPub = EC_KEY_get0_public_key(myecc); 	/* ephemeral public key */
    }
    /* validate that the public point is on the NIST P-256 curve */
    if (rc == 0) 		{
	if (EC_POINT_is_on_curve(eCurveData.G, callerPointPub, eCurveData.ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				   "Generated point not on curve\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    if (rc == 0) {
	/* let d_caller be private scalar and P_caller be public point */
	/* p_tpm is public point. p_tpmX is to be X-coordinate and p_tpmY the
	   Y-coordinate */

	/* Allocate the space for P_tpm */
	tpmPointPub = EC_POINT_new(eCurveData.G); 			/* freed @2 */
	if (tpmPointPub == NULL) {
	    if (tssVerbose) printf("TSS_ECC_Salt: EC_POINT_new failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* grab the public point x and y using the parameters passed in */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_Salt: "
				"Salt key sizes are X: %d and Y: %d\n",
				publicArea->unique.ecc.x.t.size,
				publicArea->unique.ecc.y.t.size);
	p_tpmX = BN_bin2bn((const unsigned char *)&publicArea->unique.ecc.x.t.buffer,
			   publicArea->unique.ecc.x.t.size, NULL);	/* freed @3 */
	if (p_tpmX == NULL) {
	    if (tssVerbose) printf("TSS_ECC_Salt: BN_bin2bn p_tpmX failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	bigY = BN_bin2bn((const unsigned char*)&publicArea->unique.ecc.y.t.buffer,
			 publicArea->unique.ecc.y.t.size, bigY);	/* freed @15 */
	if (bigY == NULL) {
	    if (tssVerbose) printf("TSS_ECC_Salt: BN_bin2bn bigY failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_Salt: "
				"Salt public key X %s\n", BN_bn2hex(p_tpmX));
	if (tssVverbose) printf("TSS_ECC_Salt: "
				"Salt public key Y %s\n", BN_bn2hex(bigY));
    }
    /* Create the openssl form of the TPM salt public key as EC_POINT using coordinates */
    if (rc == 0) {
	if (EC_POINT_set_affine_coordinates_GFp
	    (eCurveData.G, tpmPointPub, p_tpmX, bigY, eCurveData.ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				   "Cannot create TPM public point from coordinates\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    /* RFC 2440 Named curve prime256v1 */
    if (rc == 0) {
	rc = TSS_BN_hex2bn(&zBn,			/* freed @4 */
			   "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    }
    /* add the generator z to the group we are constructing */
    if (rc == 0) {
	if (EC_GROUP_set_generator(eCurveData.G, tpmPointPub, zBn, BN_value_one()) == 0) {
	    if(tssVerbose) printf ("TSS_ECC_Salt: "
				   "Error EC_GROUP_set_generator()\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    /* Check for validity of our group  */
    if (rc == 0) {
	if (EC_GROUP_check(eCurveData.G, eCurveData.ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				   "ec_group_check() failed\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    /* Check to see if what we think is the TPM point is on the curve */
    if (rc == 0) {
	if (EC_POINT_is_on_curve(eCurveData.G, tpmPointPub, eCurveData.ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_Salt: Error, "
				   "Point not on curve\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
	else {
	    if (tssVverbose) printf("TSS_ECC_Salt: "
				    "Validated that TPM EC point is on curve\n");
	}
    }
    if (rc == 0) {
	rPoint = EC_POINT_new(eCurveData.G);
	if (rPoint == NULL) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				   "Cannot create rPoint\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    /* Point multiply the TPM public point by the ephemeral scalar. This will produce the
       point from which we get the shared X coordinate, which we keep for use in KDFE. The
       TPM will calculate the same X. */
    if (rc == 0) {
	if (EC_POINT_mul(eCurveData.G, rPoint, NULL, tpmPointPub,
			 d_caller, eCurveData.ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				   "EC_POINT_mul failed\n") ;
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
	else {
	    if (tssVverbose) printf("TSS_ECC_Salt: "
				    "EC_POINT_mul() succeeded\n");
	}
    }
    /* Check to see if calculated point is on the curve, just for extra sanity */
    if (rc == 0) {
	if (EC_POINT_is_on_curve(eCurveData.G, rPoint, eCurveData.ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_Salt: Error,"
				   "Point r is not on curve\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
	else {
	    if (tssVverbose) printf("TSS_ECC_Salt: "
				    "Point calculated by EC_POINT_mul() is on the curve\n");
	}
    }
    if (rc == 0) {
	thepoint = EC_POINT_point2bn(eCurveData.G, rPoint, POINT_CONVERSION_UNCOMPRESSED,
				     NULL, eCurveData.ctx);	/* freed @6 */
	if (thepoint == NULL) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				   "EC_POINT_point2bn thepoint failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* get sharedX */
    if (rc == 0) {
	rc = TSS_BN_new(&sharedX);		/* freed @7 */
    }
    if (rc == 0) {
	rc = TSS_BN_new(&yBn);			/* freed @8 */
    }
    if (rc == 0) {
	if (EC_POINT_get_affine_coordinates_GFp(eCurveData.G, rPoint,
						sharedX, yBn, eCurveData.ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				   "EC_POINT_get_affine_coordinates_GFp() failed\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    if (rc == 0) {
	sizeInBytes = TSS_GetDigestSize(publicArea->nameAlg);
	sizeInBits =  sizeInBytes * 8;
	rc = TSS_Malloc(&sharedXBin, BN_num_bytes(sharedX));		/* freed @9 */
    }
    if (rc == 0) {
	lengthSharedXBin = (unsigned int)BN_bn2bin(sharedX, sharedXBin);
	if (tssVverbose) TSS_PrintAll("TSS_ECC_Salt: sharedXBin",
				      sharedXBin,
				      lengthSharedXBin);
    }
    /* encrypted salt is just the ephemeral public key */
    if (rc == 0) {
	rc = TSS_BN_new(&p_caller_Xbn);			/* freed 10 */
    }
    if (rc == 0) {
	rc = TSS_BN_new(&p_caller_Ybn);			/* freed @11 */
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_Salt: "
				"Allocated space for ephemeral BIGNUM X, Y\n");
    }
    /* Get the X-coordinate and Y-Coordinate */
    if (rc == 0) {
	if (EC_POINT_get_affine_coordinates_GFp(eCurveData.G, callerPointPub,
						p_caller_Xbn, p_caller_Ybn,
						eCurveData.ctx) == 0) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				   "EC_POINT_get_affine_coordinates_GFp() failed\n");
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
	else {
	    if (tssVverbose) printf("TSS_ECC_Salt: "
				    "Retrieved X and Y coordinates from ephemeral public\n");
	}
    }
    if (rc == 0) {
	rc = TSS_Malloc(&p_caller_Xbin, BN_num_bytes(p_caller_Xbn));	/* freed @12 */
    }
    if (rc == 0) {
	rc = TSS_Malloc(&p_caller_Ybin , BN_num_bytes(p_caller_Ybn));	/* freed @13 */
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_Salt: "
				"Allocated space for ephemeral binary X and y\n");
    }
    if (rc == 0) {
	rc = TSS_Malloc(&p_tpmXbin, BN_num_bytes(p_tpmX));		/* freed @14 */
    }
    if (rc == 0) {
	length_p_tpmXbin = (unsigned int)BN_bn2bin(p_tpmX, p_tpmXbin);
	if (tssVverbose) TSS_PrintAll("TSS_ECC_Salt: p_tpmXbin ",
				      p_tpmXbin,
				      length_p_tpmXbin);
	length_p_caller_Xbin = (unsigned int)BN_bn2bin(p_caller_Xbn, p_caller_Xbin);
	if (tssVverbose) TSS_PrintAll("TSS_ECC_Salt: p_caller_Xbin",
				      p_caller_Xbin,
				      length_p_caller_Xbin);
	length_p_caller_Ybin = (unsigned int)BN_bn2bin(p_caller_Ybn, p_caller_Ybin);
	if (tssVverbose) TSS_PrintAll("TSS_ECC_Salt: p_caller_Ybin",
				      p_caller_Ybin,
				      length_p_caller_Ybin);
    }
    /* in->encryptedSalt TPM2B_ENCRYPTED_SECRET is a size and TPMU_ENCRYPTED_SECRET secret.
       TPMU_ENCRYPTED_SECRET is a TPMS_ECC_POINT
       TPMS_ECC_POINT has two TPMB_ECC_PARAMETER, x and y
    */
    if (rc == 0) {
	/* TPMS_ECC_POINT 256/8 is a hard coded value for NIST P256, the only curve
	   currently supported */
	uint8_t *secret = encryptedSalt->t.secret;	/* TPMU_ENCRYPTED_SECRET pointer for
							   clarity */
	/* TPM2B_ENCRYPTED_SECRET size */
	encryptedSalt->t.size = sizeof(uint16_t) + (256/8) + sizeof(uint16_t) + (256/8);
	/* leading zeros, because some points may be less than 32 bytes */
	memset(secret, 0, sizeof(TPMU_ENCRYPTED_SECRET));
	/* TPMB_ECC_PARAMETER X point */
	*(uint16_t *)(secret) = htons(256/8);
	memcpy(secret +
	       sizeof(uint16_t) + (256/8) - length_p_caller_Xbin,
	       p_caller_Xbin, length_p_caller_Xbin);
	/* TPMB_ECC_PARAMETER Y point */
	*(uint16_t *)(secret + sizeof(uint16_t) + (256/8)) = htons(256/8);
	memcpy(secret +
	       sizeof(uint16_t) + (256/8) +
	       sizeof(uint16_t) + (256/8) - length_p_caller_Ybin,
	       p_caller_Ybin, length_p_caller_Ybin);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_ECC_Salt: ECC encrypted salt",
				      encryptedSalt->t.secret,
				      encryptedSalt->t.size);
    }
    /* TPM2B_ECC_PARAMETER sharedX_For_KDFE */
    if (rc == 0) {
	if (lengthSharedXBin > 32) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				   "lengthSharedXBin %u too large\n",
				   lengthSharedXBin);
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    if (rc == 0) {
	sharedX_For_KDFE.t.size = 32;
	memset(sharedX_For_KDFE.t.buffer, 0, sizeof(sharedX_For_KDFE.t.buffer));
	memcpy(sharedX_For_KDFE.t.buffer + 32 - lengthSharedXBin,
	       sharedXBin, lengthSharedXBin);
	if (tssVverbose) TSS_PrintAll("TSS_ECC_Salt: sharedX_For_KDFE",
				      sharedX_For_KDFE.t.buffer,
				      sharedX_For_KDFE.t.size);
    }
    /* TPM2B_ECC_PARAMETER p_caller_X_For_KDFE */
    if (rc == 0) {
	if (length_p_caller_Xbin > 32) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				   "length_p_caller_Xbin %u too large\n",
				   length_p_caller_Xbin);
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    if (rc == 0) {
	p_caller_X_For_KDFE.t.size = 32;
	memset(p_caller_X_For_KDFE.t.buffer, 0, sizeof(p_caller_X_For_KDFE.t.buffer));
	memcpy(p_caller_X_For_KDFE.t.buffer + 32 - length_p_caller_Xbin,
	       p_caller_Xbin, length_p_caller_Xbin);
	if (tssVverbose) TSS_PrintAll("TSS_ECC_Salt: p_caller_X_For_KDFE",
				      p_caller_X_For_KDFE.t.buffer,
				      p_caller_X_For_KDFE.t.size);
    }
    /* p_tpmX_For_KDFE */
    if (rc == 0) {
	if (length_p_tpmXbin > 32) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				   "length_p_tpmXbin %u too large\n",
				   length_p_tpmXbin);
	    rc = TSS_RC_EC_EPHEMERAL_FAILURE;
	}
    }
    if (rc == 0) {
	p_tpmX_For_KDFE .t.size = 32;
	memset(p_tpmX_For_KDFE.t.buffer, 0, sizeof(p_tpmX_For_KDFE.t.buffer));
	memcpy(p_tpmX_For_KDFE.t.buffer + 32 - length_p_tpmXbin,
	       p_tpmXbin, length_p_tpmXbin);
	if (tssVverbose) TSS_PrintAll("TSS_ECC_Salt: p_tpmX_For_KDFE",
				      p_tpmX_For_KDFE.t.buffer,
				      p_tpmX_For_KDFE.t.size);
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_Salt: "
				"Calling TSS_KDFE\n");
	/* TPM2B_DIGEST salt size is the largest supported digest algorithm.
	   This has already been validated when unmarshaling the Name hash algorithm.
	*/
	/* salt = KDFe(tpmKey_NameAlg, sharedX, "SECRET", P_caller, P_tpm,
	   tpmKey_NameAlgSizeBits) */
	salt->t.size = sizeInBytes;
	rc = TSS_KDFE((uint8_t *)&salt->t.buffer, 	/* KDFe output */
		      publicArea->nameAlg,		/* hash algorithm */
		      &sharedX_For_KDFE.b,		/* Z (key) */
		      "SECRET",				/* KDFe label */
		      &p_caller_X_For_KDFE.b,		/* context U */
		      &p_tpmX_For_KDFE.b,		/* context V */
		      sizeInBits);			/* required size of key in bits */
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_ECC_Salt: salt",
				      (uint8_t *)&salt->t.buffer,
				      salt->t.size);
    }
    /* cleanup */
    if (myecc != NULL) 		EC_KEY_free(myecc);		/* @1 */
    if (tpmPointPub != NULL)    EC_POINT_free(tpmPointPub);	/* @2 */
    if (p_tpmX != NULL)		BN_clear_free(p_tpmX);		/* @3 */
    if (zBn != NULL)            BN_clear_free(zBn);		/* @4 */
    if (rPoint != NULL)		EC_POINT_free(rPoint);		/* @5 */
    if (thepoint != NULL)       BN_clear_free(thepoint);	/* @6 */
    if (sharedX != NULL)        BN_clear_free(sharedX);		/* @7 */
    if (yBn != NULL)		BN_clear_free(yBn);		/* @8 */
    free(sharedXBin);						/* @9 */
    if (p_caller_Xbn != NULL)   BN_clear_free(p_caller_Xbn);	/* @10 */
    if (p_caller_Ybn != NULL)   BN_clear_free(p_caller_Ybn);	/* @11 */
    free(p_caller_Xbin);					/* @12 */
    free(p_caller_Ybin);					/* @13 */
    free(p_tpmXbin);						/* @14 */
    if (bigY != NULL)           BN_clear_free(bigY);		/* @15 */
    if (eCurveData.ctx != NULL)	BN_CTX_free(eCurveData.ctx);	/* @16 */
#endif	/* 0 */
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/*
  AES
*/

TPM_RC TSS_AES_GetEncKeySize(size_t *tssSessionEncKeySize)
{
    *tssSessionEncKeySize = sizeof(mbedtls_aes_context);
    return 0;
}
TPM_RC TSS_AES_GetDecKeySize(size_t *tssSessionDecKeySize)
{
    *tssSessionDecKeySize = sizeof(mbedtls_aes_context);
    return 0;
}

#define TSS_AES_KEY_BITS 128

#ifndef TPM_TSS_NOCRYPTO
#ifndef TPM_TSS_NOFILE

TPM_RC TSS_AES_KeyGenerate(void *tssSessionEncKey,
			   void *tssSessionDecKey)
{
    TPM_RC		rc = 0;
    int 		irc;
    unsigned char 	userKey[AES_128_BLOCK_SIZE_BYTES];
    const char 		*envKeyString = NULL;
    unsigned char 	*envKeyBin = NULL;
    size_t 		envKeyBinLen;

    if (rc == 0) {
	envKeyString = getenv("TPM_SESSION_ENCKEY");
    }
    if (envKeyString == NULL) {
	/* If the env variable TPM_SESSION_ENCKEY is not set, generate a random key for this
	   TSS_CONTEXT */
	if (rc == 0) {
	    rc = TSS_RandBytes(userKey, AES_128_BLOCK_SIZE_BYTES);
	}
    }
    /* The env variable TPM_SESSION_ENCKEY can set a (typically constant) encryption key.  This is
       useful for scripting, where the env variable is set to a random seed at the beginning of the
       script. */
    else {
	/* hexascii to binary */
	if (rc == 0) {
	    rc = TSS_Array_Scan(&envKeyBin,			/* freed @1 */
				&envKeyBinLen, envKeyString);
	}
	/* range check */
	if (rc == 0) {
	    if (envKeyBinLen != AES_128_BLOCK_SIZE_BYTES) {
		if (tssVerbose)
		    printf("TSS_AES_KeyGenerate: Error, env variable length %lu not %lu\n",
			   (unsigned long)envKeyBinLen, (unsigned long)sizeof(userKey));
		rc = TSS_RC_BAD_PROPERTY_VALUE;
	    }
	}
	/* copy the binary to the common userKey for use below */
	if (rc == 0) {
	    memcpy(userKey, envKeyBin, envKeyBinLen);
	}
    }
    /* translate to an mbedtls key token */
    if (rc == 0) {
	mbedtls_aes_init(tssSessionEncKey);
	irc = mbedtls_aes_setkey_enc(tssSessionEncKey, userKey, TSS_AES_KEY_BITS);
	if (irc != 0) {
	    TSS_Error(irc);
	    if (tssVerbose)
		printf("TSS_AES_KeyGenerate: Error setting mbedtls AES encryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	}
    }
    if (rc == 0) {
	mbedtls_aes_init(tssSessionDecKey);
	irc = mbedtls_aes_setkey_dec(tssSessionDecKey, userKey, TSS_AES_KEY_BITS);
	if (irc != 0) {
	    TSS_Error(irc);
            if (tssVerbose) {
		printf("TSS_AES_KeyGenerate: Error setting mbedtls AES decryption key\n");
	    }
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	}
    }
    free(envKeyBin);	/* @1 */
    return rc;
}

#endif
#endif

/* TSS_AES_Encrypt() is AES non-portable code to encrypt 'decrypt_data' to 'encrypt_data' using CBC.
   This function uses the session encryption key for encrypting session state.

   The stream is padded as per PKCS#7 / RFC2630

   'encrypt_data' must be free by the caller
*/

#ifndef TPM_TSS_NOFILE

TPM_RC TSS_AES_Encrypt(void *tssSessionEncKey,
		       unsigned char **encrypt_data,   		/* output, caller frees */
		       uint32_t *encrypt_length,		/* output */
		       const unsigned char *decrypt_data,	/* input */
		       uint32_t decrypt_length)			/* input */
{
    TPM_RC		rc = 0;
    int 		irc;
    uint32_t		pad_length;
    unsigned char	*decrypt_data_pad;
    unsigned char	ivec[AES_128_BLOCK_SIZE_BYTES];       /* initial chaining vector */

    decrypt_data_pad = NULL;    /* freed @1 */
    if (rc == 0) {
        /* calculate the pad length and padded data length */
        pad_length = AES_128_BLOCK_SIZE_BYTES - (decrypt_length % AES_128_BLOCK_SIZE_BYTES);
        *encrypt_length = decrypt_length + pad_length;
	/* allocate memory for the encrypted response */
        rc = TSS_Malloc(encrypt_data, *encrypt_length);
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        rc = TSS_Malloc(&decrypt_data_pad, *encrypt_length);
    }
    /* pad the decrypted clear text data */
    if (rc == 0) {
        /* unpadded original data */
        memcpy(decrypt_data_pad, decrypt_data, decrypt_length);
        /* last gets pad = pad length */
        memset(decrypt_data_pad + decrypt_length, pad_length, pad_length);
        /* set the IV */
        memset(ivec, 0, sizeof(ivec));
        /* encrypt the padded input to the output */
        irc = mbedtls_aes_crypt_cbc(tssSessionEncKey,
				    MBEDTLS_AES_ENCRYPT,
				    *encrypt_length,
				    ivec,
				    decrypt_data_pad,
				    *encrypt_data);
	if (irc != 0) {
	    TSS_Error(irc);
	    if (tssVerbose) printf("TSS_AES_Encrypt: Encryption failure -%04x\n", -irc);
	    rc = TSS_RC_AES_ENCRYPT_FAILURE;
	}
    }
    free(decrypt_data_pad);     /* @1 */
    return rc;
}

#endif 	/* TPM_TSS_NOFILE */

/* TSS_AES_Decrypt() is AES non-portable code to decrypt 'encrypt_data' to 'decrypt_data' using CBC.
   This function uses the session encryption key for decrypting session state.

   The stream must be padded as per PKCS#7 / RFC2630

   decrypt_data must be free by the caller
*/

#ifndef TPM_TSS_NOFILE

TPM_RC TSS_AES_Decrypt(void *tssSessionDecKey,
		       unsigned char **decrypt_data,   		/* output, caller frees */
		       uint32_t *decrypt_length,		/* output */
		       const unsigned char *encrypt_data,	/* input */
		       uint32_t encrypt_length)			/* input */
{
    TPM_RC          	rc = 0;
    int 		irc;
    uint32_t		pad_length;
    uint32_t		i;
    unsigned char       *pad_data;
    unsigned char       ivec[AES_128_BLOCK_SIZE_BYTES];       /* initial chaining vector */

    /* sanity check encrypted length */
    if (rc == 0) {
        if (encrypt_length < AES_128_BLOCK_SIZE_BYTES) {
            if (tssVerbose) printf("TSS_AES_Decrypt: Error, bad length %u\n",
				   encrypt_length);
            rc = TSS_RC_AES_DECRYPT_FAILURE;
        }
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        rc = TSS_Malloc(decrypt_data, encrypt_length);
    }
    /* decrypt the input to the padded output */
    if (rc == 0) {
        /* set the IV */
        memset(ivec, 0, sizeof(ivec));
        /* decrypt the padded input to the output */
        irc = mbedtls_aes_crypt_cbc(tssSessionDecKey,
				    MBEDTLS_AES_DECRYPT,
				    encrypt_length,
				    ivec,
				    encrypt_data,
				    *decrypt_data);
    }
    /* get the pad length */
    if (rc == 0) {
        /* get the pad length from the last byte */
        pad_length = (uint32_t)*(*decrypt_data + encrypt_length - 1);
        /* sanity check the pad length */
        if ((pad_length == 0) ||
            (pad_length > AES_128_BLOCK_SIZE_BYTES)) {
            if (tssVerbose) printf("TSS_AES_Decrypt: Error, illegal pad length\n");
            rc = TSS_RC_AES_DECRYPT_FAILURE;
        }
    }
    if (rc == 0) {
        /* get the unpadded length */
        *decrypt_length = encrypt_length - pad_length;
        /* pad starting point */
        pad_data = *decrypt_data + *decrypt_length;
        /* sanity check the pad */
        for (i = 0 ; (rc == 0) && (i < pad_length) ; i++, pad_data++) {
            if (*pad_data != pad_length) {
                if (tssVerbose) printf("TSS_AES_Decrypt: Error, bad pad %02x at index %u\n",
				       *pad_data, i);
                rc = TSS_RC_AES_DECRYPT_FAILURE;
            }
        }
    }
    return rc;
}

#endif 	/* TPM_TSS_NOFILE */

/* TSS_AES_EncryptCFB() is the unpadded AES used for command parameter encryption.

   The input and output are the same length.
*/

TPM_RC TSS_AES_EncryptCFB(uint8_t	*dOut,		/* OUT: the encrypted data */
			  uint32_t	keySizeInBits,	/* IN: key size in bits */
			  uint8_t 	*key,           /* IN: key buffer */
			  uint8_t 	*iv,		/* IN/OUT: IV for decryption */
			  uint32_t	dInSize,       	/* IN: data size */
			  uint8_t 	*dIn)		/* IN: data buffer */
{
    TPM_RC		rc = 0;
    int 		irc;
    mbedtls_aes_context aes_ctx;

    mbedtls_aes_init(&aes_ctx);
    if (rc == 0) {
	irc = mbedtls_aes_setkey_enc(&aes_ctx, key, keySizeInBits);	/* freed @1 */
	if (irc != 0) {
	    TSS_Error(irc);
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	}
    }
    if (rc == 0) {
	size_t iv_off = 0;
	irc = mbedtls_aes_crypt_cfb128(&aes_ctx,
				       MBEDTLS_AES_ENCRYPT,
				       dInSize,
				       &iv_off,
				       iv,
				       dIn,
				       dOut);
	if (irc != 0) {
	    TSS_Error(irc);
	    if (tssVerbose) printf("TSS_AES_EncryptCFB: Encryption failure -%04x\n", -irc);
	    rc = TSS_RC_AES_ENCRYPT_FAILURE;
	}
    }
    mbedtls_aes_free(&aes_ctx);		/* @1 */
    return rc;
}

/* TSS_AES_DecryptCFB() is the unpadded AES used for response parameter decryption.

   The input and output are the same length.
*/

TPM_RC TSS_AES_DecryptCFB(uint8_t *dOut,          	/* OUT: the decrypted data */
			  uint32_t keySizeInBits, 	/* IN: key size in bits */
			  uint8_t *key,           	/* IN: key buffer */
			  uint8_t *iv,            	/* IN/OUT: IV for decryption. */
			  uint32_t dInSize,       	/* IN: data size */
			  uint8_t *dIn)			/* IN: data buffer */
{
    TPM_RC		rc = 0;
    int 		irc;
    mbedtls_aes_context aes_ctx;

    if (tssVverbose) TSS_PrintAll("TSS_AES_DecryptCFB:", key, keySizeInBits/8);
    mbedtls_aes_init(&aes_ctx);
    if (rc == 0) {
	irc = mbedtls_aes_setkey_enc(&aes_ctx, key, keySizeInBits);	/* freed @1 */
	if (irc != 0) {
	    TSS_Error(irc);
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	}
    }
    if (rc == 0) {
	size_t iv_off = 0;
	irc = mbedtls_aes_crypt_cfb128(&aes_ctx,
				       MBEDTLS_AES_DECRYPT,
				       dInSize,
				       &iv_off,
				       iv,
				       dIn,
				       dOut);
	if (irc != 0) {
	    TSS_Error(irc);
	    if (tssVerbose) printf("TSS_AES_DecryptCFB: Decryption failure -%04x\n", -irc);
	    rc = TSS_RC_AES_DECRYPT_FAILURE;
	}
    }
    mbedtls_aes_free(&aes_ctx);		/* @1 */
    return rc;
}
