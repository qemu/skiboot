/********************************************************************************/
/*										*/
/*			 Ultravisor Support Interface  				*/
/*										*/
/* (c) Copyright IBM Corporation 2019						*/
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

#ifdef __ULTRAVISOR__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssfile.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Startup_fp.h>
#include "tssproperties.h"

#include "tssuv.h"

// PEF policyccdecrypt-auth
unsigned char pefpolicies_policyccdecrypt_auth_bin[] = {
  0x8d, 0xbd, 0x2a, 0xa1, 0x0f, 0x70, 0x1b, 0x1e, 0xda, 0x23, 0x0f, 0xa8,
  0xa3, 0x88, 0x03, 0xd3, 0x42, 0xf3, 0xb4, 0x8c, 0x2f, 0xfc, 0xbe, 0xd5,
  0x6c, 0x04, 0x67, 0x4c, 0x79, 0xdf, 0xf0, 0x0f
};
unsigned int pefpolicies_policyccdecrypt_auth_bin_len = 32;

// PEF axonepolicyb
unsigned char pefpolicies_axonepolicyb_bin[] = {
  0xfc, 0x02, 0xa3, 0x69, 0x58, 0xb0, 0x3f, 0xce, 0x29, 0x71, 0xa3, 0xb0,
  0x54, 0xb5, 0xad, 0xcc, 0x9d, 0x76, 0x3f, 0x54, 0xc9, 0x7f, 0x15, 0x83,
  0x7b, 0xc3, 0x71, 0x86, 0x65, 0x0f, 0xc4, 0xd3
};
unsigned int pefpolicies_axonepolicyb_bin_len = 32;

TPMI_DH_OBJECT tss_uv_keyHandle = 0x81800000;

#if 0 // Do not need this anymore? post ken readpublic update.
// h81800000.bin
unsigned char __h81800000_bin[] = {
  0x00, 0x0b, 0xf6, 0x53, 0xa9, 0xe0, 0xb0, 0x0f, 0x97, 0x76, 0x82, 0xa8,
  0x5e, 0xfb, 0xca, 0x3f, 0x59, 0x3d, 0x28, 0x3a, 0x1f, 0x10, 0xb5, 0x96,
  0xa6, 0x5e, 0x79, 0xf3, 0x45, 0x07, 0xa3, 0x6d, 0xe8, 0xe1
};
unsigned int __h81800000_bin_len = 34;
#endif

/** @todo (andmike) Pub bin to be passed in from OPAL */
unsigned char pefpolicies_o1pub_bin[] = {
  0x01, 0x38, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x0c, 0x20, 0x00, 0x20,
  0x63, 0x73, 0xdf, 0x8b, 0x9d, 0x61, 0xac, 0x6b, 0x5d, 0xd9, 0xac, 0x19,
  0x14, 0x63, 0x76, 0xb6, 0x64, 0x77, 0x58, 0x66, 0xde, 0x15, 0xd1, 0xc2,
  0x91, 0xef, 0x92, 0x6f, 0x55, 0xeb, 0x73, 0x20, 0x00, 0x10, 0x00, 0x17,
  0x00, 0x0b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc2, 0xf2,
  0x16, 0x20, 0x00, 0x01, 0x2c, 0xa1, 0xea, 0x99, 0x76, 0x44, 0x49, 0xe7,
  0x6b, 0xd6, 0xb6, 0x28, 0x51, 0x34, 0xc5, 0x2e, 0xa7, 0x4e, 0x0e, 0x7c,
  0x1b, 0x30, 0x03, 0xca, 0x7a, 0x0b, 0xe0, 0x8d, 0x7e, 0x44, 0x8e, 0x03,
  0x5e, 0x16, 0xdc, 0x79, 0xf1, 0x3a, 0x86, 0x2f, 0x66, 0xbc, 0xa0, 0x2d,
  0xb6, 0x5c, 0x73, 0x12, 0x6c, 0x00, 0xfa, 0xa7, 0xfa, 0x99, 0xb8, 0x9b,
  0xfe, 0x84, 0xf2, 0x9d, 0x0e, 0x98, 0xa9, 0x14, 0x74, 0x7d, 0x1d, 0x37,
  0x6c, 0x37, 0x31, 0xd0, 0x7a, 0xdf, 0x2b, 0xd4, 0x79, 0x96, 0xc4, 0xea,
  0xe2, 0x1b, 0x23, 0x6f, 0x20, 0x76, 0x9d, 0x02, 0xb5, 0xa9, 0xf8, 0xb8,
  0x92, 0x92, 0x1c, 0x45, 0x8d, 0xb2, 0x92, 0x7e, 0xb7, 0x23, 0x91, 0xeb,
  0x6d, 0x63, 0xfa, 0xea, 0x74, 0xea, 0x62, 0x0b, 0x6f, 0x25, 0x31, 0x3f,
  0x82, 0x8b, 0xf3, 0x42, 0x26, 0x32, 0xec, 0x5d, 0xfc, 0x66, 0x09, 0x06,
  0x21, 0xa0, 0xcf, 0x16, 0xd5, 0x36, 0x8f, 0x59, 0x09, 0x10, 0x21, 0xed,
  0x5b, 0xa7, 0x57, 0x04, 0x9a, 0x2d, 0xbd, 0x70, 0xc1, 0x9e, 0x67, 0x71,
  0xb3, 0x20, 0x1c, 0x8c, 0xa4, 0x8d, 0x56, 0x98, 0x8c, 0x35, 0xfc, 0x57,
  0x37, 0x7a, 0x3a, 0x30, 0xea, 0x79, 0xfd, 0x62, 0xae, 0xfe, 0x50, 0xb8,
  0xd2, 0x82, 0x7a, 0xe4, 0x5c, 0x8b, 0xd5, 0xfe, 0xf3, 0x21, 0x81, 0x9b,
  0x3f, 0xc2, 0x1f, 0x70, 0x0d, 0xe9, 0x84, 0xf1, 0x6e, 0xe4, 0xd8, 0x38,
  0x6f, 0xa6, 0x02, 0x45, 0x1c, 0xc3, 0x10, 0xf6, 0x32, 0x36, 0x2d, 0x92,
  0x81, 0x3e, 0x3c, 0xc5, 0x79, 0x80, 0x71, 0xf9, 0x58, 0xc2, 0xa9, 0x37,
  0xb2, 0xa0, 0xf4, 0x39, 0xbd, 0x92, 0x7f, 0xd5, 0x03, 0x86, 0xc3, 0x54,
  0x85, 0xec, 0x21, 0x80, 0x46, 0x0f, 0xb5, 0x55, 0x78, 0x69, 0x8c, 0x4e,
  0x2d, 0xe9
};

unsigned int pefpolicies_o1pub_bin_len = 314;

// /* TPM2B Types */
//  typedef struct {
//    UINT16          size;
//    BYTE            buffer[1];
//  } TPM2B, *P2B;

///* Table 71 - Definition of TPM2B_DIGEST Structure */
//
//  typedef struct {
//      UINT16    size;
//      BYTE      buffer[sizeof(TPMU_HA)];
//  } DIGEST_2B;
//
//  typedef union {
//      DIGEST_2B    t;
//      TPM2B        b;
//  } TPM2B_DIGEST;

//
// typedef struct {
//      UINT32              count;          /* number of digests in the list, mini  mum is two for TPM2_PolicyOR(). */
//     TPM2B_DIGEST        digests[8];     /* a list of digests */
// } TPML_DIGEST;
//

TPML_DIGEST tss_uv_tpml_hashlist;

static void traceError(const char *command, TPM_RC rc)
{
    const char *msg;
    const char *submsg;
    const char *num;
    printf("%s: failed, rc %08x\n", command, rc);
    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
    printf("%s%s%s\n", msg, submsg, num);
}

/**
 * @brief readpublic fills the TSS context object slot with the
 *        wrapping key public part. The Name is required for
 *        the HMAC calculation.
 *
 */
static TPM_RC TSS_UV_ReadPublic(TSS_CONTEXT *tssContext,
		const TPMI_DH_OBJECT keyHandle)
{
	TPM_RC		rc;
	ReadPublic_In	*readPublicIn;
	ReadPublic_Out	*readPublicOut;
	uint8_t		*outPublicBuffer;
	uint16_t	outPublicWritten;

	readPublicIn = NULL;
	readPublicOut = NULL;
	outPublicBuffer = NULL;

	rc = TSS_Malloc((unsigned char **)&readPublicIn,
			sizeof(*readPublicIn));
	if (rc) {
	    traceError("readPublicIn malloc", rc);
	    goto out;
	}

	rc = TSS_Malloc((unsigned char **)&readPublicOut,
			sizeof(*readPublicOut));
	if (rc) {
	    traceError("readPublicOut malloc", rc);
	    goto readpublic_free;
	}

	readPublicIn->objectHandle = keyHandle;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)readPublicOut,
			 (COMMAND_PARAMETERS *)readPublicIn,
			 NULL,
			 TPM_CC_ReadPublic,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
	    goto readpublic_free;
	}

	/* marshal the wrapping key public part for the compare */
	rc = TSS_Structure_Marshal(&outPublicBuffer,
			&outPublicWritten,
			&readPublicOut->outPublic,
			(MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshalu);
	if (rc) {
		goto public_buffer_free;
	}

	if (outPublicWritten != pefpolicies_o1pub_bin_len) {
		rc = 1;
		goto public_buffer_free;
	}

	rc = memcmp(outPublicBuffer, pefpolicies_o1pub_bin,
			pefpolicies_o1pub_bin_len);

public_buffer_free:
	free(outPublicBuffer);
readpublic_free:
	free(readPublicOut);
	free(readPublicIn);
out:
	return rc;
}

static void TSS_UV_Init_Decrypt_Hashlist(TPML_DIGEST *hashlist)
{
	TPM2B *tpm2b;
	uint16_t targetSize;

	hashlist->count = 2;

	/* PEF policyccdecrypt-auth */
	tpm2b = &hashlist->digests[0].b;
	targetSize = sizeof(hashlist->digests[0].t.buffer);
	TSS_TPM2B_Create(tpm2b, pefpolicies_policyccdecrypt_auth_bin,
			(uint16_t)pefpolicies_policyccdecrypt_auth_bin_len,
			targetSize);

	/* PEF axonepolicyb */
	tpm2b = &hashlist->digests[1].b;
	targetSize = sizeof(hashlist->digests[1].t.buffer);
	TSS_TPM2B_Create(tpm2b, pefpolicies_axonepolicyb_bin,
			(uint16_t)pefpolicies_axonepolicyb_bin_len,
			targetSize);
}

static TPM_RC TSS_UV_Policy_AuthValue_In(TSS_CONTEXT *tssContext,
		TPMI_SH_AUTH_SESSION sessionHandle)
{
	TPM_RC			rc;
	PolicyAuthValue_In 	policyAuthValueIn;

	policyAuthValueIn.policySession = sessionHandle;
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&policyAuthValueIn,
			 NULL,
			 TPM_CC_PolicyAuthValue,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static TPM_RC TSS_UV_Policy_Or_In(TSS_CONTEXT *tssContext,
		TPMI_SH_AUTH_SESSION sessionHandle)
{
	TPM_RC			rc;
	TPML_DIGEST		*pHashList = &tss_uv_tpml_hashlist;
	PolicyOR_In 		*policyORIn;

	TSS_UV_Init_Decrypt_Hashlist(pHashList);

	policyORIn = NULL;

	rc = TSS_Malloc((unsigned char **)&policyORIn, sizeof(*policyORIn));
	if (rc) {
	    traceError("policyORIn malloc", rc);
	    goto out;
	}

	policyORIn->policySession = sessionHandle;
	policyORIn->pHashList = *pHashList;
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)policyORIn,
			 NULL,
			 TPM_CC_PolicyOR,
			 TPM_RH_NULL, NULL, 0);

	free(policyORIn);

out:
	return rc;
}

static TPM_RC TSS_UV_Policy_RSA_Decrypt(TSS_CONTEXT *tssContext,
		TPMI_SH_AUTH_SESSION sessionHandle)
{
	TPM_RC			rc;
	PolicyCommandCode_In 	policyCommandCodeIn;

	policyCommandCodeIn.policySession = sessionHandle;
	policyCommandCodeIn.code = TPM_CC_RSA_Decrypt;
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&policyCommandCodeIn,
			 NULL,
			 TPM_CC_PolicyCommandCode,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static TPM_RC TSS_UV_Start_Auth_Session(TSS_CONTEXT *tssContext,
		TPMI_SH_AUTH_SESSION *sessionHandle)
{
	TPM_RC			rc;
	StartAuthSession_In 	*startAuthSessionIn;
	StartAuthSession_Out 	*startAuthSessionOut;
	StartAuthSession_Extra	*startAuthSessionExtra;

	startAuthSessionIn = NULL;
	startAuthSessionOut = NULL;
	startAuthSessionExtra = NULL;

	rc = TSS_Malloc((unsigned char **)&startAuthSessionIn, sizeof(*startAuthSessionIn));
	if (rc) {
	    traceError("startAuthSessionIn malloc", rc);
	    goto out;
	}

	rc = TSS_Malloc((unsigned char **)&startAuthSessionOut, sizeof(*startAuthSessionOut));
	if (rc) {
	    traceError("startAuthSessionOut malloc", rc);
	    goto auth_session_free;
	}

	rc = TSS_Malloc((unsigned char **)&startAuthSessionExtra, sizeof(*startAuthSessionExtra));
	if (rc) {
	    traceError("startAuthSessionExtra malloc", rc);
	    goto auth_session_free;
	}

	startAuthSessionIn->sessionType = TPM_SE_POLICY;
	startAuthSessionIn->tpmKey = TPM_RH_NULL;
	startAuthSessionIn->bind = TPM_RH_NULL;
	startAuthSessionIn->encryptedSalt.b.size = 0;	/* (not required) */
	startAuthSessionIn->nonceCaller.t.size = 0;	/* (not required) */
	startAuthSessionIn->symmetric.algorithm = TPM_ALG_AES;
	startAuthSessionIn->authHash = TPM_ALG_SHA256;
	startAuthSessionIn->symmetric.keyBits.aes = 128;
	startAuthSessionIn->symmetric.mode.aes = TPM_ALG_CFB;
	startAuthSessionExtra->bindPassword = NULL;	/* (not required) */
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)startAuthSessionOut,
			 (COMMAND_PARAMETERS *)startAuthSessionIn,
			 (EXTRA_PARAMETERS *)startAuthSessionExtra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
	    goto auth_session_free;
	}

	*sessionHandle = startAuthSessionOut->sessionHandle;

auth_session_free:
	free(startAuthSessionIn);
	free(startAuthSessionOut);
	free(startAuthSessionExtra);
out:
	return rc;
}

#if 0
static TPM_RC TSS_NvPublic_GetSlotForHandle(TSS_CONTEXT *tssContext,
		size_t *slotIndex,
		TPMI_RH_NV_INDEX nvIndex)
{
	size_t 	i;

	/* search all slots for handle */
	for (i = 0 ; i < (sizeof(tssContext->nvPublic) / sizeof(TSS_NVPUBLIC)) ; i++) {
		if (tssContext->nvPublic[i].nvIndex == nvIndex) {
			*slotIndex = i;
			return 0;
		}
	}
	return TSS_RC_NO_NVPUBLIC_SLOT;
}
#endif

#if 0
static TPM_RC TSS_ObjectPublic_GetSlotForHandle(TSS_CONTEXT *tssContext,
		size_t *slotIndex,
		TPM_HANDLE handle)
{
	size_t      i;

	/* search all slots for handle */
	for (i = 0 ; i < (sizeof(tssContext->sessions) / sizeof(TSS_SESSIONS)) ; i++) {
		if (tssContext->objectPublic[i].objectHandle == handle) {
			*slotIndex = i;
			return 0;
		}
	}
	return TSS_RC_NO_OBJECTPUBLIC_SLOT;
}
#endif

#if 0
static TPM_RC TSS_Name_Store(TSS_CONTEXT *tssContext,
			     TPM2B_NAME *name,
			     TPM_HANDLE handle,
			     const char *string)
{
    TPM_RC 	rc = 0;
    TPM_HT 	handleType;
    size_t	slotIndex;

    printf("TSS_Name_Store: Handle %08x\n", handle);
    handleType = (TPM_HT) ((handle & HR_RANGE_MASK) >> HR_SHIFT);

    switch (handleType) {
      case TPM_HT_NV_INDEX:
	/* for NV, the Name was returned at creation */
	rc = TSS_NvPublic_GetSlotForHandle(tssContext, &slotIndex, handle);
	if (rc != 0) {
	    rc = TSS_NvPublic_GetSlotForHandle(tssContext, &slotIndex, TPM_RH_NULL);
	    if (rc == 0) {
		tssContext->nvPublic[slotIndex].nvIndex = handle;
	    }
	    else {
		printf("TSS_Name_Store: Error, no slot available for handle %08x\n", handle);
	    }
	}
	if (rc == 0) {
	    tssContext->nvPublic[slotIndex].name = *name;
	}
	break;
      case TPM_HT_TRANSIENT:
      case TPM_HT_PERSISTENT:
	if (rc == 0) {
	    if (string == NULL) {
		if (handle != 0) {
		    /* if this handle is already used, overwrite the slot */
		    rc = TSS_ObjectPublic_GetSlotForHandle(tssContext, &slotIndex, handle);
		    if (rc != 0) {
			rc = TSS_ObjectPublic_GetSlotForHandle(tssContext, &slotIndex, TPM_RH_NULL);
			if (rc == 0) {
			    tssContext->objectPublic[slotIndex].objectHandle = handle;
			}
			else {
				printf("TSS_Name_Store: "
				       "Error, no slot available for handle %08x\n",
				       handle);
			}
		    }
		}
		else {
		    printf("TSS_Name_Store: handle and string are both null");
		    rc = TSS_RC_NAME_FILENAME;
		}
	    }
	    else {
		if (handle == 0) {
		    printf("TSS_Name_Store: string unimplemented");
		    rc = TSS_RC_NAME_FILENAME;
		}
		else {
		    printf("TSS_Name_Store: handle and string are both not null");
		    rc = TSS_RC_NAME_FILENAME;
		}
	    }
	}
	if (rc == 0) {
	    tssContext->objectPublic[slotIndex].name = *name;
	}
	break;
      default:
	printf("TSS_Name_Store: handle type %02x unimplemented", handleType);
	rc = TSS_RC_NAME_FILENAME;
    }
    return rc;
}
#endif

/*
  TSS_UV_Decrypt()

  The policies contain 3 terms:

  Policy A should be a constant
  Policy B should be a constant based on the NV index attributes
  Policy C is calculated using the duplication authority public key

  @ uvContext	input, uv context
  @ keyPassword	input, pointer to nul terminated string password
  @ decLength	output, pointer to decrypted data length
  @ decBuffer	output, pointer to decrypted data
  @ encLength	input, encrypted data length
  @ encBuffer	input, encrypted data
  TBD Items below:
  @ keyHandle	input, TPM decryption key persistent handle, perhaps #define constant
  @ pHashList	input, pointer to a TPML_DIGEST containing the policy OR terms
*/

TPM_RC TSS_UV_Decrypt(void *uvContext, const char *keyPassword,
		uint16_t *decLength, uint8_t *decBuffer,
		uint16_t encLength, const uint8_t *encBuffer)
{
	TPM_RC			rc, _rc;
	TSS_CONTEXT		*tssContext;
	TPMI_SH_AUTH_SESSION	sessionHandle;
	TPMI_DH_OBJECT		keyHandle = tss_uv_keyHandle;
	RSA_Decrypt_In 		*rsa_DecryptIn;
	RSA_Decrypt_Out 	*rsa_DecryptOut;

	printf("%s: Enter pwd %s\n", __func__, keyPassword);

	/* Start a TSS context */
	rc = TSS_Create(&tssContext);
	if (rc) {
		return rc;
	}

	/* Set uv_ctx and interface type*/
	tssContext->uv_ctx = uvContext;
	tssContext->tssInterfaceType = "uv";

	rc = TSS_UV_ReadPublic(tssContext, keyHandle);
	if (rc) {
	    traceError("readpublic", rc);
	    goto out;
	}

	/* start the policy session */
	rc = TSS_UV_Start_Auth_Session(tssContext, &sessionHandle);
	if (rc) {
	    traceError("startauthsession", rc);
	    goto out;
	}

	/* Policy Command Code RSA Decrypt */
	rc = TSS_UV_Policy_RSA_Decrypt(tssContext, sessionHandle);
	if (rc) {
	    traceError("policycommandcode", rc);
	    goto out;
	}

	/* policy authvalue */
	rc = TSS_UV_Policy_AuthValue_In(tssContext, sessionHandle);
	if (rc) {
	    traceError("policyAuthValueIn", rc);
	    goto out;
	}

	/* policy or */
	rc = TSS_UV_Policy_Or_In(tssContext, sessionHandle);
	if (rc) {
	    traceError("policyor", rc);
	    goto out;
	}

	/* decrypt the encrypted secret */
	rsa_DecryptIn = NULL;
	rsa_DecryptOut = NULL;

	rc = TSS_Malloc((unsigned char **)&rsa_DecryptIn, sizeof(*rsa_DecryptIn));
	if (rc) {
	    traceError("rsa_DecryptIn malloc", rc);
	    goto out;
	}

	rc = TSS_Malloc((unsigned char **)&rsa_DecryptOut, sizeof(*rsa_DecryptOut));
	if (rc) {
	    traceError("rsa_DecryptOut malloc", rc);
	    goto rsa_decrypt_in_free;
	}

	rsa_DecryptIn->keyHandle = keyHandle;
	rsa_DecryptIn->cipherText.t.size = (uint16_t)encLength;	/* cast safe, range tested above */
	memcpy(rsa_DecryptIn->cipherText.t.buffer, encBuffer, encLength);
	rsa_DecryptIn->inScheme.scheme = TPM_ALG_NULL;
	rsa_DecryptIn->label.t.size = 0;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)rsa_DecryptOut,
			 (COMMAND_PARAMETERS *)rsa_DecryptIn,
			 NULL,
			 TPM_CC_RSA_Decrypt,
			 sessionHandle, keyPassword, TPMA_SESSION_ENCRYPT,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
	    traceError("rsa_decrypt", rc);
	    goto rsa_decrypt_out_free;
	}

	/* Open code TSS_Structure_Marshal as malloc not needed on pre-allocated buffer */
	/* marshal once to calculates the byte length */
	*decLength = 0;
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(&rsa_DecryptOut->message,
			decLength, NULL, NULL);
	if (rc == 0) {
	  uint8_t *buffer1 = decBuffer;        /* for marshaling, moves pointer */
          *decLength = 0;
	  rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(&rsa_DecryptOut->message,
			  decLength, &buffer1, NULL);
	  /* Adjust for return data containing length information */
	  buffer1 = decBuffer + sizeof(uint16_t);
          *decLength = *decLength - sizeof(uint16_t);
	  memmove(decBuffer, buffer1, *decLength);
	}


rsa_decrypt_out_free:
	free(rsa_DecryptOut);
rsa_decrypt_in_free:
	free(rsa_DecryptIn);
out:
	_rc = TSS_Delete(tssContext);
	if (rc == 0) {
		rc = _rc;
	}

	return rc;
}

#endif /* __ULTRAVISOR__ */
