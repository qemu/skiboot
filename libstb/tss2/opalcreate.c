#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsserror.h>

#ifdef __SKIBOOT__
#include <libstb/tpm2.h>
#include <libfdt/libfdt.h>
#include <skiboot.h>
#include <ultravisor.h>
#endif

#include "tssproperties.h"

#ifndef __SKIBOOT__
#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif
#define prlog(l, f, ...) do { printf(pr_fmt(f), ##__VA_ARGS__); } while(0)

int wrapping_key_init(void);

#endif

#define WRAPPING_KEY_PARENT_HANDLE	0x81800000
#define WRAPPING_KEY_HANDLE		0x81800001
#define WRAPPING_KEY_PASSWD_LEN		16

#define PROP_PERSISTENT_HANDLES		0x81000000

static TPM2B_NAME *key_publicname;
static char *key_passwd;    /* null terminated wrapping key passwd */

#ifdef __SKIBOOT__
static const char tss_interface[] = "skiboot";
#endif

int verbose = TRUE;


//#define KENPOLICY
//#define SKIPOLICY
//#define PCR6ZERO
#define PCR16ZERO

unsigned char policy_a_bin[] = {
  0x8d, 0xbd, 0x2a, 0xa1, 0x0f, 0x70, 0x1b, 0x1e, 0xda, 0x23, 0x0f, 0xa8,
  0xa3, 0x88, 0x03, 0xd3, 0x42, 0xf3, 0xb4, 0x8c, 0x2f, 0xfc, 0xbe, 0xd5,
  0x6c, 0x04, 0x67, 0x4c, 0x79, 0xdf, 0xf0, 0x0f
};

unsigned char policy_b_bin[] = {
#ifdef KENPOLICY
  0x3e, 0x85, 0x0d, 0xd5, 0xc6, 0x0e, 0x42, 0x05, 0x48, 0xd7, 0x5a, 0xcf,
  0xe1, 0x07, 0x66, 0xd0, 0xb6, 0xdd, 0xbd, 0x91, 0x5e, 0xab, 0xf1, 0x13,
  0x54, 0xa9, 0x4c, 0xa1, 0xd4, 0xc9, 0xcb, 0x4d
#elseif SKIPOLICY
  0xfa, 0xfd, 0x20, 0x8d, 0x16, 0xcb, 0xc9, 0x8d, 0x1b, 0x32, 0xa8, 0xd4,
  0xc3, 0x04, 0x9f, 0x0c, 0xdb, 0xb2, 0x63, 0x44, 0xce, 0xe5, 0xc9, 0x0f,
  0xe7, 0xe8, 0xc0, 0xd6, 0xb3, 0x0c, 0x45, 0xed
#elseif PCR6ZERO
  0x1d, 0x48, 0xdf, 0x1d, 0x11, 0x73, 0x57, 0x0f, 0xc3, 0x99, 0x6f, 0x1f,
  0xd2, 0xc3, 0x20, 0xa6, 0x51, 0xb5, 0xd8, 0x15, 0xf6, 0x01, 0xa1, 0xa7,
  0x3a, 0x23, 0xb3, 0x9a, 0xb7, 0xb6, 0xeb, 0x5d
/* PCR16ZERO */
#else
  0x97, 0x95, 0xd7, 0x8f, 0x53, 0xde, 0x94, 0x40, 0x18, 0x99, 0xcc, 0x2d,
  0x5b, 0xa7, 0x60, 0x07, 0xb3, 0xd4, 0xda, 0xd8, 0x5b, 0xf9, 0x5c, 0xab,
  0xee, 0xba, 0x04, 0xd0, 0xf9, 0x8b, 0x50, 0x2e
#endif
};

unsigned char policyor_ab_bin[] = {
#ifdef KENPOLICY
  0x6c, 0x77, 0xac, 0x6b, 0x22, 0xb8, 0x0e, 0x21, 0xc7, 0x21, 0x58, 0x50,
  0xc6, 0x49, 0x9f, 0x0e, 0x45, 0x9b, 0xd0, 0x2c, 0x9d, 0xce, 0xa0, 0xab,
  0xa5, 0x1f, 0x2c, 0x05, 0x11, 0x5c, 0xb9, 0xd7
#elseif SKIPOLICY
  0x39, 0x72, 0xb6, 0xc9, 0x99, 0x2c, 0x9b, 0xb7, 0x58, 0xfe, 0x03, 0x6c,
  0x8e, 0xa3, 0x83, 0x97, 0xed, 0xf9, 0x95, 0xc8, 0x5c, 0x2f, 0xa1, 0x5b,
  0x66, 0x82, 0xdd, 0xe4, 0xae, 0x31, 0x49, 0x43
#elseif PCR6ZERO
  0xf5, 0xc3, 0x7a, 0xfb, 0xcb, 0x47, 0xee, 0xc9, 0x16, 0xb0, 0xf2, 0xb9,
  0x64, 0x72, 0xe9, 0x24, 0x53, 0xe8, 0x41, 0xe3, 0x7f, 0x50, 0x8e, 0x77,
  0x1a, 0xcb, 0x22, 0x57, 0xd7, 0xe6, 0xb0, 0xf9
/* PCR16ZERO */
#else
  0xe8, 0x6c, 0x73, 0x54, 0x25, 0x1a, 0xa8, 0xe6, 0xce, 0x27, 0xfd, 0xdc,
  0x54, 0x19, 0x46, 0xf4, 0x81, 0x20, 0xff, 0x95, 0xc3, 0xd7, 0xa4, 0xd3,
  0x43, 0xf4, 0x63, 0x32, 0x1b, 0xd3, 0xe5, 0x5c
#endif
};

static void traceError(const char *command, TPM_RC rc)
{
	const char *msg;
	const char *submsg;
	const char *num;
	prlog(PR_ERR,"%s: failed, rc %08x\n", command, rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	prlog(PR_ERR,"%s%s%s\n", msg, submsg, num);
}

static TPM_RC evictcontrol(TSS_CONTEXT *ctx, TPM_HANDLE object,
			   TPM_HANDLE persistent)
{
	EvictControl_In *in;
	TPM_RC rc;

	if (!object || !persistent || (object == TPM_RH_NULL) ||
	    (persistent == TPM_RH_NULL))
		return TSS_RC_NULL_PARAMETER;

	in = calloc(1, sizeof(EvictControl_In));
	if (!in) {
		prlog(PR_ERR,"EvictControl_In malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}

	in->auth = TPM_RH_PLATFORM;
	in->objectHandle = object;
	in->persistentHandle = persistent;
	rc = TSS_Execute(ctx,
			 NULL,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_EvictControl,
			 TPM_RS_PW,   NULL, 0,
			 TPM_RH_NULL, NULL, 0,
			 TPM_RH_NULL, NULL, 0,
			 TPM_RH_NULL, NULL, 0);

	free(in);
	return rc;
}

static TPM_RC flushcontext(TSS_CONTEXT *ctx, TPM_HANDLE handle)
{
	FlushContext_In *in;
	TPM_RC rc;

	if (!handle || handle == TPM_RH_NULL)
		return TSS_RC_NULL_PARAMETER;

	in = calloc(1, sizeof(FlushContext_In));
	if (!in) {
		prlog(PR_ERR,"FlushContext_In malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}

	in->flushHandle = handle;
	rc =  TSS_Execute(ctx,
			 NULL,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	free(in);

	if (rc)
		prlog(PR_ERR,"%s failed to flush handle 0x%x/n", __func__, handle);

	return rc;
}

static TPM_RC startauthsession(TSS_CONTEXT *ctx, TPM_HANDLE *sessionHandle)
{
	StartAuthSession_Extra *extra;
	StartAuthSession_Out *out;
	StartAuthSession_In *in;
	TPM_RC rc;

	extra = calloc(1, sizeof(StartAuthSession_Extra));
	if (!extra) {
		prlog(PR_ERR,"StartAuthSession_Extra malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}
	out = calloc(1, sizeof(StartAuthSession_Out));
	if (!out) {
		prlog(PR_ERR,"StartAuthSession_Out malloc failed\n");
		free(extra);
		return TSS_RC_OUT_OF_MEMORY;
	}
	in = calloc(1, sizeof(StartAuthSession_In));
	if (!in) {
		prlog(PR_ERR,"StartAuthSession_In malloc failed\n");
		free(extra);
		free(out);
		return TSS_RC_OUT_OF_MEMORY;
	}

	/* Start Auth Session */
	in->sessionType = TPM_SE_POLICY;
	in->tpmKey = TPM_RH_NULL;
	in->bind = TPM_RH_NULL;
	in->encryptedSalt.b.size = 0;	/* (not required) */
	in->nonceCaller.t.size = 0;	/* (not required) */
	extra->bindPassword = NULL;	/* (not required) */
	in->authHash = TPM_ALG_SHA256;
	in->symmetric.algorithm = TPM_ALG_AES;	/* response encryption */
	in->symmetric.keyBits.aes = 128;
	in->symmetric.mode.aes = TPM_ALG_CFB;

	rc = TSS_Execute(ctx,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 (EXTRA_PARAMETERS *) extra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);

	if (rc == 0)
		*sessionHandle = out->sessionHandle;	/* FIXME */

	free(in);
	free(extra);
	free(out);
	return rc;
}

static TPM_RC policycommandcode(TSS_CONTEXT *ctx, TPM_HANDLE session,
				TPM_CC code)
{
	PolicyCommandCode_In *in;
	TPM_RC rc;

	in = calloc(1, sizeof(PolicyCommandCode_In));
	if (!in) {
		prlog(PR_ERR,"PolicyCommandCode_In malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}

	in->policySession = session;
	in->code = code;

	rc = TSS_Execute(ctx,
			 NULL,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_PolicyCommandCode,
			 TPM_RH_NULL, NULL, 0);
	free(in);
	return rc;
}

static TPM_RC policypcr(TSS_CONTEXT *ctx, TPM_HANDLE session, TPM_HANDLE pcr)
{
	PolicyPCR_In *in;
	TPM_RC rc;

	in = calloc(1, sizeof(PolicyPCR_In));
	if (!in) {
		prlog(PR_ERR,"PolicyPCR_In malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}

	in->policySession = session;
	in->pcrDigest.b.size = 0;
	in->pcrs.count = 1;		/* hard code one hash algorithm */
	in->pcrs.pcrSelections[0].hash = TPM_ALG_SHA256;
	in->pcrs.pcrSelections[0].sizeofSelect= 3;
	in->pcrs.pcrSelections[0].pcrSelect[0] = 0;
	in->pcrs.pcrSelections[0].pcrSelect[1] = 0;
	in->pcrs.pcrSelections[0].pcrSelect[2] = 0;
	in->pcrs.pcrSelections[0].pcrSelect[pcr/8] = 1 << (pcr % 8);

	rc = TSS_Execute(ctx,
			 NULL,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_PolicyPCR,
			 TPM_RH_NULL, NULL, 0);
	free(in);
	return rc;
}

static TPM_RC policyor(TSS_CONTEXT *ctx, TPM_HANDLE session)
{
	PolicyOR_In *in;
	TPM_RC rc;

	in = calloc(1, sizeof(PolicyOR_In));
	if (!in) {
		prlog(PR_ERR,"PolicyOR_In malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}

	in->policySession = session;
	in->pHashList.count = 2;

	/* Add policy A */
	rc = TSS_TPM2B_Create(&in->pHashList.digests[0].b,
			      policy_a_bin,
			      sizeof(policy_a_bin),
			      sizeof(in->pHashList.digests[0].t.buffer));
	if (rc) {
		prlog(PR_ERR,"Failed to add policy A, rc=%d\n", rc);
		goto out_free;
	}

	/* Add policy B */
	rc = TSS_TPM2B_Create(&in->pHashList.digests[1].b,
			      policy_b_bin,
			      sizeof(policy_b_bin),
			      sizeof(in->pHashList.digests[1].t.buffer));
	if (rc) {
		prlog(PR_ERR,"Failed to add policy B, rc=%d\n", rc);
		goto out_free;
	}

	rc = TSS_Execute(ctx,
			 NULL,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_PolicyOR,
			 TPM_RH_NULL, NULL, 0);
out_free:
	free(in);
	return rc;
}

static TPM_RC readpublic(TSS_CONTEXT *ctx, TPM_HANDLE handle,
			 TPM2B_PUBLIC *public, TPM2B_NAME *name)
{
	ReadPublic_Out *out;
	ReadPublic_In *in;
	TPM_RC rc;

	if (!handle)
		return TSS_RC_NULL_PARAMETER;

	in =  calloc(1, sizeof(ReadPublic_In));
	if (!in) {
		prlog(PR_ERR,"ReadPublic_In malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}
	out = calloc(1, sizeof(ReadPublic_Out));
	if (!out) {
		prlog(PR_ERR,"ReadPublic_Out malloc failed\n");
		free(in);
		return TSS_RC_OUT_OF_MEMORY;
	}

	in->objectHandle = handle;
	rc = TSS_Execute(ctx,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_ReadPublic,
			 TPM_RH_NULL, NULL, 0);

	if (rc)
		goto out_free;
	if (public)
		memcpy(public, &out->outPublic, sizeof(out->outPublic));
	if (name)
		memcpy(name, &out->name, sizeof(out->name));

out_free:
	free(in);
	free(out);
	return rc;
}

/* passwd is a null terminated string */
static TPM_RC objectchangeauth(TSS_CONTEXT *ctx, TPM_HANDLE session,
			       TPM_HANDLE object, TPM_HANDLE parent,
			       char *passwd, TPM2B_PRIVATE *priv)
{
	ObjectChangeAuth_Out *out;
	ObjectChangeAuth_In *in;
	TPM_RC rc;

	in = calloc(1, sizeof(ObjectChangeAuth_In));
	if (!in) {
		prlog(PR_ERR,"ObjectChangeAuth_In malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}
	out = calloc(1, sizeof(ObjectChangeAuth_Out));
	if (!out) {
		prlog(PR_ERR,"ObjectChangeAuth_Out malloc failed\n");
		free(in);
		return TSS_RC_OUT_OF_MEMORY;
	}

	in->objectHandle = object;
	in->parentHandle = parent;
	rc = TSS_TPM2B_StringCopy(&in->newAuth.b, passwd,
				  sizeof(in->newAuth.t.buffer));
	if (rc) {
		prlog(PR_ERR, "Failed to copy key_passwd, rc=%d\n", rc);
		goto out_free;
	}

	rc = TSS_Execute(ctx,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_ObjectChangeAuth,
			 session, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
	if (rc)
		goto out_free;
	if (priv)
		memcpy(priv, &out->outPrivate, sizeof(*priv));

out_free:
	free(in);
	free(out);
	return rc;
}

static TPM_RC load(TSS_CONTEXT *ctx, TPM_HANDLE parent, TPM2B_PRIVATE *priv,
		   TPM2B_PUBLIC *pub, TPM_HANDLE *transientHandle)
{
	Load_Out *out;
	Load_In *in;
	TPM_RC rc;

	if (!priv || !pub)
		return TSS_RC_NULL_PARAMETER;

	in = calloc(1, sizeof(Load_In));
	if (!in) {
		prlog(PR_ERR,"Load_In malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}
	out = calloc(1, sizeof(Load_Out));
	if (!out) {
		prlog(PR_ERR,"Load_Out malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}

	/* Private part with changed auth, but public part has not changed */
	in->parentHandle = parent;
	memcpy(&in->inPrivate, priv, sizeof(in->inPrivate));
	memcpy(&in->inPublic, pub, sizeof(in->inPublic));

	rc = TSS_Execute(ctx,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_Load,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);

	if (rc)
		goto out_free;
	if (transientHandle)
		*transientHandle = out->objectHandle;

out_free:
	free(in);
	free(out);
	return rc;
}

static TPM_RC createprimary(TSS_CONTEXT *ctx, TPM_HANDLE *transient)
{
	CreatePrimary_Out *out;
	CreatePrimary_In *in;
	TPM_RC rc;

	TPMS_RSA_PARMS *rsaDetail;
	TPMT_PUBLIC *publicArea;

	in = calloc(1, sizeof(CreatePrimary_In));
	if (!in) {
		prlog(PR_ERR,"CreatePrimary_In malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}
	out = calloc(1, sizeof(CreatePrimary_Out));
	if (!out) {
		prlog(PR_ERR,"CreatePrimary_Out malloc failed\n");
		free(in);
		return TSS_RC_OUT_OF_MEMORY;
	}

	in->primaryHandle = TPM_RH_PLATFORM;
	in->inSensitive.sensitive.userAuth.t.size = 0;
	in->inSensitive.sensitive.data.t.size = 0;

	publicArea = &in->inPublic.publicArea;

	publicArea->objectAttributes.val = 0;
	publicArea->objectAttributes.val |= TPMA_OBJECT_NODA;
	publicArea->objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
	publicArea->objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
	publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	publicArea->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	publicArea->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_SIGN;

	publicArea->type = TPM_ALG_RSA;
	publicArea->nameAlg = TPM_ALG_SHA256;
	publicArea->unique.rsa.t.size = 0;
	publicArea->authPolicy.t.size = 0;

	rsaDetail = &publicArea->parameters.rsaDetail;

	rsaDetail->symmetric.algorithm = TPM_ALG_AES;
	rsaDetail->symmetric.keyBits.aes = 128;
	rsaDetail->symmetric.mode.aes = TPM_ALG_CFB;
	rsaDetail->scheme.scheme = TPM_ALG_NULL;
	rsaDetail->keyBits = 2048;
	rsaDetail->exponent = 0;

	in->inPublic.publicArea.unique.rsa.t.size = 0;
	in->outsideInfo.t.size = 0;
	in->creationPCR.count = 0;

	rc = TSS_Execute(ctx,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_CreatePrimary,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0,
			 TPM_RH_NULL, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc)
		goto out_free;
	if (transient)
		*transient = out->objectHandle;

out_free:
	free(in);
	free(out);
	return rc;
}

/* passwd is a null terminated string */
static TPM_RC create(TSS_CONTEXT *ctx, TPM_HANDLE parent, char *passwd,
		     TPM2B_PRIVATE *priv, TPM2B_PUBLIC *pub)
{
	Create_Out *out;
	Create_In *in;
	TPM_RC rc;

	TPMS_RSA_PARMS *rsaDetail;
	TPMT_PUBLIC *publicArea;

	in = calloc(1, sizeof(Create_In));
	if (!in) {
		prlog(PR_ERR,"Create_In malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}
	out = calloc(1, sizeof(Create_Out));
	if (!out) {
		prlog(PR_ERR,"Create_Out malloc failed\n");
		free(in);
		return TSS_RC_OUT_OF_MEMORY;
	}

	in->parentHandle = parent;
	rc = TSS_TPM2B_StringCopy(&in->inSensitive.sensitive.userAuth.b,
			passwd,
			sizeof(in->inSensitive.sensitive.userAuth.t.buffer));
	if (rc) {
		prlog(PR_ERR, "Failed to copy key_passwd, rc=%d\n", rc);
		goto out_free;
	}

	publicArea = &in->inPublic.publicArea;

	publicArea->objectAttributes.val = 0;
	publicArea->objectAttributes.val |= TPMA_OBJECT_NODA;
	publicArea->objectAttributes.val |= TPMA_OBJECT_ENCRYPTEDDUPLICATION;
	publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	publicArea->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_SIGN;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_USERWITHAUTH;

	publicArea->type = TPM_ALG_RSA;
	publicArea->nameAlg = TPM_ALG_SHA256;
	publicArea->unique.rsa.t.size = 0;

	rsaDetail = &publicArea->parameters.rsaDetail;

	rsaDetail->symmetric.algorithm = TPM_ALG_NULL;
	rsaDetail->scheme.scheme = TPM_ALG_OAEP;
	rsaDetail->scheme.details.oaep.hashAlg = TPM_ALG_SHA256;
	rsaDetail->keyBits = 2048;
	rsaDetail->exponent = 0;

	in->outsideInfo.t.size = 0;
	in->creationPCR.count = 0;

	/* Add policyor AB */
	rc = TSS_TPM2B_Create(&publicArea->authPolicy.b,
			      policyor_ab_bin,
			      sizeof(policyor_ab_bin),
			      sizeof(publicArea->authPolicy.t.buffer));
	if (rc) {
		prlog(PR_ERR,"Failed to add policyor AB, rc = 0x%x\n", rc);
		goto out_free;
	}

	rc = TSS_Execute(ctx,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_Create,
			 TPM_RS_PW,   NULL, 0,
			 TPM_RH_NULL, NULL, 0,
			 TPM_RH_NULL, NULL, 0,
			 TPM_RH_NULL, NULL, 0);

	if (rc)
		goto out_free;
	if (priv)
		memcpy(priv, &out->outPrivate, sizeof(out->outPrivate));
	if (pub)
		memcpy(pub, &out->outPublic, sizeof(out->outPublic));

out_free:
	free(in);
	free(out);
	return rc;
}

static TPM_RC getcapability(TSS_CONTEXT *ctx, uint32_t capability,
			    uint32_t property, TPMS_CAPABILITY_DATA *data)
{
	GetCapability_Out *out;
	GetCapability_In *in;
	TPM_RC rc;

	in = calloc(1, sizeof(GetCapability_In));
	if (!in) {
		prlog(PR_ERR,"GetCapability_In malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}
	out = calloc(1, sizeof(GetCapability_Out));
	if (!out) {
		prlog(PR_ERR,"GetCapability_Out malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}

	in->capability = capability;
	in->property = property;
	in->propertyCount = 64;

	rc = TSS_Execute(ctx,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_GetCapability,
			 TPM_RH_NULL, NULL, 0,
			 TPM_RH_NULL, NULL, 0,
			 TPM_RH_NULL, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc)
		goto out_free;
	if (data)
		memcpy(data, &out->capabilityData, sizeof(out->capabilityData));

out_free:
	free(in);
	free(out);
	return rc;
}

static TPM_RC policygetdigest(TSS_CONTEXT *ctx, TPM_HANDLE session,
			      TPM2B_DIGEST *policyDigest)
{
	PolicyGetDigest_Out *out;
	PolicyGetDigest_In *in;
	TPM_RC rc;

	out = calloc(1, sizeof(PolicyGetDigest_Out));
	if (!out) {
		prlog(PR_ERR,"PolicyGetDigest_Out malloc failed\n");
		return TSS_RC_OUT_OF_MEMORY;
	}
	in = calloc(1, sizeof(PolicyGetDigest_In));
	if(!in) {
		prlog(PR_ERR,"PolicyGetDigest_In malloc failed\n");
		free(out);
		return TSS_RC_OUT_OF_MEMORY;
	}

	in->policySession = session;
	rc = TSS_Execute(ctx,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_PolicyGetDigest,
			 TPM_RH_NULL, NULL, 0);

	if (rc)
		goto out_free;

	if (policyDigest)
		memcpy(policyDigest, &out->policyDigest,
		       sizeof(out->policyDigest));
out_free:
	free(in);
	free(out);
	return rc;
}

static void print_policySession(TSS_CONTEXT *ctx, TPM_HANDLE session)
{
	TPM2B_DIGEST policyDigest;
	TPM_RC rc;

	rc = policygetdigest(ctx, session, &policyDigest);

	if (rc == 0)
		TSS_PrintAll("PolicyDigest", policyDigest.t.buffer,
			     policyDigest.t.size);
}

/* passwd is a null pointer terminated string */
static int change_wrapping_key_passwd(TSS_CONTEXT *ctx,
				      char *passwd)
{
	TPM_HANDLE wrapping_transient;
	TPM2B_PRIVATE wrapping_priv;
	TPM2B_PUBLIC wrapping_pub;
	TPM_HANDLE session;
	TPM_RC rc;

	memset(&session, 0, sizeof(TPM_HANDLE));

	rc = startauthsession(ctx, &session);
	if (rc) {
		traceError("startauthsession", rc);
		goto out_err;
	}

	rc = policycommandcode(ctx, session, TPM_CC_ObjectChangeAuth);
	if (rc) {
	    traceError("policycommandcode", rc);
	    goto out_err_session;
	}

	/* print_policySession is being used only for debugging */
	print_policySession(ctx, session);

	rc = policypcr(ctx, session, 16);
	if (rc) {
	    traceError("policypcr", rc);
	    goto out_err_session;
	}

	print_policySession(ctx, session);

	/* policyor A B */
	rc = policyor(ctx, session);
	if (rc) {
	    traceError("policyor", rc);
	    goto out_err_session;
	}

	print_policySession(ctx, session);

	rc = readpublic(ctx, WRAPPING_KEY_PARENT_HANDLE, NULL, NULL);
	if (rc) {
		traceError("readpublic", rc);
		prlog(PR_ERR,"Wrapping key parent not found\n");
		goto out_err_session;
	}

	rc = readpublic(ctx, WRAPPING_KEY_HANDLE, &wrapping_pub, NULL);
	if (rc) {
		traceError("readpublic", rc);
		prlog(PR_ERR,"Wrapping key not found\n");
		goto out_err_session;
	}

	/* Execute the policy, change the wrapping key authorization password */
	rc = objectchangeauth(ctx, session, WRAPPING_KEY_HANDLE,
			      WRAPPING_KEY_PARENT_HANDLE, passwd,
			      &wrapping_priv);
	if (rc) {
		traceError("objectchangeauth", rc);
		goto out_err_session;
	}

	rc = evictcontrol(ctx, WRAPPING_KEY_HANDLE, WRAPPING_KEY_HANDLE);
	if (rc) {
	    traceError("evictcontrol", rc);
	    prlog(PR_ERR,"Failed to evict the current wrapping key\n");
	    goto out_err_session;
	}

	/* Load the RSA keypair with changed auth */
	rc = load(ctx, WRAPPING_KEY_PARENT_HANDLE, &wrapping_priv,
		  &wrapping_pub, &wrapping_transient);
 	if (rc) {
	    traceError("load", rc);
	    goto out_err_session;
	}

	rc = evictcontrol(ctx, wrapping_transient, WRAPPING_KEY_HANDLE);
	if (rc) {
	    traceError("evictcontrol", rc);
	    prlog(PR_ERR,"Failed to persist the new wrapping key\n");
	    goto out_err_transient;
	}

	/* Flush the transient RSA keypair and session */
	flushcontext(ctx, wrapping_transient);
	flushcontext(ctx, session);

	return 0;

out_err_transient:
	flushcontext(ctx, wrapping_transient);
out_err_session:
	flushcontext(ctx, session);
out_err:
	return -1;
}

static bool handle_exist(TPMS_CAPABILITY_DATA *capabilityData, TPM_HANDLE handle)
{
	uint32_t i;

	if (!capabilityData)
		false;

	for (i = 0; i < capabilityData->data.handles.count; i++)
		if (capabilityData->data.handles.handle[i] == handle)
			return true;
	return false;
}

#ifdef __SKIBOOT__
int fdt_add_wrapping_key(void *fdt)
{
	if (!key_passwd || WRAPPING_KEY_PASSWD_LEN == 0 || !key_publicname) {
		prlog(PR_ERR, "%s failed\n", __func__);
		return -1;
	}

	fdt_begin_node(fdt, "ibm,uv-tpm");
	fdt_property_string(fdt, "compatible", "ibm,uv-tpm");

	fdt_property_u32(fdt, "wrapping-key-handle", WRAPPING_KEY_HANDLE);
	fdt_property(fdt, "wrapping-key-passwd", key_passwd,
		     WRAPPING_KEY_PASSWD_LEN+1); /* Include null */
	fdt_property(fdt, "wrapping-key-publicname",
			&key_publicname->t.name[0], key_publicname->t.size);
	fdt_property(fdt, "wrapping-key-policy-a", policy_a_bin,
		     sizeof(policy_a_bin));
	fdt_property(fdt, "wrapping-key-policy-b", policy_b_bin,
		     sizeof(policy_b_bin));

	fdt_end_node(fdt);

	/* Destroy the wrapping key passwd */
	memset(key_passwd, 0, WRAPPING_KEY_PASSWD_LEN);

	free(key_passwd);
	free(key_publicname);

	return 0;
}
#endif

static int generate_random_passwd(TSS_CONTEXT *ctx, char *passwd,
				  uint16_t passwd_len)
{
	GetRandom_Out *out;
	GetRandom_In *in;
	TPM_RC rc = 0;

	int bytesCopied;
	int i;

	in = calloc(1, sizeof(GetRandom_In));
	if (!in) {
		prlog(PR_ERR,"GetRandom_In malloc failed\n");
		goto out_err;
	}
	out = calloc(1, sizeof(GetRandom_Out));
	if (!out) {
		prlog(PR_ERR,"GetRandom_Out malloc failed\n");
		free(in);
		goto out_err;
	}

	bytesCopied = 0;
	while ((rc == 0) && (bytesCopied < passwd_len)) {
		in->bytesRequested = passwd_len;

		rc = TSS_Execute(ctx,
				 (RESPONSE_PARAMETERS *) out,
				 (COMMAND_PARAMETERS *) in,
				 NULL,
				 TPM_CC_GetRandom,
				 TPM_RH_NULL, NULL, 0);
		if (rc) {
			traceError("getrandom", rc);
			goto out_err_free;
		}
		/* Copy as many bytes as were received or until bytes requested */
		for (i = 0; (i < out->randomBytes.t.size) &&
			    (bytesCopied < passwd_len); i++) {

			/* Skip zero bytes */
			if (out->randomBytes.t.buffer[i] == 0)
				continue;
			passwd[bytesCopied] = out->randomBytes.t.buffer[i];
			bytesCopied++;
		}
	}
	free(in);
	free(out);
	return bytesCopied;

out_err_free:
	free(in);
	free(out);
out_err:
	return 0;
}

int wrapping_key_init(void)
{
	TPMS_CAPABILITY_DATA capabilityData;
	TPM_HANDLE transientHandle;
	TPM2B_PRIVATE wrapping_priv;
	TPM2B_PUBLIC wrapping_pub;
	TSS_CONTEXT *ctx;
	TPM_RC rc;

	int key_passwd_len;
	uint32_t i;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");

	key_passwd = malloc(WRAPPING_KEY_PASSWD_LEN + 1);
	if (!key_passwd) {
		prlog(PR_ERR,"Wrapping key passwd malloc failed\n");
		goto out_err;
	}

	rc = TSS_Create(&ctx);
	if (rc) {
		prlog(PR_ERR,"Failed to create TSS context\n");
		free(key_passwd);
		goto out_err;
	}

#ifdef __SKIBOOT__
	ctx->tpm_device = tpm2_get_device();
	ctx->tpm_driver = tpm2_get_driver();
	ctx->tssInterfaceType = tss_interface;
#endif

	key_passwd_len = generate_random_passwd(ctx, key_passwd,
						WRAPPING_KEY_PASSWD_LEN);
	if (key_passwd_len != WRAPPING_KEY_PASSWD_LEN) {
		prlog(PR_ERR,"Failed to generate the wrapping key, bytes=%d\n",
		      key_passwd_len);
		goto out_err_free;
	}
	key_passwd[key_passwd_len] = 0;

//	TSS_PrintAll("Wrapping key passwd:", key_passwd, key_passwd_len);

	rc = getcapability(ctx, TPM_CAP_HANDLES, PROP_PERSISTENT_HANDLES,
			   &capabilityData);
	if (rc) {
		traceError("getcapability", rc);
		goto out_err_free;
	}

	prlog(PR_ERR,"Persistent Handles:\n");
	for (i = 0; i < capabilityData.data.handles.count; i++)
		prlog(PR_ERR,"\t%08x\n", capabilityData.data.handles.handle[i]);

	/*
	 * If the wrapping key already exists, just change its password.
	 * Otherwise, create the key and make it persistent to save some time in
	 * subsequent boot cycles.
	 */
	if (handle_exist(&capabilityData, WRAPPING_KEY_HANDLE)) {
		rc = change_wrapping_key_passwd(ctx, key_passwd);
		if (rc) {
			prlog(PR_ERR,"change_wrapping_key_passwd failed\n");
			goto out_err_free;
		}
		goto out_publicname;
	}

	if (!handle_exist(&capabilityData, WRAPPING_KEY_PARENT_HANDLE)) {
		rc = createprimary(ctx, &transientHandle);
		if (rc) {
			traceError("createprimary", rc);
			goto out_err_free;
		}
		rc = evictcontrol(ctx, transientHandle,
				  WRAPPING_KEY_PARENT_HANDLE);
		if (rc) {
			traceError("evictcontrol", rc);
			prlog(PR_ERR,"Failed to persist the wrapping key parent\n");
			goto out_err_free;
		}
		flushcontext(ctx, transientHandle);
	}

	rc = create(ctx, WRAPPING_KEY_PARENT_HANDLE, key_passwd,
		    &wrapping_priv, &wrapping_pub);
	if (rc) {
		traceError("create", rc);
		goto out_err_free;
	}

	rc = load(ctx, WRAPPING_KEY_PARENT_HANDLE, &wrapping_priv,
		  &wrapping_pub, &transientHandle);
 	if (rc) {
		traceError("load", rc);
		prlog(PR_ERR,"Failed to load the transient wrapping key\n");
		goto out_err_free;
	}

	rc = evictcontrol(ctx, transientHandle, WRAPPING_KEY_HANDLE);
	if (rc) {
		traceError("evictcontrol", rc);
		prlog(PR_ERR,"Failed to persist the wrapping key\n");
		goto out_err_free;
	}
	flushcontext(ctx, transientHandle);

out_publicname:
	key_publicname = malloc(sizeof(TPM2B_NAME));
	if (!key_publicname) {
		prlog(PR_ERR,"wrapping key name malloc failed\n");
		rc = TSS_RC_OUT_OF_MEMORY;
		goto out_err_free;
	}

	/* Read the wrapping key public name for the ultravisor */
	rc = readpublic(ctx, WRAPPING_KEY_HANDLE, NULL, key_publicname);
	if (rc) {
		traceError("readpublic", rc);
		prlog(PR_ERR,"Failed to read the key publicname\n");
		free(key_publicname);
		goto out_err_free;
	}

	rc = TSS_Delete(ctx);
	if (rc)
		prlog(PR_ERR,"Failed to delete TSS context\n");

	prlog(PR_ERR,"All done!\n");
	return 0;

out_err_free:
	free(key_passwd);

	rc = TSS_Delete(ctx);
	if (rc)
		prlog(PR_ERR,"Failed to free TSS context\n");
out_err:
	prlog(PR_ERR, "%s failed\n", __func__);
	return -1;
}

#ifndef __SKIBOOT__
int main(void)
{
	int rc;

	rc = wrapping_key_init();
	if (rc)
		goto out_err;

	if (key_passwd)
		free(key_passwd);
	if (key_publicname)
		free(key_publicname);

	return 0;
out_err:
	return -1;
}
#endif
