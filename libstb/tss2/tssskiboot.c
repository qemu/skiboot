/********************************************************************************/
/*										*/
/*			 Skiboot Support Interface  				*/
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

#ifdef __SKIBOOT__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssfile.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Startup_fp.h>
#include <ibmtss/tssprint.h>
#include "tssproperties.h"

#include "tssskiboot.h"

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
TPM_RC TSS_NV_ReadPublic(TSS_CONTEXT *ctx, NV_ReadPublic_In *in,
				NV_ReadPublic_Out *out)
{
	TPM_RC rc;

	printf("%s: nvIndex %x\n", __func__, in->nvIndex);

	rc = TSS_Execute(ctx,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_NV_ReadPublic,
			 TPM_RH_NULL, NULL, 0);

	if (rc == 0) {
		printf("%s: name algorithm %04x\n", __func__,
		       out->nvPublic.nvPublic.nameAlg);
		printf("%s: data size %u\n", __func__,
		       out->nvPublic.nvPublic.dataSize);
		printf("%s: attributes %08x\n", __func__,
		       out->nvPublic.nvPublic.attributes.val);
		TSS_TPMA_NV_Print(out->nvPublic.nvPublic.attributes, 0);
		TSS_PrintAll("TSS_NV_ReadPublic: policy",
			     out->nvPublic.nvPublic.authPolicy.t.buffer,
			     out->nvPublic.nvPublic.authPolicy.t.size);
		TSS_PrintAll("TSS_NV_ReadPublic: name",
			     out->nvName.t.name, out->nvName.t.size);
	} else {
		traceError("TSS_NV_ReadPublic", rc);
	}

	return rc;
}

#endif /* __SKIBOOT__ */
