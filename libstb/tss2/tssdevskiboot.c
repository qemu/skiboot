/********************************************************************************/
/*										*/
/*		Skiboot Transmit and Receive Utilities				*/
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


#ifdef __SKIBOOT__

#undef DEBUG
#define pr_fmt(fmt) "TSS-DEV-SKIBOOT: " fmt

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include "tssproperties.h"

#include <libstb/tpm2.h>
#include <skiboot.h>
#include "tssdevskiboot.h"

extern int tssVerbose;

TPM_RC TSS_Skiboot_Transmit(TSS_CONTEXT *tssContext,
		uint8_t *responseBuffer, uint32_t *read,
		const uint8_t *commandBuffer, uint32_t written,
		const char *message)
{
	TPM_RC rc;
	struct tpm_dev *tpm_device;
	struct tpm_driver *tpm_driver;
	size_t size;

//	devuv_dprintf("%s: Enter\n", __func__);
	/* open on first transmit */
//	if (tssContext->tssFirstTransmit) {
//		rc = TSS_Dev_UV_Open(tssContext);
//		if (rc) {
//			goto out;
//		}
//	}

	if (tssVerbose) {
		printf("%s: %s\n", __func__, message);
		TSS_PrintAll("TSS_Skiboot_Send", commandBuffer, written);
	}

	if (!tssContext->tpm_device || !tssContext->tpm_driver) {
		printf("%s: tpm device/driver not set\n", __func__);
		return TSS_RC_NO_CONNECTION;
	}

	tssContext->tssFirstTransmit = FALSE;
	tpm_device = tssContext->tpm_device;
	tpm_driver = tssContext->tpm_driver;

	memcpy(responseBuffer, commandBuffer, written);
	size = *read;
	rc = tpm_driver->transmit(tpm_device, responseBuffer, written, &size);
	*read = size;

	if (tssVerbose)
		TSS_PrintAll("TSS_Skiboot_Receive", responseBuffer, *read);

#if 0
	printf("%s: sending to tpm...\n", __func__);
	rc = tpm_driver->send(tpm_device, commandBuffer, written);
	printf("%s: sent to tpm, rc=%x written %d\n", __func__, rc, written);

	if (rc) {
		prlog(PR_INFO, "send error %d", rc);
		return TSS_RC_BAD_CONNECTION;
	}

	printf("%s: receiving data from the tpm...read %d\n", __func__, *read);
	rc = tpm_driver->receive(tpm_device, responseBuffer, read);
	printf("%s: received data from the tpm, rc = %d, read %d\n", __func__,
	       rc, *read);
#endif
	if (rc) {
		printf("%s: receive error %d\n", __func__, rc);
		return TSS_RC_BAD_CONNECTION;
	}

	if (*read < (sizeof(TPM_ST) + 2*sizeof(uint32_t))) {
		prlog(PR_INFO, "received %d bytes < header\n", *read);
		return TSS_RC_MALFORMED_RESPONSE;
	}

	/* Now we need to get the actual return code from the response buffer
	 * and delivery it to the upper layers
	 */
	rc = be32_to_cpu(*(uint32_t *)(responseBuffer + sizeof(TPM_ST)+ sizeof(uint32_t)));
	return rc;
}

/*
TPM_RC TSS_Dev_UV_Close(TSS_CONTEXT *tssContext)
{
	devuv_dprintf("%s: Closing %s\n", __func__, tssContext->tssDevice);
	svm_tss_tpm_close(tssContext->uv_ctx);
	return 0;
}
*/
#endif	/* __SKIBOOT__ */
