/********************************************************************************/
/*										*/
/*		UV Transmit and Receive Utilities				*/
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


#ifdef __ULTRAVISOR__

#undef DEBUG
#define pr_fmt(fmt) "TSS-DEV-UV: " fmt

#include <svm/svm-tss.h>

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include "tssproperties.h"

#include "tssdevuv.h"
#include "tssuv.h"

#define DEBUG
#ifdef DEBUG
#define devuv_dprintf(fmt...) do { printf(fmt); } while(0)
#else
#define devuv_dprintf(fmt...) do { } while(0)
#endif

/* TSS_Dev_UV_Open() updates state for open */

static uint32_t TSS_Dev_UV_Open(TSS_CONTEXT *tssContext)
{
	uint32_t rc;

	devuv_dprintf("%s: Opening %s\n", __func__, tssContext->tssDevice);
	/** @todo (andmike) Add to tssContext for tracking open, close */
	rc = svm_tss_tpm_open(tssContext->uv_ctx);
	if (rc) {
		devuv_dprintf("%s: Error opening %s\n", __func__, tssContext->tssDevice);
		rc = TSS_RC_NO_CONNECTION;
	}

	return rc;
}

/* TSS_Dev_Send_Cmd() sends the TPM command buffer.

   Returns an error if the device write fails.
*/

static uint32_t TSS_Dev_UV_Send_Cmd(TSS_CONTEXT *tssContext,
		const uint8_t *buffer, uint16_t length,
		const char *message)
{
	uint32_t rc = 0;
	ssize_t	bytes;

	devuv_dprintf("%s: Enter\n", __func__);
	if (message != NULL) {
		devuv_dprintf("%s: %s\n", __func__, message);
	}

	bytes = svm_tss_tpm_write(tssContext->uv_ctx, buffer, length);
	if (bytes < 0) {
		devuv_dprintf("%s: write error %ld\n",
				__func__, bytes);
		rc = TSS_RC_BAD_CONNECTION;
	}

	return rc;
}

/* TSS_Dev_Recv_Cmd() reads a response buffer.  'buffer' must be at least
   MAX_RESPONSE_SIZE bytes.

   Returns TPM packet error code.

   Validates that the packet length and the packet responseSize match
*/

static uint32_t TSS_Dev_UV_Recv_Cmd(TSS_CONTEXT *tssContext,
		uint8_t *buffer, uint32_t *length)
{
	uint32_t rc;
	ssize_t	bytes;
	uint32_t responseSize;
	uint32_t responseCode;

	devuv_dprintf("%s: Enter\n", __func__);
	bytes = svm_tss_tpm_read(tssContext->uv_ctx, buffer, MAX_RESPONSE_SIZE);
	if (bytes <= 0) {
		rc = TSS_RC_BAD_CONNECTION;
		if (bytes < 0) {
			devuv_dprintf("%s: read error %ld\n",
					__func__, bytes);
		}
		goto out;
	}

	/* verify that there is at least a tag, responseSize, and responseCode */

	if ((unsigned int)bytes < (sizeof(TPM_ST) + sizeof(uint32_t) + sizeof(uint32_t))) {
		devuv_dprintf("%s: read bytes %ld < header\n", __func__, bytes);
		rc = TSS_RC_MALFORMED_RESPONSE;
		goto out;
	}

	/* get responseSize from the packet */

	responseSize = be32_to_cpu(*(uint32_t *)(buffer + sizeof(TPM_ST)));
	/* sanity check against the length actually received, the return code */
	if ((uint32_t)bytes != responseSize) {
		devuv_dprintf("%s: read bytes %u != responseSize %u\n", __func__,
				(uint32_t)bytes, responseSize);
		devuv_dprintf("%s: buffer %x %x %x %x %x %x %x %x %x %x\n", __func__,
				buffer[0],
				buffer[1],
				buffer[2],
				buffer[3],
				buffer[4],
				buffer[5],
				buffer[6],
				buffer[7],
				buffer[8],
				buffer[9]);
		rc = TSS_RC_BAD_CONNECTION;
		goto out;
	}

	/* read the TPM return code from the packet */

	responseCode = be32_to_cpu(*(uint32_t *)(buffer + sizeof(TPM_ST)+ sizeof(uint32_t)));
	rc = responseCode;
	*length = responseSize;

out:
	devuv_dprintf("%s: rc %08x\n", __func__, rc);
	return rc;
}

/* TSS_Dev_Transmit() transmits the command and receives the response.

   Can return device transmit and receive packet errors, but normally returns
   the TPM response code.
*/

TPM_RC TSS_Dev_UV_Transmit(TSS_CONTEXT *tssContext,
		uint8_t *responseBuffer, uint32_t *read,
		const uint8_t *commandBuffer, uint32_t written,
		const char *message)
{
	TPM_RC rc;

	devuv_dprintf("%s: Enter\n", __func__);
	/* open on first transmit */
	if (tssContext->tssFirstTransmit) {
		rc = TSS_Dev_UV_Open(tssContext);
		if (rc) {
			goto out;
		}
	}

	tssContext->tssFirstTransmit = FALSE;

	/* send the command.  Error if the device send fails. */
	rc = TSS_Dev_UV_Send_Cmd(tssContext, commandBuffer, written, message);
	if (rc) {
		goto out;
	}

	/* receive the response.  Returns errors, malformed response errors.
	   Else returns the TPM response code. */

	rc = TSS_Dev_UV_Recv_Cmd(tssContext, responseBuffer, read);

out:
	return rc;
}


TPM_RC TSS_Dev_UV_Close(TSS_CONTEXT *tssContext)
{
	devuv_dprintf("%s: Closing %s\n", __func__, tssContext->tssDevice);
	svm_tss_tpm_close(tssContext->uv_ctx);
	return 0;
}

#endif	/* TPM_POSIX */
