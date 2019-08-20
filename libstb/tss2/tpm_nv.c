#include "tssskiboot.h"
#include <libstb/tpm2.h>
#include "tpm_nv.h"
#include <skiboot.h>

int tpm_nv_init(void)
{
	TSS_CONTEXT *ctx;
	NV_ReadPublic_In in;
	NV_ReadPublic_Out out;
	TPM_RC rc;

	prlog(PR_INFO, "%s begin\n", __func__);
	rc = TSS_Create(&ctx);
	if (rc) {
		prlog(PR_INFO, "%s: TSS_Create failed rc=%d\n", __func__, rc);
		return rc;
	}

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");

	ctx->tpm_device = tpm2_get_device();
	ctx->tpm_driver = tpm2_get_driver();
	ctx->tssInterfaceType = "skiboot";

	in.nvIndex = 0x01c10190;

	rc = TSS_NV_ReadPublic(ctx, &in, &out);
	if (rc) {
		prlog(PR_INFO, "%s: TSS_NV_ReadPublic failed rc=%d\n", __func__, rc);
		goto out;
	}
	prlog(PR_INFO, "nvreadpublic: name algorithm %04x\n", out.nvPublic.nvPublic.nameAlg);
	prlog(PR_INFO, "nvreadpublic: data size %u\n", out.nvPublic.nvPublic.dataSize);
	prlog(PR_INFO, "nvreadpublic: attributes %08x\n", out.nvPublic.nvPublic.attributes.val);
	TSS_TPMA_NV_Print(out.nvPublic.nvPublic.attributes, 0);

out:
	rc = TSS_Delete(ctx);
	if (rc)
		return -1;

	return 0;
}
