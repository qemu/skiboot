// SPDX-License-Identifier: Apache-2.0
/* Copyright 2018-2019 IBM Corp. */

#ifndef __ULTRAVISOR_API_H
#define __ULTRAVISOR_API_H

#include <types.h>

struct uv_opal {
	__be32 magic;		/**< 'OPUV' 0x4F505556 OPUV_MAGIC */
	__be32 version;		/**< uv_opal struct version */
	__be32 uv_ret_code;	/**< 0 - Success, <0> : error. */
	__be32 uv_api_ver;	/**< Current uv api version. */
	__be64 uv_base_addr;	/**< Base address of UV in secure memory. */
	__be64 sys_fdt;		/**< System FDT. */
	__be64 uv_fdt;		/**< UV FDT in secure memory. */
	__be64 uv_mem;		/**< struct memcons */
};

#endif /* __ULTRAVISOR_API_H */
