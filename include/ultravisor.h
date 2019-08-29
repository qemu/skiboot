// SPDX-License-Identifier: Apache-2.0
/* Copyright 2018-2019 IBM Corp. */

#ifndef __ULTRAVISOR_H
#define __ULTRAVISOR_H

#include <ultravisor-api.h>
#include <processor.h>
#include <types.h>

/* Bit 15 of an address should be set for it to be used as a secure memory area
 * for the secure virtual machines */
#define UV_SECURE_MEM_BIT              (PPC_BIT(15))
#define MAX_COMPRESSED_UV_IMAGE_SIZE 0x40000 /* 256 Kilobytes */
#define UV_READ_SCOM  0xF114
#define UV_WRITE_SCOM 0xF118
#define UCALL_BUFSIZE 4
#define UV_ACCESS_BIT		0x1ULL << 48
/* Address at which the Ultravisor is loaded for BML and Mambo */
#define UV_LOAD_BASE		0xC0000000
#define UV_LOAD_MAX_SIZE	0x200000
#define UV_FDT_MAX_SIZE		0x100000
#define UV_HB_RESERVE_SIZE	0x4000000;

extern bool uv_present;
#define is_uv_present() uv_present

extern int start_uv(uint64_t entry, struct uv_opal *uv_opal);
extern bool uv_add_mem_range(__be64 start, __be64 end);
extern void uv_preload_image(void);
extern void uv_decompress_image(void);
extern void init_uv(void);
extern int start_ultravisor(void);
extern long ucall(unsigned long opcode, unsigned long *retbuf, ...);

static inline bool can_access_xscom(void)
{
	return (is_msr_bit_set(MSR_S) || !is_uv_present());
}

static inline int uv_xscom_read(u64 partid, u64 pcb_addr, u64 *val)
{
	long rc;
	unsigned long retbuf[UCALL_BUFSIZE];

	rc = ucall(UV_READ_SCOM, retbuf, partid, pcb_addr);
	*val = retbuf[0];
	return rc;
}

static inline int uv_xscom_write(u64 partid, u64 pcb_addr, u64 val)
{
	unsigned long retbuf[UCALL_BUFSIZE];

	return ucall(UV_WRITE_SCOM, retbuf, partid, pcb_addr, val);
}

#endif /* __ULTRAVISOR_H */
