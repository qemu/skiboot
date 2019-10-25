// SPDX-License-Identifier: Apache-2.0
/* Copyright 2018-2019 IBM Corp. */

#include <skiboot.h>
#include <xscom.h>
#include <chip.h>
#include <device.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <ultravisor.h>
#include <mem_region.h>
#include <debug_descriptor.h>
#include <console.h>
#include <ultravisor-api.h>
#include <libfdt/libfdt.h>
#include <libstb/container.h>
#include <libstb/cvc.h>
#include <libstb/tss2/tpm_nv.h>

bool uv_present = false;
static char *uv_image = NULL;
static size_t uv_image_size;
struct xz_decompress *uv_xz = NULL;
static struct uv_opal *uv_opal;
static int num_secure_ranges = 0;

struct memcons uv_memcons __section(".data.memcons") = {
	.magic		= MEMCONS_MAGIC,
	.obuf_phys	= INMEM_UV_CON_START,
	.ibuf_phys	= INMEM_UV_CON_START + INMEM_UV_CON_OUT_LEN,
	.obuf_size	= INMEM_UV_CON_OUT_LEN,
	.ibuf_size	= INMEM_UV_CON_IN_LEN,
};

static struct dt_node *add_uv_dt_node(void)
{
	struct dt_node *dev, *uv;

	dev = dt_new_check(dt_root, "ibm,ultravisor");
	if (!dev)
		return NULL;

	dt_add_property_string(dev, "compatible", "ibm,ultravisor");
	uv = dt_new_check(dev, "firmware");
	if (!uv) {
		dt_free(dev);
		return NULL;
	}

	dt_add_property_string(uv, "compatible", "ibm,uv-firmware");
	return dev;
}

static struct dt_node *find_uv_node(void)
{
	struct dt_node *uv_node, *dt;

	uv_node = dt_find_compatible_node(dt_root, NULL, "ibm,uv-firmware");
	if (!uv_node) {
		prlog(PR_INFO, "ibm,uv-firmware compatible node not found, creating\n");
		dt = add_uv_dt_node();
		if (!dt)
			return NULL;
		uv_node = dt_find_compatible_node(dt_root, NULL, "ibm,uv-firmware");
	}

	return uv_node;
}

static bool find_secure_mem_to_copy(uint64_t *target, uint64_t *sz)
{
	struct dt_node *uv_node = find_uv_node();
	const struct dt_property *ranges;
	uint64_t uv_pef_reg;
	uint64_t *range, sm_size, img_size = UV_LOAD_MAX_SIZE;

	/*
	 * "uv-secure-memory" property could have multiple
	 * secure memory blocks. Pick first to load
	 * ultravisor in it.
	 */
	ranges = dt_find_property(uv_node, "secure-memory-ranges");
	if (!ranges)
		return false;

	range = (void *)ranges->prop;
	do {
		uv_pef_reg = dt_get_number(range, 2);
		if (!uv_pef_reg)
			return false;

		sm_size = dt_get_number(range + 1, 2);
		if (sm_size > img_size)
			break;
		range += 2;
	} while (range);

	*target = uv_pef_reg;
	*sz = sm_size;
	return true;
}

static uint64_t find_uv_fw_base_addr(struct dt_node *uv_node)
{
	uint64_t base_addr = 0;

	if (dt_has_node_property(uv_node, "reg", NULL))
		base_addr = dt_prop_get_u64(uv_node, "reg");

	return base_addr;
}

static int create_dtb_uv(void *uv_fdt)
{
	if (fdt_create(uv_fdt, UV_FDT_MAX_SIZE)) {
		prerror("UV: Failed to create uv_fdt\n");
		return 1;
	}

	fdt_finish_reservemap(uv_fdt);
	fdt_begin_node(uv_fdt, "");
	fdt_property_string(uv_fdt, "description", "Ultravisor fdt");
	fdt_begin_node(uv_fdt, "ibm,uv-fdt");
	fdt_property_string(uv_fdt, "compatible", "ibm,uv-fdt");
	if (fdt_add_wrapping_key(uv_fdt))
		prlog(PR_ERR, "Failed to add the wrapping key to dt\n");
	fdt_end_node(uv_fdt);
	fdt_end_node(uv_fdt);
	fdt_finish(uv_fdt);

	return OPAL_SUCCESS;
}


static void cpu_start_ultravisor(void *data)
{
	struct uv_opal *ptr = (struct uv_opal *)data;
	start_uv(ptr->uv_base_addr, ptr);
}

int start_ultravisor(void)
{
	struct proc_chip *chip = get_chip(this_cpu()->chip_id);
	struct cpu_thread *cpu;
	struct cpu_job **jobs;
	int i=0;

	/* init_uv should have made the ibm,ultravisor node by now so don't
	 * start if something went wrong */
	if (!dt_find_compatible_node(dt_root, NULL, "ibm,ultravisor")) {
		prlog(PR_NOTICE, "UV: No ibm,ultravisor found, won't start ultravisor\n");
		return OPAL_HARDWARE;
	}

	if (create_dtb_uv((void *)uv_opal->uv_fdt))
		return OPAL_NO_MEM;

	prlog(PR_NOTICE, "UV: Starting Ultravisor at 0x%llx sys_fdt 0x%llx uv_fdt 0x%0llx\n",
				uv_opal->uv_base_addr, uv_opal->sys_fdt, uv_opal->uv_fdt);

	if (!uv_opal->uv_base_addr)
		abort();

	/* Alloc memory for Jobs */
	jobs = zalloc(sizeof(struct cpu_job*) * cpu_max_pir);

	for_each_available_cpu(cpu) {
		if (cpu == this_cpu())
			continue;
		jobs[i++] = cpu_queue_job(cpu, "start_ultravisor",
					cpu_start_ultravisor, (void *)uv_opal);
	}

	cpu_start_ultravisor((void *)uv_opal);

	/*
	 * From now on XSCOM must go through Ultravisor via ucall, indicate that
	 */
	if (chip->xscom_base & UV_ACCESS_BIT)
		uv_present = true;

	/* wait for everyone to sync back */
	while (i > 0) {
		cpu_wait_job(jobs[--i], true);
	}

	/* free used stuff */
	free(jobs);

	/* Check everything is fine */
	if (uv_opal->uv_ret_code) {
		return OPAL_HARDWARE;
	}

	return OPAL_SUCCESS;
}

static void free_uv(void)
{
	struct mem_region *region = find_mem_region("ibm,firmware-allocs-memory@0");

	lock(&region->free_list_lock);
	mem_free(region, uv_image, __location__);
	unlock(&region->free_list_lock);
}

static bool alloc_uv(void)
{
	struct proc_chip *chip = next_chip(NULL);

	uv_image_size = MAX_COMPRESSED_UV_IMAGE_SIZE;
	if (!(uv_image = local_alloc(chip->id, uv_image_size, uv_image_size)))
		return false;
	memset(uv_image, 0, uv_image_size);
	return true;
}

/* We could be running on Mambo, Cronus, or Hostboot
 *
 * Detect Mambo via chip quirk.  Mambo writes the uncompressed UV images
 * directly to secure memory and passes secure memory location via device tree.
 *
 * Detect Cronus when HB decompress fails.  Cronus writes the uncompressed UV
 * image to insecure memory and init_uv will copy from insecure to secure.
 *
 * Assume HB by waiting for decompress.  UV should have been loaded from FSP
 * and decompressed earlier via uv_preload_image and uv_decompress_image.  The
 * secure location of the UV provided by those functions in xz struct. */
void init_uv()
{
	struct dt_node *node;
	const struct dt_property *base;
	uint64_t uv_src_addr, uv_pef_reg, uv_pef_size;

	prlog(PR_DEBUG, "UV: Init starting\n");

	if (!is_msr_bit_set(MSR_S)) {
		prerror("UV: S bit not set\n");
		goto load_error;
	}

	if (!(uv_opal = zalloc(sizeof(struct uv_opal)))) {
		prerror("UV: Failed to allocate uv_opal\n");
		goto load_error;
	}


	if (!(node = find_uv_node())) {
		prerror("UV: Device tree node not found\n");
		goto load_error;
	}

	if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS) {
		prlog(PR_INFO, "UV: Mambo simulator detected\n");

		if (!find_secure_mem_to_copy(&uv_pef_reg, &uv_pef_size)) {
			prerror("UV: No secure memory configured, exiting\n");
			goto load_error;
		}

		goto start;
	}

	tpm_nv_init();

	/* This would be null in case we are on Mambo or Cronus */
	if (!uv_xz) {

		prlog(PR_INFO, "UV: Platform load failed, detecting UV image via device tree\n");

		if (!find_secure_mem_to_copy(&uv_pef_reg, &uv_pef_size)) {
			prerror("UV: No secure memory configured, exiting\n");
			goto load_error;
		}

		if (!(uv_src_addr = find_uv_fw_base_addr(node))) {
			prerror("UV: Couldn't find UV base address in device tree\n");
			goto load_error;
		}

		prlog(PR_INFO, "UV: Copying Ultravisor to protected memory 0x%llx from 0x%llx\n", uv_pef_reg, uv_src_addr);

		memcpy((void *)uv_pef_reg, (void *)uv_src_addr, UV_LOAD_MAX_SIZE);

		goto start;
	}

	/* Hostboot path */
	wait_xz_decompress(uv_xz);
	if (uv_xz->status) {
		prerror("UV: Compressed Ultravisor image failed to decompress");
		goto load_error;
	}

	/* the uncompressed location will be the base address of ultravisor
	 * so fix up if it's already there */
	base = dt_find_property(node, "reg");
	if (base)
		dt_del_property(node, (struct dt_property *)base);

	dt_add_property_u64(node, "reg", (uint64_t)uv_xz->dst);

	uv_pef_reg = (uint64_t)uv_xz->dst;
	uv_pef_size = (uint64_t)uv_xz->dst_size;

start:
	uv_opal->uv_base_addr = uv_pef_reg;
	uv_opal->uv_mem = (__be64)&uv_memcons;
	/*
	 * Place the uv_fdt 128MB below the top of secure memory.
	 * UV should/will copy this information out early during
	 * start up and clear it out. So this information needs
	 * to be preserved until then.
	 */
	uv_opal->uv_fdt = uv_pef_reg + uv_pef_size - (128<<20);

	dt_add_property_u64(node, "memcons", (u64)&uv_memcons);
	debug_descriptor.uv_memcons_phys = (u64)&uv_memcons;

	uv_opal->sys_fdt = (__be64)create_dtb(dt_root, false);
	if (!uv_opal->sys_fdt) {
		prerror("UV: Failed to create system fdt\n");
		goto load_error;
	}

load_error:
	free_uv();
	free(uv_xz);
}

static bool dt_append_memory_range(struct dt_node *node, __be64 start,
				   __be64 len)
{
	const struct dt_property *ranges;
	size_t size;
	u32 *new_ranges;
	int i;

	/* for Cronus boot the BML script creates secure-memory-ranges
	 * for Mambo boot the ultra.tcl script create secure-memory ranges
	 * for HostBoot, skiboot parses HDAT in hdata/memory.c and creates it here */
	ranges = dt_find_property(node, "secure-memory-ranges");
	if (!ranges) {
		prlog(PR_DEBUG, "Creating secure-memory-ranges.\n");
		ranges = dt_add_property_cells(node, "secure-memory-ranges",
					       hi32(start), lo32(start),
					       hi32(len), lo32(len));
		return true;
	}

	prlog(PR_DEBUG, "Adding secure memory range range at 0x%llx of size: 0x%llx\n", start, len);
	/* Calculate the total size in bytes of the new property */
	size = ranges->len + 16;
	new_ranges = (u32 *)malloc(size);
	memcpy(new_ranges, ranges->prop, ranges->len);

	i = ranges->len / 4;
	/* The ranges property will be of type <addr size ...> */
	new_ranges[i++] = hi32(start);
	new_ranges[i++] = lo32(start);
	new_ranges[i++] = hi32(len);
	new_ranges[i] = lo32(len);

	/* Update our node with the new set of ranges */
	dt_del_property(node, (struct dt_property *)ranges);
	dt_add_property(node, "secure-memory-ranges", (void *)new_ranges, size);

	return true;
}

/*
 * This code returns false on invalid memory ranges and in no-secure mode.
 * It is the caller's responsibility of moving the memory to appropriate
 * reserved areas.
 */
bool uv_add_mem_range(__be64 start, __be64 end)
{
	struct dt_node *uv_node;
	bool ret = false;
	char buff[128];

	if (!is_msr_bit_set(MSR_S))
		return ret;

	/* Check if address range is secure */
	if (!((start & UV_SECURE_MEM_BIT) && (end & UV_SECURE_MEM_BIT))) {
		prlog(PR_DEBUG, "Invalid secure address range.\n");
		return ret;
	}

	uv_node = find_uv_node();
	if (!uv_node) {
		prlog(PR_ERR, "Could not create uv node\n");
		return false;
	}

	ret = dt_append_memory_range(uv_node, start, end - start);

	if (ret)
		prlog(PR_NOTICE, "UV: Secure memory range added to DT [0x%016llx..0x%015llx]\n", start, end);

	snprintf(buff, 128, "ibm,secure-mem%d", num_secure_ranges++);
	mem_reserve_fw(strdup(buff), start, end - start);

	return ret;
}

/*
 * Preload the UV image from PNOR partition
 */
void uv_preload_image(void)
{
	int ret;

	prlog(PR_INFO, "UV: Preload starting\n");

	if (!alloc_uv()) {
		prerror("UV: Memory allocation failed\n");
		return;
	}

	ret = start_preload_resource(RESOURCE_ID_UV_IMAGE, RESOURCE_SUBID_NONE,
				     uv_image, &uv_image_size);

	if (ret != OPAL_SUCCESS) {
		prerror("UV: platform load failed: %d\n", ret);
	}
}

/*
 * Decompress the UV image
 *
 * This function modifies the uv_image variable to point to the decompressed
 * image location.
 */
void uv_decompress_image(void)
{
	const struct dt_property *ranges;
	struct dt_node *uv_node;
	uint64_t *range;

	if (uv_image == NULL) {
		prerror("UV: Preload hasn't started yet! Aborting.\n");
		return;
	}

	if (wait_for_resource_loaded(RESOURCE_ID_UV_IMAGE,
				     RESOURCE_SUBID_NONE) != OPAL_SUCCESS) {
		prerror("UV: Ultravisor image load failed\n");
		return;
	}

	uv_node = dt_find_compatible_node(dt_root, NULL, "ibm,uv-firmware");
	if (!uv_node) {
		prerror("UV: Cannot find ibm,uv-firmware node\n");
		return;
	}

	ranges = dt_find_property(uv_node, "secure-memory-ranges");
	if (!ranges) {
		prerror("UV: Cannot find secure-memory-ranges");
		return;
	}

	uv_xz = malloc(sizeof(struct xz_decompress));
	if (!uv_xz) {
		prerror("UV: Cannot allocate memory for decompression of UV\n");
		return;
	}

	/* the load area is the first secure memory range */
	range = (void *)ranges->prop;
	uv_xz->dst = (void *)dt_get_number(range, 2);
	uv_xz->dst_size = dt_get_number(range + 1, 2);
	uv_xz->src = uv_image;
	uv_xz->src_size = uv_image_size;

	if (stb_is_container((void*)uv_xz->src, uv_xz->src_size))
		uv_xz->src = uv_xz->src + SECURE_BOOT_HEADERS_SIZE;

	/* TODO security and integrity checks? */
	xz_start_decompress(uv_xz);
	if ((uv_xz->status != OPAL_PARTIAL) && (uv_xz->status != OPAL_SUCCESS))
		prerror("UV: XZ decompression failed status 0x%x\n", uv_xz->status);
}
