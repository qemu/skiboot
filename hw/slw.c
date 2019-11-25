// SPDX-License-Identifier: Apache-2.0
/*
 * Everything to do with deep power saving (stop) states
 * SLeep/Winkle, Handle ChipTOD chip & configure core timebases
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <xscom.h>
#include <xscom-p8-regs.h>
#include <xscom-p9-regs.h>
#include <io.h>
#include <cpu.h>
#include <chip.h>
#include <mem_region.h>
#include <chiptod.h>
#include <interrupts.h>
#include <timebase.h>
#include <errorlog.h>
#include <libfdt/libfdt.h>
#include <opal-api.h>
#include <nvram.h>
#include <sbe-p8.h>
#include <bitmap.h>

#include <p9_stop_api.H>
#include <p8_pore_table_gen_api.H>
#include <sbe_xip_image.h>

#define MAX_RESET_PATCH_SIZE	64
/* The POWER ISA mf/mtspr allows atmost 2048 SPRs. */
#define SPR_BITMAP_LENGTH		2048
#define DEFAULT_CPMMR_VALUE 0x2022000000000000

static uint32_t slw_saved_reset[MAX_RESET_PATCH_SIZE];

static bool slw_current_le = false;

enum wakeup_engine_states wakeup_engine_state = WAKEUP_ENGINE_NOT_PRESENT;
bool has_deep_states = false;

#define HILE_BIT	PPC_BIT(4)
#define RADIX_BIT	PPC_BIT(8)
#define default_hid0_val (HILE_BIT | RADIX_BIT)
/**
 * The struct and SPR list is a subset of the libpore/p9_stop_api.c counterpart
 */
/**
 * @brief summarizes attributes associated with a SPR register.
 */
typedef struct
{
    uint32_t iv_sprId;
    bool     iv_isThreadScope;
    uint32_t iv_saveMaskPos;

} StopSprReg_t;

/**
 * @brief a true in the table below means register is of scope thread
 * whereas a false meanse register is of scope core.
 * The number is the bit position on a uint32_t mask
 */

static const StopSprReg_t g_sprRegister[] =
{
	{ P9_STOP_SPR_DAWR,      true,  1   },
	{ P9_STOP_SPR_HSPRG0,    true,  3   },
	{ P9_STOP_SPR_LDBAR,     true,  4,  },
	{ P9_STOP_SPR_LPCR,      true,  5   },
	{ P9_STOP_SPR_PSSCR,     true,  6   },
	{ P9_STOP_SPR_MSR,       true,  7   },
	{ P9_STOP_SPR_HRMOR,     false, 255 },
	{ P9_STOP_SPR_HID,       false, 21  },
	{ P9_STOP_SPR_HMEER,     false, 22  },
	{ P9_STOP_SPR_PMCR,      false, 23  },
	{ P9_STOP_SPR_PTCR,      false, 24  },
	{ P9_STOP_SPR_URMOR,     false, 255 },
	{ P9_STOP_SPR_SMFCTRL,   true,  28  },
	{ P9_STOP_SPR_USPRG0,    true,  29  },
	{ P9_STOP_SPR_USPRG1,    true,  30  },
};

static const uint32_t MAX_SPR_SUPPORTED	= ARRAY_SIZE(g_sprRegister);
uint32_t find_mask_self_save(const uint64_t sprn);
bool self_restore_cpu_iterator(uint64_t sprn, uint64_t val);
bool self_save_cpu_iterator(const uint64_t self_save_reg);

DEFINE_LOG_ENTRY(OPAL_RC_SLW_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SLW_SET, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SLW_GET, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SLW_REG, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
		 OPAL_NA);

static void slw_do_rvwinkle(void *data)
{
	struct cpu_thread *cpu = this_cpu();
	struct cpu_thread *master = data;
	uint64_t lpcr = mfspr(SPR_LPCR);
	struct proc_chip *chip;

	/* Setup our ICP to receive IPIs */
	icp_prep_for_pm();

	/* Setup LPCR to wakeup on external interrupts only */
	mtspr(SPR_LPCR, ((lpcr & ~SPR_LPCR_P8_PECE) | SPR_LPCR_P8_PECE2));
	isync();

	prlog(PR_DEBUG, "SLW: CPU PIR 0x%04x going to rvwinkle...\n",
	      cpu->pir);

	/* Tell that we got it */
	cpu->state = cpu_state_rvwinkle;

	enter_p8_pm_state(1);

	/* Restore SPRs */
	init_shared_sprs();
	init_replicated_sprs();

	/* Ok, it's ours again */
	cpu->state = cpu_state_active;

	prlog(PR_DEBUG, "SLW: CPU PIR 0x%04x woken up !\n", cpu->pir);

	/* Cleanup our ICP */
	reset_cpu_icp();

	/* Resync timebase */
	chiptod_wakeup_resync();

	/* Restore LPCR */
	mtspr(SPR_LPCR, lpcr);
	isync();

	/* If we are passed a master pointer we are the designated
	 * waker, let's proceed. If not, return, we are finished.
	 */
	if (!master)
		return;

	prlog(PR_DEBUG, "SLW: CPU PIR 0x%04x waiting for master...\n",
	      cpu->pir);

	/* Allriiiight... now wait for master to go down */
	while(master->state != cpu_state_rvwinkle)
		sync();

	/* XXX Wait one second ! (should check xscom state ? ) */
	time_wait_ms(1000);

	for_each_chip(chip) {
		struct cpu_thread *c;
		uint64_t tmp;
		for_each_available_core_in_chip(c, chip->id) {
			xscom_read(chip->id,
				 XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
							EX_PM_IDLE_STATE_HISTORY_PHYP),
				   &tmp);	
			prlog(PR_TRACE, "SLW: core %x:%x"
			      " history: 0x%016llx (mid2)\n",
			      chip->id, pir_to_core_id(c->pir),
			      tmp);
		}
	}

	prlog(PR_DEBUG, "SLW: Waking master (PIR 0x%04x)...\n", master->pir);

	/* Now poke all the secondary threads on the master's core */
	for_each_cpu(cpu) {
		if (!cpu_is_sibling(cpu, master) || (cpu == master))
			continue;
		icp_kick_cpu(cpu);

		/* Wait for it to claim to be back (XXX ADD TIMEOUT) */
		while(cpu->state != cpu_state_active)
			sync();
	}

	/* Now poke the master and be gone */
	icp_kick_cpu(master);
}

static void slw_patch_reset(void)
{
	uint32_t *src, *dst, *sav;

	BUILD_ASSERT((&reset_patch_end - &reset_patch_start) <=
		     MAX_RESET_PATCH_SIZE);

	src = &reset_patch_start;
	dst = (uint32_t *)0x100;
	sav = slw_saved_reset;
	while(src < &reset_patch_end) {
		*(sav++) = *(dst);
		*(dst++) = *(src++);
	}
	sync_icache();
}

static void slw_unpatch_reset(void)
{
	extern uint32_t reset_patch_start;
	extern uint32_t reset_patch_end;
	uint32_t *src, *dst, *sav;

	src = &reset_patch_start;
	dst = (uint32_t *)0x100;
	sav = slw_saved_reset;
	while(src < &reset_patch_end) {
		*(dst++) = *(sav++);
		src++;
	}
	sync_icache();
}

static bool slw_general_init(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp;
	int rc;

	/* PowerManagement GP0 clear PM_DISABLE */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP0), &tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
				"SLW: Failed to read PM_GP0\n");
		return false;
	}
	tmp = tmp & ~0x8000000000000000ULL;
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP0), tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
				"SLW: Failed to write PM_GP0\n");
		return false;
	}
	prlog(PR_TRACE, "SLW: PMGP0 set to 0x%016llx\n", tmp);

	/* Read back for debug */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP0), &tmp);
	if (rc)
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
				 "SLW: Failed to re-read PM_GP0. Continuing...\n");

	prlog(PR_TRACE, "SLW: PMGP0 read   0x%016llx\n", tmp);

	return true;
}

static bool slw_set_overrides(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	int rc;

	rc = xscom_write(chip->id,
			 XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_SPECIAL_WAKEUP_PHYP),
			 0);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
			"SLW: Failed to write PM_SPECIAL_WAKEUP_PHYP\n");
		return false;
	}

	return true;
}

static bool slw_set_overrides_p9(struct proc_chip *chip, struct cpu_thread *c)
{
	uint64_t tmp;
	int rc;
	uint32_t core = pir_to_core_id(c->pir);

	/* Clear special wakeup bits that could hold power mgt */
	rc = xscom_write(chip->id,
			 XSCOM_ADDR_P9_EC_SLAVE(core, EC_PPM_SPECIAL_WKUP_HYP),
			 0);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
			"SLW: Failed to write EC_PPM_SPECIAL_WKUP_HYP\n");
		return false;
	}
	/* Read back for debug */
	rc = xscom_read(chip->id,
			XSCOM_ADDR_P9_EC_SLAVE(core, EC_PPM_SPECIAL_WKUP_HYP),
			&tmp);
	if (tmp)
		prlog(PR_WARNING,
			"SLW: core %d EC_PPM_SPECIAL_WKUP_HYP read  0x%016llx\n",
		     core, tmp);
	rc = xscom_read(chip->id,
			XSCOM_ADDR_P9_EC_SLAVE(core, EC_PPM_SPECIAL_WKUP_OTR),
			&tmp);
	if (tmp)
		prlog(PR_WARNING,
			"SLW: core %d EC_PPM_SPECIAL_WKUP_OTR read  0x%016llx\n",
		      core, tmp);
	return true;
}

static bool slw_unset_overrides(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);

	/* XXX FIXME: Save and restore the overrides */
	prlog(PR_DEBUG, "SLW: slw_unset_overrides %x:%x\n", chip->id, core);
	return true;
}

static bool slw_set_idle_mode(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp;
	int rc;

	/*
	 * PM GP1 allows fast/deep mode to be selected independently for sleep
	 * and winkle. Init PM GP1 so that sleep happens in fast mode and
	 * winkle happens in deep mode.
	 * Make use of the OR XSCOM for this since the OCC might be manipulating
	 * the PM_GP1 register as well. Before doing this ensure that the bits
	 * managing idle states are cleared so as to override any bits set at
	 * init time.
	 */

	tmp = ~EX_PM_GP1_SLEEP_WINKLE_MASK;
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_CLEAR_GP1),
			 tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
						"SLW: Failed to write PM_GP1\n");
		return false;
	}

	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_SET_GP1),
			 EX_PM_SETUP_GP1_FAST_SLEEP_DEEP_WINKLE);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
						"SLW: Failed to write PM_GP1\n");
		return false;
	}

	/* Read back for debug */
	xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP1), &tmp);
	prlog(PR_TRACE, "SLW: PMGP1 read   0x%016llx\n", tmp);
	return true;
}

static bool slw_get_idle_state_history(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp;
	int rc;

	/* Cleanup history */
	rc = xscom_read(chip->id,
		   XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_IDLE_STATE_HISTORY_PHYP),
		   &tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_GET),
			"SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		return false;
	}

	prlog(PR_TRACE, "SLW: core %x:%x history: 0x%016llx (old1)\n",
	    chip->id, core, tmp);

	rc = xscom_read(chip->id,
		   XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_IDLE_STATE_HISTORY_PHYP),
		   &tmp);

	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_GET),
			"SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		return false;
	}

	prlog(PR_TRACE, "SLW: core %x:%x history: 0x%016llx (old2)\n",
	    chip->id, core, tmp);

	return true;
}

static bool idle_prepare_core(struct proc_chip *chip, struct cpu_thread *c)
{
	prlog(PR_TRACE, "FASTSLEEP: Prepare core %x:%x\n",
	    chip->id, pir_to_core_id(c->pir));

	if(!slw_general_init(chip, c))
		return false;
	if(!slw_set_overrides(chip, c))
		return false;
	if(!slw_set_idle_mode(chip, c))
		return false;
	if(!slw_get_idle_state_history(chip, c))
		return false;

	return true;

}

/* Define device-tree fields */
#define MAX_NAME_LEN	16
struct cpu_idle_states {
	char name[MAX_NAME_LEN];
	u32 latency_ns;
	u32 residency_ns;
	/*
	 * Register value/mask used to select different idle states.
	 * PMICR in POWER8 and PSSCR in POWER9
	 */
	u64 pm_ctrl_reg_val;
	u64 pm_ctrl_reg_mask;
	u32 flags;
};

static struct cpu_idle_states nap_only_cpu_idle_states[] = {
	{ /* nap */
		.name = "nap",
		.latency_ns = 4000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_NAP_ENABLED \
		       | 0*OPAL_PM_SLEEP_ENABLED \
		       | 0*OPAL_PM_WINKLE_ENABLED \
		       | 0*OPAL_USE_PMICR,
		.pm_ctrl_reg_val = 0,
		.pm_ctrl_reg_mask = 0 },
};

static struct cpu_idle_states power8_cpu_idle_states[] = {
	{ /* nap */
		.name = "nap",
		.latency_ns = 4000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_NAP_ENABLED \
		       | 0*OPAL_USE_PMICR,
		.pm_ctrl_reg_val = 0,
		.pm_ctrl_reg_mask = 0 },
	{ /* fast sleep (with workaround) */
		.name = "fastsleep_",
		.latency_ns = 40000,
		.residency_ns = 300000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_SLEEP_ENABLED_ER1 \
		       | 0*OPAL_USE_PMICR, /* Not enabled until deep
						states are available */
		.pm_ctrl_reg_val = OPAL_PM_FASTSLEEP_PMICR,
		.pm_ctrl_reg_mask = OPAL_PM_SLEEP_PMICR_MASK },
	{ /* Winkle */
		.name = "winkle",
		.latency_ns = 10000000,
		.residency_ns = 1000000000, /* Educated guess (not measured).
					     * Winkle is not currently used by 
					     * linux cpuidle subsystem so we
					     * don't have real world user.
					     * However, this should be roughly
					     * accurate for when linux does
					     * use it. */
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_WINKLE_ENABLED \
		       | 0*OPAL_USE_PMICR, /* Currently choosing deep vs
						fast via EX_PM_GP1 reg */
		.pm_ctrl_reg_val = 0,
		.pm_ctrl_reg_mask = 0 },
};

/*
 * cpu_idle_states for key idle states of POWER9 that we want to
 * exploit.
 * Note latency_ns and residency_ns are estimated values for now.
 */
static struct cpu_idle_states power9_cpu_idle_states[] = {
	{
		.name = "stop0_lite", /* Enter stop0 with no state loss */
		.latency_ns = 1000,
		.residency_ns = 10000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 0*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3),
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop0",
		.latency_ns = 2000,
		.residency_ns = 20000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	/* stop1_lite has been removed since it adds no additional benefit over stop0_lite */

	{
		.name = "stop1",
		.latency_ns = 5000,
		.residency_ns = 50000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(1) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	/*
	 * stop2_lite has been removed since currently it adds minimal benefit over stop2.
	 * However, the benefit is eclipsed by the time required to ungate the clocks
	 */

	{
		.name = "stop2",
		.latency_ns = 10000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(2) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop4",
		.latency_ns = 100000,
		.residency_ns = 10000000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(4) \
				 | OPAL_PM_PSSCR_MTL(7) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop5",
		.latency_ns = 200000,
		.residency_ns = 20000000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(5) \
				 | OPAL_PM_PSSCR_MTL(7) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	{
		.name = "stop8",
		.latency_ns = 2000000,
		.residency_ns = 20000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(8) \
				 | OPAL_PM_PSSCR_MTL(11) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	{
		.name = "stop11",
		.latency_ns = 10000000,
		.residency_ns = 100000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(11) \
				 | OPAL_PM_PSSCR_MTL(11) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

};

/*
 * Latency for Stop4 and 5 are bumped up so that cpuidle path is not exercised
 * in the PEF environment, but the states are available to be exercised during a
 * hotplug
 */
static struct cpu_idle_states power9_pef_cpu_idle_states[] = {
	{
		.name = "stop0_lite", /* Enter stop0 with no state loss */
		.latency_ns = 1000,
		.residency_ns = 10000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 0*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3),
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop0",
		.latency_ns = 2000,
		.residency_ns = 20000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	/* stop1_lite has been removed since it adds no additional benefit over stop0_lite */

	{
		.name = "stop1",
		.latency_ns = 5000,
		.residency_ns = 50000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(1) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	/*
	 * stop2_lite has been removed since currently it adds minimal benefit over stop2.
	 * However, the benefit is eclipsed by the time required to ungate the clocks
	 */

	{
		.name = "stop2",
		.latency_ns = 10000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(2) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop4",
		.latency_ns = 10000000,
		.residency_ns = 100000000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(4) \
				 | OPAL_PM_PSSCR_MTL(7) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop5",
		.latency_ns = 10000000,
		.residency_ns = 100000000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(5) \
				 | OPAL_PM_PSSCR_MTL(7) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
};

/*
 * Prior to Mambo.7.8.21, mambo did set the MSR correctly for lite stop
 * states, so disable them for now.
 */
static struct cpu_idle_states power9_mambo_cpu_idle_states[] = {
	{
		.name = "stop0",
		.latency_ns = 2000,
		.residency_ns = 20000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop1",
		.latency_ns = 5000,
		.residency_ns = 50000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(1) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop2",
		.latency_ns = 10000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(2) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop4",
		.latency_ns = 100000,
		.residency_ns = 1000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(4) \
				 | OPAL_PM_PSSCR_MTL(7) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	{
		.name = "stop8",
		.latency_ns = 2000000,
		.residency_ns = 20000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(8) \
				 | OPAL_PM_PSSCR_MTL(11) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	{
		.name = "stop11",
		.latency_ns = 10000000,
		.residency_ns = 100000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(11) \
				 | OPAL_PM_PSSCR_MTL(11) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

};

static void slw_late_init_p9(struct proc_chip *chip)
{
	struct cpu_thread *c;
	int rc;

	prlog(PR_INFO, "SLW: Configuring self-restore for HRMOR\n");
	for_each_available_cpu(c) {
		if (c->chip_id != chip->id)
			continue;
		/*
		 * Clear HRMOR. Need to update only for thread
		 * 0 of each core. Doing it anyway for all threads
		 */
		rc =  p9_stop_save_cpureg((void *)chip->homer_base,
						P9_STOP_SPR_HRMOR, 0,
						c->pir);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Failed to set HRMOR for CPU %x,RC=0x%x\n",
			c->pir, rc);
			prlog(PR_ERR, "Disabling deep stop states\n");
		}
	}
}

uint32_t __attribute__((const))
find_mask_self_save(const uint64_t sprn)
{
	uint32_t save_reg_vector = -1;
	int index;
	for (index = 0; index < MAX_SPR_SUPPORTED; ++index) {
		if (sprn == (CpuReg_t) g_sprRegister[index].iv_sprId) {
			save_reg_vector = PPC_BIT32(
					g_sprRegister[index].iv_saveMaskPos);
			break;
		}
	}
	return save_reg_vector;
}

bool __attribute__((const))
self_restore_cpu_iterator(uint64_t sprn, uint64_t val)
{
	struct cpu_thread *cpu;
	struct proc_chip *chip;
	int rc;

	for_each_available_cpu(cpu) {
		chip = get_chip(cpu->chip_id);
		rc = p9_stop_save_cpureg((void *)chip->homer_base,
					 sprn,
					 val,
					 cpu->pir);
		if (rc) {
			prlog(PR_ERR,
			      "SLW: Failed to set spr %llx for CPU %x, RC=0x%x\n",
			      sprn, cpu->pir, rc);
			return rc;
		}
	}
	return rc;
}

bool __attribute__((const))
self_save_cpu_iterator(const uint64_t self_save_reg)
{
	struct cpu_thread *cpu;
	struct proc_chip *chip;
	int rc;
	uint32_t save_reg_vector;

	for_each_available_cpu(cpu) {
		chip = get_chip(cpu->chip_id);
		save_reg_vector =
			find_mask_self_save(self_save_reg);
		if (save_reg_vector == -1)
			return true;
		rc = p9_stop_save_cpureg_control((void *) chip->homer_base,
						 cpu->pir,
						 save_reg_vector);
		if (rc) {
			prlog(PR_ERR,
			      "SLW: Failed to set spr %llx for CPU %x, RC=0x%x\n",
			      self_save_reg, cpu->pir, rc);
			return rc;
		}
		prlog(PR_NOTICE, "SLW: Self save reg: 0x%llx\n",
		      self_save_reg);
	}
	return rc;
}
/* Add device tree properties to determine self-save | restore */
void add_cpu_self_save_properties()
{
	int i, rc;
	struct dt_node *self_restore, *self_save, *power_mgt;
	bitmap_t *self_restore_map, *self_save_map;

	const uint64_t self_restore_regs[] = {
		0x130, // HSPRG0
		0x13E, // LPCR
		0x151, // HMEER
		0x3F0, // HID0
		0x3F1, // HID1
		0x3F4, // HID4
		0x3F6, // HID5
		0x7D0, // MSR
		0x357 // PSCCR
	};

	const uint64_t self_save_regs[] = {
		0x130, // HSPRG0
		0x13E, // LPCR
		0x151, // HMEER
		0x7D0, // MSR
		0x1D0, //PTCR
		0x1F0, // USPRG0
		0x1F1, //USPRG1
		0x1FF, //SMFCTRL
		0x357 // PSCCR
	};

	uint64_t *ucall_location_100 = (uint64_t *)0x20ffffe00100;
	uint64_t *ucall_location_110 = (uint64_t *)0x20FFFFE00110;
	uint64_t *ucall_location_120 = (uint64_t *)0x20FFFFE00120;
	const int arr_100 [] = {
		0x48000020,
		0xa64a397c,
		0xa600a07e,
		0xa407b57a
	};

	const int arr_110 [] = {
		0xa603bb7e,
		0x20012138,
		0xa6033a7c,
		0x2400004c
	};

	const int arr_120 [] = {
		0x44000042,
		0x00000200,
		0x00000200,
		0x00000200
	};

	self_save_map = zalloc(BITMAP_BYTES(SPR_BITMAP_LENGTH));
	self_restore_map = zalloc(BITMAP_BYTES(SPR_BITMAP_LENGTH));

	for (i = 0; i < ARRAY_SIZE(self_restore_regs); i++) {
		if (is_msr_bit_set(MSR_S) && self_restore_regs[i] != P9_STOP_SPR_HID)
			continue;
		bitmap_set_bit(*self_restore_map, self_restore_regs[i]);
	}

	if (is_msr_bit_set(MSR_S)) {
		rc = self_restore_cpu_iterator(P9_STOP_SPR_HID,
					       default_hid0_val);
		if (rc)
			goto bail;
		if (uv_base_addr) {
			rc = self_restore_cpu_iterator(P9_STOP_SPR_URMOR,
						       uv_base_addr);
			if (rc)
				goto bail;
		} else {
			prlog(PR_ERR,
			      "SLW: uv_base_addr is NULL\n");
			goto bail;
		}
	}
	for (i = 0; i < ARRAY_SIZE(self_save_regs); i++) {
		bitmap_set_bit(*self_save_map, self_save_regs[i]);
		if (!is_msr_bit_set(MSR_S))
			continue;
		rc = self_save_cpu_iterator(self_save_regs[i]);
		if (rc)
			goto bail;
	}

	power_mgt = dt_find_by_path(dt_root, "/ibm,opal/power-mgt");
	if (!power_mgt) {
		prerror("OCC: dt node /ibm,opal/power-mgt not found\n");
		goto bail;
	}

	self_restore = dt_new(power_mgt, "self-restore");
	if (!self_restore) {
		prerror("OCC: Failed to create self restore node");
		goto bail;
	}
	dt_add_property_string(self_restore, "status", "enabled");

	dt_add_property(self_restore, "sprn-bitmask", *self_restore_map,
			SPR_BITMAP_LENGTH / 8);

	self_save = dt_new(power_mgt, "self-save");
	if (!self_save) {
		prerror("OCC: Failed to create self save node");
		goto bail;
	}
	if (proc_gen == proc_gen_p9) {
		dt_add_property_string(self_save, "status", "enabled");

		dt_add_property(self_save, "sprn-bitmask", *self_save_map,
				SPR_BITMAP_LENGTH / 8);
	} else {
		dt_add_property_string(self_save, "status", "disabled");
	}

	/* Patching code in the HCODE that solves the BE_LE switch for SC2
	 * instruction */
	memcpy(ucall_location_100, arr_100, sizeof(arr_100));
	memcpy(ucall_location_110, arr_110, sizeof(arr_110));
	memcpy(ucall_location_120, arr_120, sizeof(arr_120));
bail:
	free(self_save_map);
	free(self_restore_map);
}

/* Add device tree properties to describe idle states */
void add_cpu_idle_state_properties(void)
{
	struct dt_node *power_mgt;
	struct cpu_idle_states *states;
	struct proc_chip *chip;
	int nr_states;

	bool can_sleep = true;
	bool has_stop_inst = false;
	u8 i;

	u64 *pm_ctrl_reg_val_buf;
	u64 *pm_ctrl_reg_mask_buf;
	u32 supported_states_mask;
	u32 opal_disabled_states_mask = ~0xEC000000; /* all but stop11 */
	const char* nvram_disable_str;
	u32 nvram_disabled_states_mask = 0x00;
	u32 stop_levels;

	/* Variables to track buffer length */
	u8 name_buf_len;
	u8 num_supported_idle_states;

	/* Buffers to hold idle state properties */
	char *name_buf, *alloced_name_buf;
	u32 *latency_ns_buf;
	u32 *residency_ns_buf;
	u32 *flags_buf;

	prlog(PR_DEBUG, "CPU idle state device tree init\n");

	/* Create /ibm,opal/power-mgt if it doesn't exist already */
	power_mgt = dt_new_check(opal_node, "power-mgt");
	if (!power_mgt) {
		/**
		 * @fwts-label CreateDTPowerMgtNodeFail
		 * @fwts-advice OPAL failed to add the power-mgt device tree
		 * node. This could mean that firmware ran out of memory,
		 * or there's a bug somewhere.
		 */
		prlog(PR_ERR, "creating dt node /ibm,opal/power-mgt failed\n");
		return;
	}

	/*
	 * Chose the right state table for the chip
	 *
	 * XXX We use the first chip version, we should probably look
	 * for the smaller of all chips instead..
	 */
	chip = next_chip(NULL);
	assert(chip);
	if (chip->type == PROC_CHIP_P9_NIMBUS ||
	    chip->type == PROC_CHIP_P9_CUMULUS) {
		if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS) {
			states = power9_mambo_cpu_idle_states;
			nr_states = ARRAY_SIZE(power9_mambo_cpu_idle_states);
		} else if (is_msr_bit_set(MSR_S)) {
			prlog(PR_EMERG, "pef state table is enabled\n");
			states = power9_pef_cpu_idle_states;
			nr_states = ARRAY_SIZE(power9_pef_cpu_idle_states);
		} else {
			states = power9_cpu_idle_states;
			nr_states = ARRAY_SIZE(power9_cpu_idle_states);
		}

		has_stop_inst = true;
		stop_levels = dt_prop_get_u32_def(power_mgt,
			"ibm,enabled-stop-levels", 0);
		if (stop_levels != 0) {
			prerror("HACK: stop levels enabled, forcing stop0 and stop1\n");
			stop_levels = 0xc0000000;
		}
		if (!stop_levels) {
			prerror("SLW: No stop levels available. Power saving is disabled!\n");
			has_deep_states = false;
		} else {
		/* Iterate to see if we have deep states enabled */
			for (i = 0; i < nr_states; i++) {
				u32 level = 31 - (states[i].pm_ctrl_reg_val &
					 OPAL_PM_PSSCR_RL_MASK);

				if ((stop_levels & (1ul << level)) &&
					(states[i].flags & OPAL_PM_STOP_INST_DEEP))
					has_deep_states = true;
				}
			}
			if ((wakeup_engine_state == WAKEUP_ENGINE_PRESENT) && has_deep_states) {
				slw_late_init_p9(chip);
				xive_late_init();
				nx_p9_rng_late_init();
			}
			if (wakeup_engine_state != WAKEUP_ENGINE_PRESENT)
				has_deep_states = false;
	} else if (chip->type == PROC_CHIP_P8_MURANO ||
	    chip->type == PROC_CHIP_P8_VENICE ||
	    chip->type == PROC_CHIP_P8_NAPLES) {
		const struct dt_property *p;

		p = dt_find_property(dt_root, "ibm,enabled-idle-states");
		if (p)
			prlog(PR_NOTICE,
			      "SLW: HB-provided idle states property found\n");
		states = power8_cpu_idle_states;
		nr_states = ARRAY_SIZE(power8_cpu_idle_states);

		/* Check if hostboot say we can sleep */
		if (!p || !dt_prop_find_string(p, "fast-sleep")) {
			prlog(PR_WARNING, "SLW: Sleep not enabled by HB"
			      " on this platform\n");
			can_sleep = false;
		}

		/* Clip to NAP only on Murano and Venice DD1.x */
		if ((chip->type == PROC_CHIP_P8_MURANO ||
		     chip->type == PROC_CHIP_P8_VENICE) &&
		    chip->ec_level < 0x20) {
			prlog(PR_NOTICE, "SLW: Sleep not enabled on P8 DD1.x\n");
			can_sleep = false;
		}

	} else {
		states = nap_only_cpu_idle_states;
		nr_states = ARRAY_SIZE(nap_only_cpu_idle_states);
	}


	/*
	 * Currently we can't append strings and cells to dt properties.
	 * So create buffers to which you can append values, then create
	 * dt properties with this buffer content.
	 */

	/* Allocate memory to idle state property buffers. */
	alloced_name_buf= malloc(nr_states * sizeof(char) * MAX_NAME_LEN);
	name_buf = alloced_name_buf;
	latency_ns_buf	= malloc(nr_states * sizeof(u32));
	residency_ns_buf= malloc(nr_states * sizeof(u32));
	flags_buf	= malloc(nr_states * sizeof(u32));
	pm_ctrl_reg_val_buf	= malloc(nr_states * sizeof(u64));
	pm_ctrl_reg_mask_buf	= malloc(nr_states * sizeof(u64));

	name_buf_len = 0;
	num_supported_idle_states = 0;

	/*
	 * Create a mask with the flags of all supported idle states
	 * set. Use this to only add supported idle states to the
	 * device-tree
	 */
	if (has_stop_inst) {
		/* Power 9 / POWER ISA 3.0 */
		supported_states_mask = OPAL_PM_STOP_INST_FAST;
		if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT)
			supported_states_mask |= OPAL_PM_STOP_INST_DEEP;
	} else {
		/* Power 7 and Power 8 */
		supported_states_mask = OPAL_PM_NAP_ENABLED;
		if (can_sleep)
			supported_states_mask |= OPAL_PM_SLEEP_ENABLED |
						OPAL_PM_SLEEP_ENABLED_ER1;
		if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT)
			supported_states_mask |= OPAL_PM_WINKLE_ENABLED;
	}
	nvram_disable_str = nvram_query_dangerous("opal-stop-state-disable-mask");
	if (nvram_disable_str)
		nvram_disabled_states_mask = strtol(nvram_disable_str, NULL, 0);
	prlog(PR_DEBUG, "NVRAM stop disable mask: %x\n", nvram_disabled_states_mask);
	for (i = 0; i < nr_states; i++) {
		/* For each state, check if it is one of the supported states. */
		if (!(states[i].flags & supported_states_mask))
			continue;

		/* We can only use the stop levels that HB has made available */
		if (has_stop_inst) {
			u32 level = 31 - (states[i].pm_ctrl_reg_val &
					 OPAL_PM_PSSCR_RL_MASK);

			if (!(stop_levels & (1ul << level)))
				continue;

			if ((opal_disabled_states_mask |
			     nvram_disabled_states_mask) &
			    (1ul << level)) {
				if (nvram_disable_str &&
				    !(nvram_disabled_states_mask & (1ul << level))) {
					prlog(PR_NOTICE, "SLW: Enabling: %s "
					      "(disabled in OPAL, forced by "
					      "NVRAM)\n",states[i].name);
				} else {
					prlog(PR_NOTICE, "SLW: Disabling: %s in OPAL\n",
					      states[i].name);
					continue;
				}
			}
		}

		prlog(PR_INFO, "SLW: Enabling: %s\n", states[i].name);

		/*
		 * If a state is supported add each of its property
		 * to its corresponding property buffer.
		 */
		strncpy(name_buf, states[i].name, MAX_NAME_LEN);
		name_buf = name_buf + strlen(states[i].name) + 1;

		*latency_ns_buf = cpu_to_fdt32(states[i].latency_ns);
		latency_ns_buf++;

		*residency_ns_buf = cpu_to_fdt32(states[i].residency_ns);
		residency_ns_buf++;

		*flags_buf = cpu_to_fdt32(states[i].flags);
		flags_buf++;

		*pm_ctrl_reg_val_buf = cpu_to_fdt64(states[i].pm_ctrl_reg_val);
		pm_ctrl_reg_val_buf++;

		*pm_ctrl_reg_mask_buf = cpu_to_fdt64(states[i].pm_ctrl_reg_mask);
		pm_ctrl_reg_mask_buf++;

		/* Increment buffer length trackers */
		name_buf_len += strlen(states[i].name) + 1;
		num_supported_idle_states++;

	}

	/* Point buffer pointers back to beginning of the buffer */
	name_buf -= name_buf_len;
	latency_ns_buf -= num_supported_idle_states;
	residency_ns_buf -= num_supported_idle_states;
	flags_buf -= num_supported_idle_states;
	pm_ctrl_reg_val_buf -= num_supported_idle_states;
	pm_ctrl_reg_mask_buf -= num_supported_idle_states;
	/* Create dt properties with the buffer content */
	dt_add_property(power_mgt, "ibm,cpu-idle-state-names", name_buf,
			name_buf_len* sizeof(char));
	dt_add_property(power_mgt, "ibm,cpu-idle-state-latencies-ns",
			latency_ns_buf, num_supported_idle_states * sizeof(u32));
	dt_add_property(power_mgt, "ibm,cpu-idle-state-residency-ns",
			residency_ns_buf, num_supported_idle_states * sizeof(u32));
	dt_add_property(power_mgt, "ibm,cpu-idle-state-flags", flags_buf,
			num_supported_idle_states * sizeof(u32));

	if (has_stop_inst) {
		dt_add_property(power_mgt, "ibm,cpu-idle-state-psscr",
				pm_ctrl_reg_val_buf,
				num_supported_idle_states * sizeof(u64));
		dt_add_property(power_mgt, "ibm,cpu-idle-state-psscr-mask",
				pm_ctrl_reg_mask_buf,
				num_supported_idle_states * sizeof(u64));
	} else {
		dt_add_property(power_mgt, "ibm,cpu-idle-state-pmicr",
				pm_ctrl_reg_val_buf,
				num_supported_idle_states * sizeof(u64));
		dt_add_property(power_mgt, "ibm,cpu-idle-state-pmicr-mask",
				pm_ctrl_reg_mask_buf,
				num_supported_idle_states * sizeof(u64));
	}
	assert(alloced_name_buf == name_buf);
	free(alloced_name_buf);
	free(latency_ns_buf);
	free(residency_ns_buf);
	free(flags_buf);
	free(pm_ctrl_reg_val_buf);
	free(pm_ctrl_reg_mask_buf);
}

static void slw_cleanup_core(struct proc_chip *chip, struct cpu_thread *c)
{
	uint64_t tmp;
	int rc;

	/* Display history to check transition */
	rc = xscom_read(chip->id,
			XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
					       EX_PM_IDLE_STATE_HISTORY_PHYP),
			&tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_GET),
			"SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		/* XXX error handling ? return false; */
	}

	prlog(PR_DEBUG, "SLW: core %x:%x history: 0x%016llx (new1)\n",
	       chip->id, pir_to_core_id(c->pir), tmp);

	rc = xscom_read(chip->id,
			XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
					       EX_PM_IDLE_STATE_HISTORY_PHYP),
			&tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_GET),
			"SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		/* XXX error handling ? return false; */
	}

	prlog(PR_DEBUG, "SLW: core %x:%x history: 0x%016llx (new2)\n",
	       chip->id, pir_to_core_id(c->pir), tmp);

	/*
	 * XXX FIXME: Error out if the transition didn't reach rvwinkle ?
	 */

	/*
	 * XXX FIXME: We should restore a bunch of the EX bits we
	 * overwrite to sane values here
	 */
	slw_unset_overrides(chip, c);
}

static void slw_cleanup_chip(struct proc_chip *chip)
{
	struct cpu_thread *c;

	for_each_available_core_in_chip(c, chip->id)
		slw_cleanup_core(chip, c);
}

static void slw_patch_scans(struct proc_chip *chip, bool le_mode)
{
	int64_t rc;
	uint64_t old_val, new_val;

	rc = sbe_xip_get_scalar((void *)chip->slw_base,
				"skip_ex_override_ring_scans", &old_val);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Failed to read scan override on chip %d\n",
			chip->id);
		return;
	}

	new_val = le_mode ? 0 : 1;

	prlog(PR_TRACE, "SLW: Chip %d, LE value was: %lld, setting to %lld\n",
	    chip->id, old_val, new_val);

	rc = sbe_xip_set_scalar((void *)chip->slw_base,
				"skip_ex_override_ring_scans", new_val);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Failed to set LE mode on chip %d\n", chip->id);
		return;
	}
}

int64_t slw_reinit(uint64_t flags)
{
	struct proc_chip *chip;
	struct cpu_thread *cpu;
	bool has_waker = false;
	bool target_le = slw_current_le;

	if (proc_gen < proc_gen_p8)
		return OPAL_UNSUPPORTED;

	if (flags & OPAL_REINIT_CPUS_HILE_BE)
		target_le = false;
	if (flags & OPAL_REINIT_CPUS_HILE_LE)
		target_le = true;

	prlog(PR_TRACE, "SLW Reinit from CPU PIR 0x%04x,"
	      " HILE set to %s endian...\n",
	      this_cpu()->pir,
	      target_le ? "little" : "big");

	/* Prepare chips/cores for rvwinkle */
	for_each_chip(chip) {
		if (!chip->slw_base) {
			log_simple_error(&e_info(OPAL_RC_SLW_INIT),
				"SLW: Not found on chip %d\n", chip->id);
			return OPAL_HARDWARE;
		}

		slw_patch_scans(chip, target_le);
	}
	slw_current_le = target_le;

	/* XXX Save HIDs ? Or do that in head.S ... */

	slw_patch_reset();

	/* rvwinkle everybody and pick one to wake me once I rvwinkle myself */
	for_each_available_cpu(cpu) {
		struct cpu_thread *master = NULL;

		if (cpu == this_cpu())
			continue;

		/* Pick up a waker for myself: it must not be a sibling of
		 * the current CPU and must be a thread 0 (so it gets to
		 * sync its timebase before doing time_wait_ms()
		 */
		if (!has_waker && !cpu_is_sibling(cpu, this_cpu()) &&
		    cpu_is_thread0(cpu)) {
			has_waker = true;
			master = this_cpu();
		}
		__cpu_queue_job(cpu, "slw_do_rvwinkle",
				slw_do_rvwinkle, master, true);

		/* Wait for it to claim to be down */
		while(cpu->state != cpu_state_rvwinkle)
			sync();		
	}

	/* XXX Wait one second ! (should check xscom state ? ) */
	prlog(PR_TRACE, "SLW: Waiting one second...\n");
	time_wait_ms(1000);
	prlog(PR_TRACE, "SLW: Done.\n");

	for_each_chip(chip) {
		struct cpu_thread *c;
		uint64_t tmp;
		for_each_available_core_in_chip(c, chip->id) {
			xscom_read(chip->id,
				 XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
							EX_PM_IDLE_STATE_HISTORY_PHYP),
				   &tmp);
			prlog(PR_DEBUG, "SLW: core %x:%x"
			      " history: 0x%016llx (mid)\n",
			      chip->id, pir_to_core_id(c->pir), tmp);
		}
	}


	/* Wake everybody except on my core */
	for_each_cpu(cpu) {
		if (cpu->state != cpu_state_rvwinkle ||
		    cpu_is_sibling(cpu, this_cpu()))
			continue;
		icp_kick_cpu(cpu);

		/* Wait for it to claim to be back (XXX ADD TIMEOUT) */
		while(cpu->state != cpu_state_active)
			sync();
	}

	/* Did we find a waker ? If we didn't, that means we had no
	 * other core in the system, we can't do it
	 */
	if (!has_waker) {
		prlog(PR_TRACE, "SLW: No candidate waker, giving up !\n");
		return OPAL_HARDWARE;
	}

	/* Our siblings are rvwinkling, and our waker is waiting for us
	 * so let's just go down now
	 */
	slw_do_rvwinkle(NULL);

	slw_unpatch_reset();

	for_each_chip(chip)
		slw_cleanup_chip(chip);

	prlog(PR_TRACE, "SLW Reinit complete !\n");

	return OPAL_SUCCESS;
}

static void slw_patch_regs(struct proc_chip *chip)
{
	struct cpu_thread *c;
	void *image = (void *)chip->slw_base;
	int rc;

	for_each_available_cpu(c) {
		if (c->chip_id != chip->id)
			continue;
	
		/* Clear HRMOR */
		rc =  p8_pore_gen_cpureg_fixed(image, P8_SLW_MODEBUILD_SRAM,
					       P8_SPR_HRMOR, 0,
					       cpu_get_core_index(c),
					       cpu_get_thread_index(c));
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_SLW_REG),
				"SLW: Failed to set HRMOR for CPU %x\n",
				c->pir);
		}

		/* XXX Add HIDs etc... */
	}
}

static void slw_init_chip_p9(struct proc_chip *chip)
{
	struct cpu_thread *c;

	prlog(PR_DEBUG, "SLW: Init chip 0x%x\n", chip->id);

	/* At power ON setup inits for power-mgt */
	for_each_available_core_in_chip(c, chip->id)
		slw_set_overrides_p9(chip, c);


}

static bool  slw_image_check_p9(struct proc_chip *chip)
{

	if (!chip->homer_base) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
				 "SLW: HOMER base not set %x\n",
				 chip->id);
		return false;
	} else
		return true;


}

static bool  slw_image_check_p8(struct proc_chip *chip)
{
	int64_t rc;

	prlog(PR_DEBUG, "SLW: slw_check chip 0x%x\n", chip->id);
	if (!chip->slw_base) {
		prerror("SLW: No image found !\n");
		return false;
	}

	/* Check actual image size */
	rc = sbe_xip_get_scalar((void *)chip->slw_base, "image_size",
				&chip->slw_image_size);
	if (rc != 0) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
			"SLW: Error %lld reading SLW image size\n", rc);
		/* XXX Panic ? */
		chip->slw_base = 0;
		chip->slw_bar_size = 0;
		chip->slw_image_size = 0;
		return false;
	}
	prlog(PR_DEBUG, "SLW: Image size from image: 0x%llx\n",
	      chip->slw_image_size);

	if (chip->slw_image_size > chip->slw_bar_size) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
			"SLW: Built-in image size larger than BAR size !\n");
		/* XXX Panic ? */
		return false;
	}
	return true;

}

static void slw_late_init_p8(struct proc_chip *chip)
{

	prlog(PR_DEBUG, "SLW: late Init chip 0x%x\n", chip->id);

	/* Patch SLW image */
        slw_patch_regs(chip);

}
static void slw_init_chip_p8(struct proc_chip *chip)
{
	struct cpu_thread *c;

	prlog(PR_DEBUG, "SLW: Init chip 0x%x\n", chip->id);
	/* At power ON setup inits for fast-sleep */
	for_each_available_core_in_chip(c, chip->id) {
		idle_prepare_core(chip, c);
	}
}

/* Workarounds while entering fast-sleep */

static void fast_sleep_enter(void)
{
	uint32_t core = pir_to_core_id(this_cpu()->pir);
	uint32_t chip_id = this_cpu()->chip_id;
	struct cpu_thread *primary_thread;
	uint64_t tmp;
	int rc;

	primary_thread = this_cpu()->primary;

	rc = xscom_read(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			&tmp);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_enter XSCOM failed(1):"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}

	primary_thread->save_l2_fir_action1 = tmp;
	primary_thread->in_fast_sleep = true;

	tmp = tmp & ~0x0200000000000000ULL;
	rc = xscom_write(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			 tmp);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_enter XSCOM failed(2):"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}
	rc = xscom_read(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			&tmp);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_enter XSCOM failed(3):"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}

}

/* Workarounds while exiting fast-sleep */

void fast_sleep_exit(void)
{
	uint32_t core = pir_to_core_id(this_cpu()->pir);
	uint32_t chip_id = this_cpu()->chip_id;
	struct cpu_thread *primary_thread;
	int rc;

	primary_thread = this_cpu()->primary;
	primary_thread->in_fast_sleep = false;

	rc = xscom_write(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			primary_thread->save_l2_fir_action1);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_exit XSCOM failed:"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}
}

/*
 * Setup and cleanup method for fast-sleep workarounds
 * state = 1 fast-sleep
 * enter = 1 Enter state
 * exit  = 0 Exit state
 */

static int64_t opal_config_cpu_idle_state(uint64_t state, uint64_t enter)
{
	/* Only fast-sleep for now */
	if (state != 1)
		return OPAL_PARAMETER;	

	switch(enter) {
	case 1:
		fast_sleep_enter();
		break;
	case 0:
		fast_sleep_exit();
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

opal_call(OPAL_CONFIG_CPU_IDLE_STATE, opal_config_cpu_idle_state, 2);

int64_t opal_slw_set_reg(uint64_t cpu_pir, uint64_t sprn, uint64_t val)
{

	struct cpu_thread *c = find_cpu_by_pir(cpu_pir);
	struct proc_chip *chip;
	int rc;

	if (!c) {
		prerror("SLW: Unknown thread with pir %x\n", (u32) cpu_pir);
		return OPAL_PARAMETER;
	}

	chip = get_chip(c->chip_id);
	if (!chip) {
		prerror("SLW: Unknown chip for thread with pir %x\n",
			(u32) cpu_pir);
		return OPAL_PARAMETER;
	}

	/*
	 * Return OPAL SUCCESS if we are in a PEF environment
	 * Self save does not currently work for HID0, hence we self
	 * restore and check against the default value as only LE Radix
	 * hypervisors can currently exist.
	 * Until there is a version that supports self save for HID,
	 * only Little Endian Radix can be supported
	*/
	if (is_uv_present()) {
		if (sprn == P9_STOP_SPR_HID && val != default_hid0_val)
			return OPAL_UNSUPPORTED;
		return OPAL_SUCCESS;
	}
	if (proc_gen == proc_gen_p9) {
		if (!has_deep_states) {
			prlog(PR_INFO, "SLW: Deep states not enabled\n");
			return OPAL_SUCCESS;
		}

		if (wakeup_engine_state != WAKEUP_ENGINE_PRESENT) {
			log_simple_error(&e_info(OPAL_RC_SLW_REG),
					 "SLW: wakeup_engine in bad state=%d chip=%x\n",
					 wakeup_engine_state,chip->id);
			return OPAL_INTERNAL_ERROR;
		}
		rc = p9_stop_save_cpureg((void *)chip->homer_base,
					 sprn, val, cpu_pir);

	} else if (proc_gen == proc_gen_p8) {
		int spr_is_supported = 0;
		void *image;
		int i;

		/* Check of the SPR is supported by libpore */
		for (i = 0; i < SLW_SPR_REGS_SIZE ; i++)  {
			if (sprn == SLW_SPR_REGS[i].value)  {
				spr_is_supported = 1;
				break;
			}
		}
		if (!spr_is_supported) {
			log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Trying to set unsupported spr for CPU %x\n",
				c->pir);
			return OPAL_UNSUPPORTED;
		}
		image = (void *)chip->slw_base;
		rc = p8_pore_gen_cpureg_fixed(image, P8_SLW_MODEBUILD_SRAM,
					      sprn, val,
					      cpu_get_core_index(c),
					      cpu_get_thread_index(c));
	} else {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
		"SLW: proc_gen not supported\n");
		return OPAL_UNSUPPORTED;

	}

	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Failed to set spr %llx for CPU %x, RC=0x%x\n",
			sprn, c->pir, rc);
		return OPAL_INTERNAL_ERROR;
	}
	prlog(PR_DEBUG, "SLW: restore spr:0x%llx on c:0x%x with 0x%llx\n",
	      sprn, c->pir, val);
	return OPAL_SUCCESS;

}

opal_call(OPAL_SLW_SET_REG, opal_slw_set_reg, 3);

int64_t opal_slw_self_save_reg(uint64_t cpu_pir, uint64_t sprn)
{
	struct cpu_thread * c = find_cpu_by_pir(cpu_pir);
	struct proc_chip * chip;
	int rc;
	int index;
	uint32_t save_reg_vector = 0;

	if (!c) {
		prlog(PR_DEBUG, "SLW: Unknown thread with pir %x\n",
		      (u32) cpu_pir);
		return OPAL_PARAMETER;
	}

	chip = get_chip(c->chip_id);
	if (!chip) {
		prlog(PR_DEBUG, "SLW: Unknown chip for thread with pir %x\n",
		      (u32) cpu_pir);
		return OPAL_PARAMETER;
	}
	if (proc_gen != proc_gen_p9 || !has_deep_states) {
		prlog(PR_DEBUG, "SLW: Does not support deep states\n");
		return OPAL_UNSUPPORTED;
	}
	if (wakeup_engine_state != WAKEUP_ENGINE_PRESENT) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: wakeup_engine in bad state=%d chip=%x\n",
			wakeup_engine_state, chip->id);
		return OPAL_INTERNAL_ERROR;
	}
	for (index = 0; index < MAX_SPR_SUPPORTED; ++index) {
		if (sprn == (CpuReg_t) g_sprRegister[index].iv_sprId) {
			save_reg_vector = PPC_BIT32(
				g_sprRegister[index].iv_saveMaskPos);
			break;
		}
	}
	if (save_reg_vector == 0)
		return OPAL_INTERNAL_ERROR;
	/*
	 * In a PEF environment, the values are saved prior to entering the
	 * secure environment, hence this can return a sucess
	 */
	if (is_uv_present())
		return OPAL_SUCCESS;
	rc = p9_stop_save_cpureg_control((void *) chip->homer_base,
						cpu_pir, save_reg_vector);

	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Failed to save vector %x for CPU %x\n",
			save_reg_vector, c->pir);
		return OPAL_INTERNAL_ERROR;
	}
	return OPAL_SUCCESS;
}
opal_call(OPAL_SLW_SELF_SAVE_REG, opal_slw_self_save_reg, 2);

void slw_init(void)
{
	struct proc_chip *chip;
	int i, rc;
	u64 cpmmr_xscom_addr;

	if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS) {
		wakeup_engine_state = WAKEUP_ENGINE_NOT_PRESENT;
		add_cpu_idle_state_properties();
		return;
	}
	if (proc_gen == proc_gen_p8) {
		for_each_chip(chip) {
			slw_init_chip_p8(chip);
			if(slw_image_check_p8(chip))
				wakeup_engine_state = WAKEUP_ENGINE_PRESENT;
			if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT)
				slw_late_init_p8(chip);
		}
		p8_sbe_init_timer();
	} else if (proc_gen == proc_gen_p9) {
		for_each_chip(chip) {
			slw_init_chip_p9(chip);
			if(slw_image_check_p9(chip))
				wakeup_engine_state = WAKEUP_ENGINE_PRESENT;
			if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT)
				slw_late_init_p9(chip);
		}
	}
	/* Setting up CPPMR bits which allow the transition to HV from UV */
	for_each_chip(chip) {
		u8 nr_cores = get_available_nr_cores_in_chip(chip->id);

		cpmmr_xscom_addr = 0x200f0106;
		for (i = 0; i < nr_cores; i++) {
			rc = xscom_write(chip->id, cpmmr_xscom_addr,
					 DEFAULT_CPMMR_VALUE | PPC_BIT(3));
			if (rc) {
				log_simple_error(&e_info(OPAL_RC_SLW_INIT),
						 "SLW: Failed to write to CPMMR\n");
			}
			/* Each core xscom address is offsetted */
			cpmmr_xscom_addr += 0x1000000;
		}
	}
	add_cpu_idle_state_properties();
	if (has_deep_states)
		add_cpu_self_save_properties();
}
