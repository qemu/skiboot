.. SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

=================
OPAL UV ABI (RFC)
=================

.. contents::
    :depth: 3

.. sectnum::
    :depth: 3

This document describes the function calling interface between OPAL
and the Ultravisor.

Protected Execution Facility
############################

Protected Execution Facility (PEF) is an architectural change for
POWER 9 that enables Secure Virtual Machines (SVMs). When enabled,
PEF adds a new higher privileged mode, called Ultravisor mode, to
POWER architecture. Along with the new mode there is new firmware
called the Protected Execution Ultravisor (or Ultravisor for short).
Ultravisor mode is the highest privileged mode in POWER architecture.

+------------------+
| Privilege States |
+==================+
|  Problem         |
+------------------+
|  Supervisor      |
+------------------+
|  Hypervisor      |
+------------------+
|  Ultravisor      |
+------------------+

PEF protects SVMs from the hypervisor, privileged users, and other
VMs in the system. SVMs are protected while at rest and can only be
executed by an authorized machine. All virtual machines utilize
hypervisor services. The Ultravisor filters calls between the SVMs
and the hypervisor to assure that information does not accidentally
leak. All hypercalls except H_RANDOM are reflected to the hypervisor.
H_RANDOM is not reflected to prevent the hypervisor from influencing
random values in the SVM.

To support this there is a refactoring of the ownership of resources
in the CPU. Some of the resources which were previously hypervisor
privileged are now ultravisor privileged.

Hardware
========

The hardware changes include the following:

* There is a new bit in the MSR that determines whether the current
  process is running in secure mode, MSR(S) bit 41. MSR(S)=1, process
  is in secure mode, MSR(s)=0 process is in normal mode.

* The MSR(S) bit can only be set by the Ultravisor.

* HRFID cannot be used to set the MSR(S) bit. If the hypervisor needs
  to return to a SVM it must use an ultracall. It can determine if
  the VM it is returning to is secure.

* There is a new Ultravisor privileged register, SMFCTRL, which has an
  enable/disable bit SMFCTRL(E).

* The privilege of a process is now determined by three MSR bits,
  MSR(S, HV, PR). In each of the tables below the modes are listed
  from least privilege to highest privilege. The higher privilege
  modes can access all the resources of the lower privilege modes.

**Secure Mode MSR Settings**

+---+---+---+---------------+
| S | HV| PR|Privilege      |
+===+===+===+===============+
| 1 | 0 | 1 | Problem       |
+---+---+---+---------------+
| 1 | 0 | 0 | Privileged(OS)|
+---+---+---+---------------+
| 1 | 1 | 0 | Ultravisor    |
+---+---+---+---------------+
| 1 | 1 | 1 | Reserved      |
+---+---+---+---------------+

**Normal Mode MSR Settings**

+---+---+---+---------------+
| S | HV| PR|Privilege      |
+===+===+===+===============+
| 0 | 0 | 1 | Problem       |
+---+---+---+---------------+
| 0 | 0 | 0 | Privileged(OS)|
+---+---+---+---------------+
| 0 | 1 | 0 | Hypervisor    |
+---+---+---+---------------+
| 0 | 1 | 1 | Problem (HV)  |
+---+---+---+---------------+

* Memory is partitioned into secure and normal memory. Only processes
  that are running in secure mode can access secure memory.

* The hardware does not allow anything that is not running secure to
  access secure memory. This means that the Hypervisor cannot access
  the memory of the SVM without using an ultracall (asking the
  Ultravisor). The Ultravisor will only allow the hypervisor to see
  the SVM memory encrypted.

* I/O systems are not allowed to directly address secure memory. This
  limits the SVMs to virtual I/O only.

* The architecture allows the SVM to share pages of memory with the
  hypervisor that are not protected with encryption. However, this
  sharing must be initiated by the SVM.

* When a process is running in secure mode all hypercalls
  (syscall lev=1) are reflected to the Ultravisor.

* When a process is in secure mode all interrupts go to the
  Ultravisor.

* The following resources have become Ultravisor privileged and
  require an Ultravisor interface to manipulate:

        * Processor configurations registers (SCOMs).

        * Stop state information.

        * The debug registers CIABR, DAWR, and DAWRX become Ultravisor
          resources when SMFCTRL(D) is set. If SMFCTRL(D) is not set they do
          not work in secure mode. When set, reading and writing requires
          an Ultravisor call, otherwise that will cause a Hypervisor Emulation
          Assistance interrupt.

        * PTCR and partition table entries (partition table is in secure
          memory). An attempt to write to PTCR will cause a Hypervisor
          Emulation Assitance interrupt.

        * LDBAR (LD Base Address Register) and IMC (In-Memory Collection)
          non-architected registers. An attempt to write to them will cause a
          Hypervisor Emulation Assistance interrupt.

        * Paging for an SVM, sharing of memory with Hypervisor for an SVM.
          (Including Virtual Processor Area (VPA) and virtual I/O).

Software/Microcode
==================

The software changes include:

* When the UV_ESM ultracall is made the Ultravisor copies the VM into
  secure memory, decrypts the verification information, and checks the
  integrity of the SVM. If the integrity check passes the Ultravisor
  passes control in secure mode.

The Ultravisor offers new services to the hypervisor and SVMs. These
are accessed through ultracalls.

Terminology
===========

* Hypercalls: special system calls used to request services from
  Hypervisor.

* Normal memory: Memory that is accessible to Hypervisor.

* Normal page: Page backed by normal memory and available to
  Hypervisor.

* Secure memory: Memory that is accessible only to Ultravisor and
  SVMs.

* Secure page: Page backed by secure memory and only available to
  Ultravisor and SVM.

* SVM: Secure Virtual Machine.

* Ultracalls: special system calls used to request services from
  Ultravisor.

Ultravisor Initialization
#########################

Secure Memory
=============

Skiboot parses secure memory from the HDAT tables and creates the secure-memory
and ibm,ultravisor device tree nodes.  secure-memory is similar to a memory@
node except the device_type is "secure_memory". For example:

.. code-block:: dts

        secure-memory@100fe00000000 {
                device_type = "secure_memory";
                compatible = "ibm,secure_memory";
                ibm,chip-id = <0>;
                reg = < 0x100fe 0x0 0x2 0x0>;
        }

Regions of secure memory will be reserved by hostboot such as OCC, HOMER, and
SBE.  Skiboot will use the existing reserve infrastructure to reserve them.
For example:

.. code-block::

        ibm,HCODE@100fffcaf0000
        ibm,OCC@100fffcdd0000
        ibm,RINGOVD@100fffcae0000
        ibm,WOFDATA@100fffcb90000
        ibm,arch-reg-data@100fffd700000
        ibm,hbrt-code-image@100fffcec0000
        ibm,hbrt-data@100fffd420000
        ibm,homer-image@100fffd800000
        ibm,homer-image@100fffdc00000
        ibm,occ-common-area@100ffff800000
        ibm,sbe-comm@100fffce90000
        ibm,sbe-comm@100fffceb0000
        ibm,sbe-ffdc@100fffce80000
        ibm,sbe-ffdc@100fffcea0000
        ibm,secure-crypt-algo-code@100fffce70000
        ibm,uvbwlist@100fffcad0000

For Mambo, ultra.tcl creates the secure-memory device tree node and the
ibm,ultravisor device tree node in external/mambo/skiboot.tcl.  Secure memory
is currently defined as the bottom half of the total the size of memory.  Mambo
has no protection on secure memory, so a watchpoint could be used to ensure
Skiboot does not touch secure memory.

For BML, the BML script parses secure memory from the Cronus config file and
creates the secure-memory and ibm,ultravisor device tree nodes.

In all cases, the console log should indicate secure memory has been found and
added to the device tree.  For example:

.. code-block::

        [   68.235326307,5] UV: Secure memory range added to DT [0x0001000e00000000..0x001001000000000]

Loading The Ultravisor
======================

Skiboot uses secure and trusted boot to load and verify the compressed UV image
from the PNOR into regular memory.  It unpacks the UV into regular memory in
the function ``init_uv``.

``init_uv`` finds the UV node in the device tree via the "ibm,ultravisor"
compatible property.  For example:

.. code-block:: dts

        ibm,ultravisor {
                compatible = "ibm,ultravisor";
                #address-cells = <0x02>;
                #size-cells = <0x02>;

                firmware@200000000 {
                        compatible = "ibm,uv-firmware";
                        reg = <0x02 0x00 0xf677f>;
                        memcons = <0x00 0x3022d030>;
                        sys-fdt = <0x00 0x30509068>;
                        uv-fdt = <0x02 0x200000>;
                };
        };

Skiboot creates ibm,ultravisor and the reg property in hdata/spira.c.

Mambo and BML use scripts to put the ultra image directly in regular memory and
a reserve is created named ibm,uv-firmware.

Starting The Ultravisor
=======================

Skiboot starts the UV in ``main_cpu_entry`` before the kernel is loaded and booted.
Skiboot creates a job on all threads and sends them to ``enter_uv`` in asm/head.S.
This function's prototype is:

.. code-block:: c

        /*
        * @brief Enter UV.
        *
        * @param Offset into ultravisor image for threads to jump to
        * @param Flattened system device tree
        *
        * @return 0 on success, else a negative error code on failure.
        */
        u64 enter_uv(uint64_t entry, void *fdt)

The sys_fdt allows passing information to the UV, such as the location of the
memory console, and is easy to extend.

In the future, a ``uv_fdt`` could be constructed in secure memory.  For
example, a wrapping key could be passed to the ultravisor via a device tree
node in secure memory:

.. code-block:: dts

        ibm,uv-fdt {
                 compatible = "ibm,uv-fdt";
                 wrapping-key-password = "gUMShz6l2x4O9IeHrvBSuBR0FYANZTYK";
        };

The UV parses ``sys_fdt``, creates internal structures, and threads return in
hypervisor privilege moded.

If successful, skiboot sets a variable named ``uv_present`` to true.  Skiboot
uses this variable to dermine if the UV is initialized and ready to perform
ucalls.

Ultravisor Failed Start Recovery
================================

If the ultravisor fails to start it will return a error code to init_uv.
init_uv will print error messages to the skiboot log and attempt to free
structures associated with the ultravisor.

Skiboot will continue to be in ultravisor privilege mode, and will need to
perform a recovery action.

[**TODO**: Need to describe the steps for Ultravisor load failure recovery action.]

Ultracalls
##########

Ultravisor calls ABI
====================

This section describes Ultravisor calls (ultracalls) needed by skiboot.  The
ultracalls allow skiboot to request services from the Ultravisor such as
initializing a chip unit via XSCOM.

Ultracalls are modeled after the hcall interface.  The specific service needed
from an ultracall is specified in register R3.  The status is returned in R3.
The call skiboot currently uses supports up to 6 arguments and 4 return
arguments.

Each ultracall returns specific error codes, applicable in the context
of the ultracall. However, like with the PowerPC Architecture Platform
Reference (PAPR), if no specific error code is defined for a
particular situation, then the ultracall will fallback to an erroneous
parameter-position based code. i.e U_PARAMETER, U_P2, U_P3 etc
depending on the ultracall parameter that may have caused the error.

For now this only covers ultracalls currently implemented and being used by
skiboot but others can be added here when it makes sense.

The full specification for all ultracalls will eventually be made available in
the public/OpenPower version of the PAPR specification.

Ultracalls used by Skiboot
==========================

UV_READ_SCOM
------------

Perform an XSCOM read and put the value in a buffer.

Syntax
~~~~~~

.. code-block:: c

        long ucall(unsigned long UV_READ_SCOM,
                unsigned long *retbuf,
                u64 partid,
                u64 pcb_addr)

Return values
~~~~~~~~~~~~~

* U_SUCCESS     on success.
* U_PERMISSION  if called from VM context.
* U_PARAMETER   if invalid partiton or address.
* U_BUSY        if unit is busy, need to retry.
* U_XSCOM_CHIPLET_OFF   if cpu is asleep.
* U_XSCOM_PARTIAL_GOOD  if partial good.
* U_XSCOM_ADDR_ERROR    if address error.
* U_XSCOM_CLOCK_ERROR   if clock error.
* U_XSCOM_PARITY_ERROR  if parity error.
* U_XSCOM_TIMEOUT       if timeout.
* U_XSCOM_CTR_OFFLINED  if centaur offline.

UV_WRITE_SCOM
-------------

Perform an XSCOM write.

Syntax
~~~~~~

.. code-block:: c

        long ucall(unsigned long UV_WRITE_SCOM,
                u64 partid,
                u64 pcb_addr,
                u64 val)

Return values
~~~~~~~~~~~~~

One of the following values:

* U_SUCCESS     on success.
* U_PERMISSION  if called from VM context.
* U_PARAMETER   if invalid partiton.
* U_BUSY        if unit is busy, need to retry.
* U_XSCOM_CHIPLET_OFF   if cpu is asleep.
* U_XSCOM_PARTIAL_GOOD  if partial good.
* U_XSCOM_ADDR_ERROR    if address error.
* U_XSCOM_CLOCK_ERROR   if clock error.
* U_XSCOM_PARITY_ERROR  if parity error.
* U_XSCOM_TIMEOUT       if timeout.
* U_XSCOM_CTR_OFFLINED  if centaur offline.

References
##########

.. [1] `Supporting Protected Computing on IBM Power Architecture <https://developer.ibm.com/articles/l-support-protected-computing/>`_
