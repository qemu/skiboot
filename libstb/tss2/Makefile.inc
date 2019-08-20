# -*-Makefile-*-

TSS2_DIR = libstb/tss2

SUBDIRS += $(TSS2_DIR)

CPPFLAGS += -I$(SRC)/$(TSS2_DIR)

TSS2_SRCS = tss.c tss20.c tssauth.c tssauth20.c tssccattributes.c
TSS2_SRCS += tsscryptoh.c tsscryptombed.c tsscryptouv.c tssdevuv.c
TSS2_SRCS += tssmarshal.c tssprint.c tssprintcmd.c tssproperties.c
TSS2_SRCS += tssresponsecode.c tsstransmit.c tssutils.c tssntc.c
TSS2_SRCS += tssuv.c Commands.c CommandAttributeData.c Unmarshal.c
TSS2_SRCS += tssdevskiboot.c tssskiboot.c tpm_nv.c

TSS2_OBJS = $(TSS2_SRCS:%.c=%.o)

CFLAGS_$(TSS2_DIR)/ = -DTPM_POSIX -DTPM_TPM20 -DTPM_NOSOCKET -DTPM_NODEV
CFLAGS_$(TSS2_DIR)/ += -DTPM_TSS_NOECC -DTPM_TSS_NORSA -D__SKIBOOT__
CFLAGS_$(TSS2_DIR)/ += -DTPM_TSS_NOFILE -DTPM_TSS_NOENV -DTPM_TSS_NOSCAN
CFLAGS_$(TSS2_DIR)/ += -DALG_SHA1=NO -Wstack-usage=4096

CFLAGS_SKIP_$(TSS2_DIR)/ = -Wsuggest-attribute=const

TSS2 = $(TSS2_DIR)/built-in.a

$(TSS2): $(TSS2_OBJS:%=$(TSS2_DIR)/%)
