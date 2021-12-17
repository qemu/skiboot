SUBDIRS += $(PLATDIR)/astbmc

ASTBMC_OBJS = pnor.o common.o slots.o \
	      witherspoon.o romulus.o p9dsu.o \
	      nicole.o mowgli.o \
	      talos.o blackbird.o \
	      rainier.o

ifeq ($(CONFIG_NPU),1)
ASTBMC_OBJS += zaius.o mihawk.o swift.o
endif

ifeq ($(CONFIG_P8),1)
ASTBMC_OBJS += palmetto.o habanero.o firestone.o \
	      p8dtu.o p8dnu.o \
	      barreleye.o \
	      vesnin.o
ifeq ($(CONFIG_NPU),1)
ASTBMC_OBJS += garrison.o
endif
endif

ASTBMC = $(PLATDIR)/astbmc/built-in.a
$(ASTBMC): $(ASTBMC_OBJS:%=$(PLATDIR)/astbmc/%)
