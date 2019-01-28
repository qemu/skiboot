# -*-Makefile-*-

PKCS7_DIR = libstb/crypto/pkcs7

SUBDIRS += $(PKCS7_DIR)

PKCS7_SRCS = pkcs7.c verify_sig.c
PKCS7_OBJS = $(PKCS7_SRCS:%.c=%.o)
PKCS7 = $(PKCS7_DIR)/built-in.a

$(PKCS7): $(PKCS7_OBJS:%=$(PKCS7_DIR)/%)
