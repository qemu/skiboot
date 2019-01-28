CRYPTO_DIR = $(LIBSTB_DIR)/crypto

SUBDIRS += $(CRYPTO_DIR)

MBEDTLS_CONFIG=

MBEDTLS=$(SRC)/$(LIBSTB_DIR)/crypto/mbedtls/library/libmbedcrypto.a
MBEDTLS+= $(SRC)/$(LIBSTB_DIR)/crypto/mbedtls/library/libmbedx509.a

MBEDTLS_CFLAGS = $(CFLAGS)
MBEDTLS_CFLAGS += -I$(SRC)/$(LIBSTB_DIR)
MBEDTLS_CFLAGS += -I$(SRC)/$(LIBSTB_DIR)/crypto -DMBEDTLS_CONFIG_FILE='<mbedtls-config.h>'
MBEDTLS_CFLAGS += -Wno-suggest-attribute=const
MBEDTLS_CFLAGS += -I$(SRC)/$(LIBSTB_DIR)/crypto/mbedtls/include
MBEDTLS_CFLAGS += $(CPPFLAGS)

$(MBEDTLS):
	@$(MAKE) -C $(SRC)/$(LIBSTB_DIR)/crypto/mbedtls/library/ CFLAGS="$(MBEDTLS_CFLAGS)" CC=$(CC) AR=$(AR) libmbedcrypto.a libmbedx509.a

include $(CRYPTO_DIR)/pkcs7/Makefile.inc

CRYPTO = $(CRYPTO_DIR)/built-in.a

$(CRYPTO): $(MBEDTLS) $(PKCS7)
