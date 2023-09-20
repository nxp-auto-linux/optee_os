ifeq ($(CFG_NXP_HSE), y)

# Enable the crypto driver
$(call force,CFG_CRYPTO_DRIVER,y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0

ifeq ($(CFG_NXP_HSE_FWDIR),)
$(error Path to HSE Firmware Package not set. Please use the \
HSE Firmware Package corresponding to PLATFORM_FLAVOR=$(PLATFORM_FLAVOR))
endif

# Determine if the HSE Firmware Version is Premium or Standard
HSE_FWTYPE_STR=$(shell grep -r '\#define HSE_FWTYPE' $(HSE_FWDIR)/interface/config/hse_target.h \
		| sed 's/.*\(PREMIUM\|STANDARD\).*/\1/')
ifeq ($(HSE_FWTYPE_STR), PREMIUM)
$(call force,CFG_HSE_PREMIUM_FW,1)
else
$(call force,CFG_HSE_PREMIUM_FW,0)
endif

hse-one-enabled = $(call cfg-one-enabled, \
                        $(foreach v,$(1), CFG_NXP_HSE_$(v)_DRV))

# HSE Crypto Drivers

# Enable HSE Cipher Driver
CFG_NXP_HSE_CIPHER_DRV ?= y
ifeq ($(CFG_NXP_HSE_CIPHER_DRV),y)
$(call force,CFG_CRYPTO_DRV_CIPHER,y)
endif

# Enable HSE Hash Driver
CFG_NXP_HSE_HASH_DRV ?= y
ifeq ($(CFG_NXP_HSE_HASH_DRV),y)
$(call force,CFG_CRYPTO_DRV_HASH,y)
endif

# Enable HSE Authenc Driver
CFG_NXP_HSE_AUTHENC_DRV ?= y
ifeq ($(CFG_NXP_HSE_AUTHENC_DRV),y)
$(call force,CFG_CRYPTO_DRV_AUTHENC,y)
endif

# Enable HSE MAC Driver
CFG_NXP_HSE_MAC_DRV ?= y
ifeq ($(CFG_NXP_HSE_MAC_DRV),y)
$(call force,CFG_CRYPTO_DRV_MAC,y)
endif

# HSE ECC Driver is disabled by default, to use it set
# CFG_NXP_HSE_ECC_DRV to y.
CFG_NXP_HSE_ECC_DRV ?= n
ifeq ($(CFG_NXP_HSE_ECC_DRV),y)
$(call force,CFG_CRYPTO_DRV_ECC,y)
endif

# Enable HSE RSA Driver
CFG_NXP_HSE_RSA_DRV ?= y
ifeq ($(CFG_NXP_HSE_RSA_DRV),y)
$(call force,CFG_CRYPTO_DRV_RSA,y)

# HSE is using only standard PKCS #1 encoding with ASN.1
$(call force,CFG_CRYPTO_RSASSA_NA1,n)
endif

ifeq ($(call hse-one-enabled,RSA ECC),y)
$(call force,CFG_CRYPTO_DRV_ACIPHER,y)
endif

# Other features provided by HSE

# Enable HSE True Random Generation Driver
CFG_NXP_HSE_RNG_DRV ?= y
ifeq ($(CFG_NXP_HSE_RNG_DRV),y)
CFG_WITH_SOFTWARE_PRNG = n
endif

# Enable Hardware Unique Key retrieval from HSE
# This key is derived from HSE's hardware root of trust
CFG_NXP_HSE_HUK_DRV ?= y

# Enable the Key Provisioning Pseudo-Trusted Application
CFG_HSE_KP_PTA ?= y

$(call force,HSE_NVM_CATALOG,1)
$(call force,HSE_RAM_CATALOG,2)

# Define a keygroup for a certain key type (e.g AES, HMAC etc.)
# A keygroup has 3 attributes: Catalog (NVM or RAM) ID and
# Size (number of slots in the group)
# These keygroups are a reflection of the keygroups of HSE's Key Catalog which is
# currently defined in pkcs11-hse repository: examples/hse-secboot/keys-config.h
# Therefore, the current values and names must be kept in sync with pkcs11-hse's
#
# This will generate three config variables for Catalog, ID and Size in this particular order:
# CFG_NXP_HSE_*_KEYGROUP_CTLG
# CFG_NXP_HSE_*_KEYGROUP_ID
# CFG_NXP_HSE_*_KEYGROUP_SIZE
#
# Example: Define an AES keygroup in the RAM Catalog with ID 2 and 7 slots
#     $(eval $(call hse-keygroup-define, $(HSE_RAM_CATALOG) AES, 2, 7))
define hse-keygroup-define
_type := $(strip $(1))
_catalog := $(strip $(2))
_id := $(strip $(3))
_size := $(strip $(4))
CFG_NXP_HSE_$$(_type)_KEYGROUP_CTLG := $$(_catalog)
CFG_NXP_HSE_$$(_type)_KEYGROUP_ID := $$(_id)
CFG_NXP_HSE_$$(_type)_KEYGROUP_SIZE := $$(_size)
endef

# Define the keygorups. RAM Catalog keygroups should be generally used because the crypto
# drivers do not need to use persistent keys. RSA/ECC keygroups can only reside in the
# NVM catalog (HSE Firmware limitation)

$(eval $(call hse-keygroup-define, HMAC, $(HSE_RAM_CATALOG), 4, 3))
$(eval $(call hse-keygroup-define, AES, $(HSE_RAM_CATALOG), 2, 7))
$(eval $(call hse-keygroup-define, SHARED_SECRET, $(HSE_RAM_CATALOG), 3, 1))
$(eval $(call hse-keygroup-define, ECCPAIR, $(HSE_NVM_CATALOG), 10, 1))
$(eval $(call hse-keygroup-define, ECCPUB, $(HSE_NVM_CATALOG), 11, 1))
$(eval $(call hse-keygroup-define, RSAPAIR, $(HSE_NVM_CATALOG), 12, 2))
$(eval $(call hse-keygroup-define, RSAPUB, $(HSE_NVM_CATALOG), 13, 2))

endif # CFG_NXP_HSE