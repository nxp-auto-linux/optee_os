PLATFORM_FLAVOR ?= s32g2

s32-common-flavorlist =  \
	s32g2 \
	s32r

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_ARM64_core,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,40)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

# Enabling the Pager requires access to SRAM
$(call force,CFG_WITH_PAGER,n)

# CPU-related configurations
ifneq (,$(filter $(PLATFORM_FLAVOR),$(s32-common-flavorlist)))
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
$(call force,CFG_NUM_THREADS,4)
else ifeq ($(PLATFORM_FLAVOR), s32g3)
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
$(call force,CFG_NUM_THREADS,8)
else
$(error Invalid PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif

# GIC is configured in ATF. OP-TEE only needs
# to map this configurations into its memory
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_GIC,y)

# Configuring secure time source
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

# Inject OP-TEE nodes in the non-secure U-boot DTB
$(call force,CFG_DT,y)

supported-ta-targets = ta_arm64

# Security-related configurations
CFG_CORE_ASLR ?= y
CFG_TA_ASLR ?= y
CFG_WITH_STACK_CANARIES ?= y

# Establish UART connectivity
CFG_S32_UART ?= y

CFG_DRAM_END ?= 	0xffffffff
CFG_SM_SIZE ?= 		0x00200000 # 2MB
CFG_UBOOT_SIZE ?= 	0x00600000 # 6MB
CFG_TEE_SIZE ?= 	0x01600000 # 22MB

# Place the TZ Mem Area at the end of DRAM, just before the Secure Monitor Mem Area
# and U-Boot (BL33) Area
CFG_TZDRAM_START ?=	($(CFG_DRAM_END) - $(CFG_SM_SIZE) - $(CFG_UBOOT_SIZE) - \
			$(CFG_TEE_SIZE) + 1)
CFG_TZDRAM_SIZE ?= 	0x01400000 # 20MB

# Shared non-secure memory at the end of the TEE Reserved Space Zone
CFG_SHMEM_START ?=	($(CFG_TZDRAM_START) + $(CFG_TZDRAM_SIZE))
CFG_SHMEM_SIZE ?= 	0x00200000 # 2MB
CFG_CORE_RESERVED_SHM ?= y

# HSE Crypto Driver disabled by default
CFG_CRYPTO_DRIVER ?= n
CFG_CRYPTO_DRIVER_DEBUG ?= 0

ifeq ($(CFG_CRYPTO_DRIVER), y)

# Use HSE_FWDIR to specify the path to HSE FW Package
# If not set, HSE_FWDIR takes a default value based on PLATFORM_FLAVOR
ifeq ($(HSE_FWDIR),)

ifeq ($(PLATFORM_FLAVOR), s32g3)
HSE_FWDIR ?= $(HOME)/HSE_FW_S32G3_0_0_21_0
else ifeq ($(PLATFORM_FLAVOR), s32g2)
HSE_FWDIR ?= $(HOME)/HSE_FW_S32G2_0_1_0_5
else ifeq ($(PLATFORM_FLAVOR), s32r)
HSE_FWDIR ?= $(HOME)/HSE_FW_S32R45_0_1_0_1
else
$(error Default path to HSE Firmware Package not defined for PLATFORM_FLAVOR=$(PLATFORM_FLAVOR))
endif
endif

$(call force,CFG_NXP_HSE,y)

CFG_HSE_HMAC_KEY_GROUP_ID ?= 1
CFG_HSE_HMAC_KEY_GROUP_SIZE ?= 6

CFG_HSE_AES_KEY_GROUP_ID ?= 2
CFG_HSE_AES_KEY_GROUP_SIZE ?= 7

CFG_HSE_SHARED_SECRET_KEY_ID ?= 3
CFG_HSE_SHARED_SECRET_GROUP_SIZE ?= 1

CFG_CRYPTO_DRV_CIPHER=y

$(call force,CFG_WITH_SOFTWARE_PRNG,n)

CFG_HSE_KP_PTA ?= y

endif
