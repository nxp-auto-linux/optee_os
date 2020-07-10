PLATFORM_FLAVOR ?= s32g274aevb

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_ARM64_core,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

# Enabling the Pager requires access to SRAM
$(call force,CFG_WITH_PAGER,n)

# CPU-related configurations
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
$(call force,CFG_NUM_THREADS,4)

# GIC is configured in ATF. OP-TEE only needs
# to map this configurations into its memory
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_GIC,y)

# Except for CPU_ON handler, the rest of the power
# management operations handlers are only stubs
$(call force,CFG_PM_STUBS,y)

# Configuring secure time source
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

supported-ta-targets = ta_arm64

# Security-related configurations
CFG_CORE_ASLR ?= y
CFG_TA_ASLR ?= y
CFG_WITH_STACK_CANARIES ?= y

# Establish UART connectivity
CFG_S32G_UART ?= y

CFG_DRAM_END ?= 0xffffffff
CFG_SM_SIZE ?= 	0x00200000 # 2Mb
CFG_TEE_SIZE ?= 0x01600000 # 22Mb

# Place the TZ Mem Area at the end of DRAM, just before the Secure Monitor Mem Area
CFG_TZDRAM_START ?=	($(CFG_DRAM_END) - $(CFG_SM_SIZE) - $(CFG_TEE_SIZE) + 1)
CFG_TZDRAM_SIZE ?= 	0x01400000 # 20Mb

# Shared non-secure memory at the end of the TEE Reserved Space Zone
CFG_SHMEM_START ?=	($(CFG_TZDRAM_START) + $(CFG_TZDRAM_SIZE))
CFG_SHMEM_SIZE ?= 	0x00200000 # 2Mb
CFG_CORE_RESERVED_SHM=y