incdirs-y += include

incdirs_ext-y += $(CFG_NXP_HSE_FWDIR)/interface
incdirs_ext-y += $(CFG_NXP_HSE_FWDIR)/interface/inc_common
incdirs_ext-y += $(CFG_NXP_HSE_FWDIR)/interface/inc_services
incdirs_ext-y += $(CFG_NXP_HSE_FWDIR)/interface/config
ifeq ($(shell [ -d $(CFG_NXP_HSE_FWDIR)/interface/inc_custom ]; echo $$?), 0)
incdirs_ext-y += $(CFG_NXP_HSE_FWDIR)/interface/inc_custom
endif

srcs-y += hse_dt.c
srcs-y += hse_mu.c
srcs-y += hse_core.c
srcs-y += hse_util.c
srcs-$(CFG_NXP_HSE_AUTHENC_DRV) += hse_auth.c
srcs-$(CFG_NXP_HSE_CIPHER_DRV) += hse_cipher.c
srcs-$(CFG_NXP_HSE_HASH_DRV) += hse_hash.c
srcs-$(CFG_NXP_HSE_HUK_DRV) += hse_huk.c
srcs-$(CFG_NXP_HSE_RNG_DRV) += hse_rng.c
srcs-$(CFG_HSE_KP_PTA) += hse_kp.c
srcs-$(CFG_NXP_HSE_ECC_DRV) += hse_ecc.c
srcs-$(CFG_NXP_HSE_RSA_DRV) += hse_rsa.c
srcs-$(CFG_NXP_HSE_MAC_DRV) += hse_mac.c
