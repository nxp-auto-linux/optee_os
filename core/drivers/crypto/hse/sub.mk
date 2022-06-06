incdirs-y += include

incdirs_ext-y += $(HSE_FWDIR)/interface
incdirs_ext-y += $(HSE_FWDIR)/interface/inc_common
incdirs_ext-y += $(HSE_FWDIR)/interface/inc_services
incdirs_ext-y += $(HSE_FWDIR)/interface/config
ifeq ($(shell [ -d $(HSE_FWDIR)/interface/inc_custom ]; echo $$?), 0)
incdirs_ext-y += $(HSE_FWDIR)/interface/inc_custom
endif

srcs-y += hse_dt.c
srcs-y += hse_mu.c
srcs-y += hse_core.c
srcs-y += hse_util.c
srcs-y += hse_cipher.c
srcs-y += hse_huk.c
srcs-y += hse_rng.c
