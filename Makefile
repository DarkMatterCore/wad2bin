TOPDIR	?=	$(CURDIR)
ifeq ($(strip $(wildcard $(TOPDIR)/config.mk)),)
# config.mk does not exist.
# read template and safe as config.mk
$(info Creating config.mk file)

$(file > config.mk,$(file < config.mk.template))
endif

include $(TOPDIR)/config.mk

PROJECT_NAME	:=	wad2bin
PROJECT_AUTHOR	:=	DarkMatterCore
PROJECT_VERSION	:=	0.8

ifeq ($(strip $(findstring Windows,$(shell uname -s))),)
TARGET			:=	$(PROJECT_NAME)
else
TARGET			:=	$(PROJECT_NAME)$(EXEEXT)
endif

# allow static build
BUILD_STATIC ?= 0

# -Wno-implicit-fallthrough is used to suppress ConvertUTF.c warnings.
# -Wno-missing-braces is used to suppress "suggest braces around initialization of subobject" warnings under certain compilers.

CFLAGS			:=	-std=gnu11 -fPIC -O2 -Wall -Wextra -Wpedantic -Wno-implicit-fallthrough -Wno-missing-braces -static-libgcc -static-libstdc++ $(INCLUDE)
LIBS			:=	-lmbedtls -lmbedx509 -lmbedcrypto -lninty-233

ifeq ($(BUILD_STATIC),1)
CFLAGS			+= 	-static -s
LIBS			+= 	-static -s
endif

CFLAGS			+=	-D_BSD_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS			+=	-DPROJECT_NAME=\"${PROJECT_NAME}\" -DPROJECT_AUTHOR=\"${PROJECT_AUTHOR}\" -DPROJECT_VERSION=\"${PROJECT_VERSION}\"

BUILD			:=	build
SOURCES			:=	source
INCLUDES		:=	mbedtls/include ninty-233/bin/include
LIBDIRS			:=	mbedtls/library ninty-233/bin/linux

ifneq ($(BUILD),$(notdir $(CURDIR)))
export OUTPUT	:=	$(CURDIR)/$(TARGET)
export TOPDIR	:=	$(CURDIR)
export DEPSDIR	:=	$(CURDIR)/$(BUILD)

export CFILES	:=	$(foreach dir,$(SOURCES),$(addprefix $(CURDIR)/$(dir)/,$(notdir $(wildcard $(CURDIR)/$(dir)/*.c))))
export OFILES	:=	$(subst .c,.o,$(notdir $(CFILES)))

export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir))

export LIBPATHS	:=	$(foreach dir,$(LIBDIRS),-L$(CURDIR)/$(dir))

.PHONY:	$(BUILD) clean clean_full all

all:	$(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

clean:
	@echo clean ...
	@rm -fr $(BUILD) $(TARGET)

clean_full:
	@echo clean ...
	@rm -fr $(BUILD) $(TARGET)
	$(MAKE) -C mbedtls clean
	$(MAKE) -C ninty-233/build/linux clean
else
.PHONY:	all libs src

all:	$(OUTPUT)

$(OUTPUT):	libs src
	@echo linking $(notdir $@)
	$(CC) $(OFILES) $(LIBPATHS) $(LIBS) -o $@

libs:
	@$(MAKE) CC='$(CC)' -C $(TOPDIR)/mbedtls lib
	@$(MAKE) CC='$(CC)' -C $(TOPDIR)/ninty-233/build/linux static

src:	$(OFILES)

define compile_rule
$(subst .c,.o,$(notdir $(1))):	$(1)
	$(CC) $(CFLAGS) -c $$^ -o $$@
endef
$(foreach csrc,$(CFILES),$(eval $(call compile_rule,$(csrc))))
endif
