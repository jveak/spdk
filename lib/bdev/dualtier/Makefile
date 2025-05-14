SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 1
SO_MINOR := 0

CFLAGS += $(ENV_CFLAGS)
LIBNAME = bdev_dualtier

C_SRCS = bdev_dualtier.c bdev_dualtier_rpc.c

SPDK_MAP_FILE = $(SPDK_ROOT_DIR)/mk/spdk_blank.map

include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk 