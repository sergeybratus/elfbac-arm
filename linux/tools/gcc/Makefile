#CC := gcc
#PLUGIN_SOURCE_FILES := pax_plugin.c
#PLUGIN_OBJECT_FILES := $(patsubst %.c,%.o,$(PLUGIN_SOURCE_FILES))
GCCPLUGINS_DIR := $(shell $(CC) -print-file-name=plugin)
#CFLAGS += -I$(GCCPLUGINS_DIR)/include -fPIC -O2 -Wall -W -std=gnu99

ifeq ($(PLUGINCC),$(HOSTCC))
HOSTLIBS := hostlibs
HOST_EXTRACFLAGS += -I$(GCCPLUGINS_DIR)/include -I$(src) -std=gnu99 -ggdb
export HOST_EXTRACFLAGS
else
HOSTLIBS := hostcxxlibs
HOST_EXTRACXXFLAGS += -I$(GCCPLUGINS_DIR)/include -I$(src) -std=gnu++98 -fno-rtti -fno-exceptions -fasynchronous-unwind-tables -ggdb -Wno-unused-parameter -Wno-narrowing -Wno-unused-variable
export HOST_EXTRACXXFLAGS
endif

export GCCPLUGINS_DIR HOSTLIBS

$(HOSTLIBS)-$(CONFIG_PAX_CONSTIFY_PLUGIN) := constify_plugin.so

always := $($(HOSTLIBS)-y)

constify_plugin-objs := constify_plugin.o

