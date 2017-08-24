# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=string_context

# Include the PANDA Makefile rules
include ../extra_plugins_panda.mak

# If you need custom CFLAGS or LIBS, set them up here
CFLAGS+=-std=c++11
#LIBS+=-lcapstone
#LIBS+=-lcapstone

# Object files comprising the plugin.
PLUGIN_OBJFILES=$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

# Plugin dynamic library. Please stick with the panda_ naming convention.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)
	$(call quiet-command,$(CXX) $(QEMU_CFLAGS) -g -shared -o $@ $^ $(LDFLAGS) $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_OBJ_DIR) $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so
