ifneq ($(LINUXINCLUDE),)
# kbuild part of makefile
obj-m += drivers/scsi/
LINUXINCLUDE := -I$M/include $(LINUXINCLUDE)

else

# normal makefile
REL ?= $(shell uname -r)
KDIR ?= /usr/src/kernels/$(REL)

default:
	$(MAKE) -C $(KDIR) M=$$PWD
%:
	$(MAKE) -C $(KDIR) M=$$PWD $*

endif
