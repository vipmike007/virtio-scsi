ifneq ($(LINUXINCLUDE),)
# kbuild part of makefile
obj-m += drivers/scsi/
obj-m += drivers/target/
LINUXINCLUDE := -I$M/include $(LINUXINCLUDE)

else

# normal makefile
REL ?= $(shell uname -r)
KDIR ?= /usr/src/kernels/$(REL)
#QEMU_IMG = qemu-img
QEMU_IMG = ../../upstream/qemu/+build/qemu-img
SRCS = drivers/scsi/virtio_scsi.c
MAKEFLAGS += -r

.PHONY: default
default:
	$(MAKE) -C $(KDIR) M=$$PWD

-include $(patsubst %,%/.*.cmd,$(sort $(dir $(SRCS))))

NAME = virtio_scsi
ARCH ?= $(shell uname -m)
RPM = rh-driver-disk/rpms/$(ARCH)/$(NAME)-$(REL).rpm
RPMBUILD = rpmbuild

.PHONY: $(NAME).spec
$(NAME).spec: $(NAME).spec.in
	VERSION=$(shell echo $(REL) | sed 's/-.*//'); \
	RELEASE=$(shell echo $(REL) | sed -n 's/^[^-]*-\(.*\)\.$(ARCH)/\1/p'); \
	sed "s/VERSION/$$VERSION/; s/RELEASE/$$RELEASE/" $< > $@.tmp
	cmp --silent $@.tmp $@ 2>/dev/null || mv $@.tmp $@
	rm -rf $@.tmp

.PHONY: $(NAME).tar.gz
$(NAME).tar.gz:
	git archive --prefix=$(NAME)/ HEAD | gzip -9c > $@.tmp
	cmp --silent $@.tmp $@ 2>/dev/null || mv $@.tmp $@
	rm -rf $@.tmp

$(RPM): $(NAME).spec $(NAME).tar.gz
	mkdir -p $(@D)
	$(RPMBUILD) --define "_sourcedir $$PWD" \
		--define "_builddir $$PWD/BUILD" \
		--define "_srcrpmdir $$PWD" \
		--define "_rpmdir $$PWD/rh-driver-disk/rpms" \
		--target $(ARCH) -ba $<

rh-driver-disk/rhdd3: $(RPM)
	rpm -q --qf '%{summary}' -p $< > $@

virtio_scsi.img: $(RPM) rh-driver-disk/rhdd3
	cd rh-driver-disk/rpms/$(ARCH) && createrepo .
	$(QEMU_IMG) convert -f vvfat -O raw fat:floppy:12:$$PWD/rh-driver-disk $@

clean:
	$(MAKE) -C $(KDIR) M=$$PWD $*
	rm -f modules.order Module.symvers built-in.o \
		$(patsubst %.c,%.o,$(SRCS)) \
		$(patsubst %.c,%.ko,$(SRCS)) \
		$(patsubst %.c,%.mod.*,$(SRCS)) \
		virtio_scsi.img $(NAME).tar.gz rh-driver-disk BUILD

endif
