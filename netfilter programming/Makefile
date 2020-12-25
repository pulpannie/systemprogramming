obj-m += netfilter.o

all: check-kdir
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order

check-kdir:
ifndef KDIR
	$(error KDIR, kernel source directory is undefined)
endif
