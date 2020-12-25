obj-m += lkm.o

KDIR = /home/jiseongg/linux-4.4

all:
		$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
		rm -rf *.o *.ko *.mod.* *.symvers *.order
