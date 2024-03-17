CONFIG_MODULE_SIG=n
obj-m = encryption.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

.PHONY: rebuild
rebuild:
        make clean
        make all