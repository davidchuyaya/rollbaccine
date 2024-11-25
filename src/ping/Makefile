CONFIG_MODULE_SIG=n
obj-m = server.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules