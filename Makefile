ccflags-y := -std=gnu99 -Wno-declaration-after-statement
MODULES = firewallExtension.ko
obj-m += firewallExtension.o

all: $(MODULES)

firewallExtension.ko: firewallExtension.c firewallExtension.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
