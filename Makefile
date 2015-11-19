KERNELDIR=/lib/modules/`uname -r`/build
#ARCH=i386
#KERNELDIR=/usr/src/kernels/`uname -r`-i686

EXTRA_CFLAGS += -I$(PWD) -Wall -Werror
MODULES = firewallExtension.ko 
obj-m += firewallExtension.o
firewallExtension-y = firewall.o list.o
PROGS = firewallSetup

all: $(MODULES)  $(PROGS)

firewallExtension.ko: firewall.c list.h list.c
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	rm -f $(PROGS) *.o

install:	
	make -C $(KERNELDIR) M=$(PWD) modules_install

quickInstall:
	cp $(MODULES) /lib/modules/`uname -r`/extra

firewallSetup: firewallSetup.o
	gcc -Wall -Werror -o $@ $<

firewallSetup.o: firewallSetup.c
	gcc -Wall -Werror -c $<
