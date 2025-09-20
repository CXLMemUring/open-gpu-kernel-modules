obj-m += p2p_safe.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	-sudo rmmod p2p_force 2>/dev/null
	-sudo rmmod p2p_enable 2>/dev/null
	-sudo rmmod p2p_safe 2>/dev/null
	sudo insmod p2p_safe.ko
	@echo "P2P Safe Enabler installed"

uninstall:
	-sudo rmmod p2p_safe

test:
	@echo "=== P2P Safe Enabler Status ==="
	@lsmod | grep p2p_safe || echo "Module not loaded"
	@echo ""
	@echo "=== Testing P2P ==="
	cd /root/bam && ./test_gpu_p2p
	@echo ""
	@echo "=== Results ==="
	@dmesg | grep P2P_SAFE | tail -10

reload: uninstall install test