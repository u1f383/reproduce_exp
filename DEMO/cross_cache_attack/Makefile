obj-m += hello.o
PWD := $(CURDIR)

all:
	make -C /home/u1f383/vuln_ko/linux-6.3.8/ M=$(PWD) modules

clean:
	make -C /home/u1f383/vuln_ko/linux-6.3.8/ M=$(PWD) clean
