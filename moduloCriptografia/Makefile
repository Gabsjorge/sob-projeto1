obj-m += moduloCrypto.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	gcc test_file.c -o teste

clean:
	rmmod moduloCrypto
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm teste
