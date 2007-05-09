os = $(shell uname -s)

ifeq ($(os), Linux)
target = linux
else ifeq ($(os), FreeBSD)
target = freebsd
else ifeq ($(os), OpenBSD)
target = openbsd
else
target = unsupported
endif

all: $(target)
	@echo "building $(target) done."

unsupported:
	@echo "target os" $(os) " is not supported"
freebsd:
	@echo "Building the FreeBSD make target with the debug flag."
	@gcc -g -Wall -o procan -lkvm -lpthread procan.c analyzer.c freebsd_collector.c config.c backend.c cli.c
openbsd:
	@echo "Building the OpenBSD make target with the debug flag."
	@gcc -g -Wall -o procan -lpthread procan.c analyzer.c openbsd_collector.c config.c backend.c cli.c
linux:
	@echo "Building the Linux make target with the debug flag."
	@gcc -g -Wall -o procan -lpthread -lproc procan.c analyzer.c linux_collector.c config.c backend.c cli.c
install:
	@echo "I can't install myself just yet."
	@echo "Install me yourself or just run from the local directory."
clean:
	@rm -f procan *~ *.core

