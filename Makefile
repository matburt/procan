#This is a Gmake file for ProcAn
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
	@echo "Building the FreeBSD make target."
	@gcc -O2 -Wall -o procan -lcurses -lpanel -lkvm -lpthread procan.c analyzer.c freebsd_collector.c config.c backend.c cli.c
openbsd:
	@echo "Building the OpenBSD make target."
	@gcc -O2 -Wall -o procan -lcurses -lpanel -lpthread procan.c analyzer.c openbsd_collector.c config.c backend.c cli.c
linux:
	@echo "Building the Linux make target."
	@gcc -O2 -Wall -o procan -lcurses -lpanel -lpthread -lproc-3.2.8 procan.c analyzer.c linux_collector.c config.c backend.c cli.c
debug-linux:
	@echo "Building the Linux debug target.";
	@gcc -g -Wall -o procan -lcurses -lpanel -lpthread -lproc-3.2.8 procan.c analyzer.c linux_collector.c config.c backend.c cli.c
install:
	@echo "I can't install myself just yet."
	@echo "Install me yourself or just run from the local directory."
clean:
	@rm -f procan *~ *.core
