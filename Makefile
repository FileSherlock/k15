# B: where generated files go. CERT: the server's identity (see tools/gen.py). Both can be
# set to build a second image, e.g. `make B=build-real CERT=cert-real`.
comma := ,
# IP: the address the server answers on, baked in (default: what QEMU's slirp expects).
# For a real server: `make B=build-hz CERT=cert-hz NAME=<name or IP in the certificate> IP=a.b.c.d`.
B ?= build
CERT ?= cert
IP ?= 10.0.2.15
# KNOCK=a,b (development): a TCP packet to port a, then one to port b, resets the machine
KNOCK ?=
KNOCKDEF := $(if $(KNOCK),-DKNOCK_A=$(word 1,$(subst $(comma), ,$(KNOCK))) -DKNOCK_B=$(word 2,$(subst $(comma), ,$(KNOCK))),)
OURIP := $(shell python3 tools/ip.py $(IP))
# CAP=n (tests): no more than n slots in each connection table, however much memory there is.
# IDLE=n (tests): how long a connection must have been quiet to be replaced when there is no room
# TSHARE=n: the table of TLS connections gets 1/2^n of the memory (default 3: an eighth), the
# table of port 80 connections the rest
CAP ?=
IDLE ?=
TSHARE ?=
TABLEDEF := $(if $(CAP),-DCAP=$(CAP),) $(if $(IDLE),-DIDLE=$(IDLE),) $(if $(TSHARE),-DTSHARE=$(TSHARE),)
# DEBUG=1 (development): count dropped and resent packets, shown in the page on port 80
# (DEBUG=2: and how busy each processor is, see bench/busy.sh)
# LIFE=n (development): the machine is reset after about n minutes (at 2.1 GHz), come what may
DEBUGDEF := $(if $(DEBUG),-DDEBUG=$(DEBUG),) $(if $(LIFE),-DLIFE=$(LIFE),)

# The image: hand-written assembly (src/os.asm) -> flat binary, loaded at 1 MiB; and a
# disk image that boots it: the boot sector (src/boot.asm), then the image, padded
all: $(B)/disk.img

$(B)/ip: FORCE
	@mkdir -p $(B)
	@python3 tools/ip.py $(IP) $@
FORCE:

$(B)/disk.img: src/boot.asm $(B)/os.bin tools/mkdisk.py
	nasm -f bin -o $(B)/boot.bin src/boot.asm
	python3 tools/mkdisk.py $(B)/boot.bin $(B)/os.bin $@

# cert/ is made on the first build (a private CA and a leaf) or holds a real certificate
GEN := $(B)/gen.inc $(B)/ec.inc $(B)/regs.inc $(B)/conf.inc
ID := $(CERT)/server.key $(CERT)/server.pem
$(ID) &:
	@mkdir -p $(B)
	CERT=$(CERT) python3 tools/gen.py www/index.html $(B)

$(GEN) &: tools/gen.py tools/ec.py www/index.html $(ID)
	@mkdir -p $(B)
	CERT=$(CERT) python3 tools/gen.py www/index.html $(B)

$(B)/os.bin: src/os.asm $(GEN) $(B)/ip
	nasm -f bin -DOURIP=$(OURIP) $(KNOCKDEF) $(TABLEDEF) $(DEBUGDEF) -I$(B)/ -o $@ -l $(B)/os.lst src/os.asm
	@echo "image: $$(stat -c %s $@) bytes"

# asm crypto checked against pyca/cryptography on the host (the asm calls and pushes as it
# likes: no red zone; and it wants its buffers below 4 GiB: no PIE)
HOSTCC := gcc -no-pie -fno-pie -O1 -mno-red-zone
$(B)/test_asm: test/test_asm.c src/os.asm $(GEN)
	nasm -f elf64 -DHOST -I$(B)/ -o $(B)/os_host.o src/os.asm
	$(HOSTCC) -o $@ test/test_asm.c $(B)/os_host.o

test: $(B)/test_asm
	python3 tools/ec.py
	CERT=$(CERT) python3 test/test_crypto.py $(B)/test_asm

# what the curve and hash code cost natively (the same object the tests use, timed on this host)
bench: $(B)/test_asm test/bench.c
	$(HOSTCC) -o $(B)/bench_asm test/bench.c $(B)/os_host.o
	$(B)/bench_asm

.PHONY: all test bench FORCE
