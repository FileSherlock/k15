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
	nasm -f bin -DOURIP=$(OURIP) $(KNOCKDEF) -I$(B)/ -o $@ -l $(B)/os.lst src/os.asm
	@echo "image: $$(stat -c %s $@) bytes"

# asm crypto checked against pyca/cryptography on the host (32-bit process)
$(B)/test_asm: test/test_asm.c src/os.asm $(GEN)
	nasm -f elf32 -DHOST -I$(B)/ -o $(B)/os_host.o src/os.asm
	gcc -m32 -no-pie -fno-pie -O1 -o $@ test/test_asm.c $(B)/os_host.o

test: $(B)/test_asm
	python3 tools/ec.py
	CERT=$(CERT) python3 test/test_crypto.py $(B)/test_asm

# what the curve and hash code cost natively (the same object the tests use, timed on this host)
bench: $(B)/test_asm test/bench.c
	gcc -m32 -no-pie -fno-pie -O1 -o $(B)/bench test/bench.c $(B)/os_host.o
	$(B)/bench

.PHONY: all test bench FORCE
