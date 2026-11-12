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
# SITE: the folder of files that is served (tools/pack.py makes them part of the image).
# P80=redirect: port 80 sends everybody to https://NAME/ (default: it serves the page at /)
# HSTS=seconds, CACHE=seconds, HEADERS='Name: value': headers for every file (tools/pack.py)
SITE ?= www
P80 ?= page
HSTS ?=
CACHE ?= 600
HEADERS ?=
# WIN=n: so many segments of a response may be on their way to a client at once
WIN ?=
WINDEF := $(if $(WIN),-DWIN=$(WIN),) $(if $(WXTEST),-DWXTEST=$(WXTEST),) $(if $(ISNTOP),-DISNTOP=$(ISNTOP),) $(if $(ISNBITS),-DISNBITS=$(ISNBITS),) $(if $(KEYLIFE),-DKEYLIFE=$(KEYLIFE),)

# the routines a handshake spends its time in: none of their jumps may lie on a 32-byte
# boundary (tools/jcc.py; of `seal` only the loops count, which that list can't say)
HOT := shablk xdh cswap comb select vm fas addk fmul inv chacha aeskey aesblk

# (the image, its listing and the disk hold the private key: for their owner's eyes only)
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
	@chmod go= $@

# cert/ is made on the first build (a private CA and a leaf) or holds a real certificate.
# NAME: the name a generated certificate is for, and the one of a certificate's names
# that port 80 sends everybody to (default: the certificate's first). SAN='a b': further
# names for a generated certificate. $(B)/names.conf changes when they do.
GEN := $(B)/gen.inc $(B)/ec.inc $(B)/regs.inc $(B)/conf.inc
ID := $(CERT)/server.key $(CERT)/server.pem
$(ID) &:
	@mkdir -p $(B)
	CERT=$(CERT) python3 tools/gen.py $(B)

$(B)/names.conf: FORCE
	@mkdir -p $(B)
	@echo '$(NAME) $(SAN)' > $@.$$$$; if cmp -s $@.$$$$ $@; then rm $@.$$$$; else mv $@.$$$$ $@; fi

$(GEN) &: tools/gen.py tools/ec.py $(ID) $(B)/names.conf
	@mkdir -p $(B)
	CERT=$(CERT) python3 tools/gen.py $(B)

# The site: every file under $(SITE) as the response it is sent as, and the table of paths.
# It is made again when $(B)/site.conf changes, which lists the settings and the files
# (names, sizes, times: file names are not for make to read).
PACKED := $(B)/site.inc $(B)/site.bin
PACKSET := $(SITE) $(P80) $(HSTS) $(CACHE) $(HEADERS)
$(B)/site.conf: FORCE
	@mkdir -p $(B)
	@{ echo '$(PACKSET)'; find $(SITE) -type f -printf '%p %s %T@\n' | sort; } > $@.$$$$; \
	 if cmp -s $@.$$$$ $@; then rm $@.$$$$; else mv $@.$$$$ $@; fi
$(PACKED) &: tools/pack.py $(B)/site.conf $(GEN)
	P80=$(P80) HSTS=$(HSTS) CACHE=$(CACHE) HEADERS='$(HEADERS)' python3 tools/pack.py $(SITE) $(B)

$(B)/os.bin: src/os.asm $(GEN) $(PACKED) $(B)/ip
	nasm -f bin -DOURIP=$(OURIP) $(KNOCKDEF) $(TABLEDEF) $(DEBUGDEF) $(WINDEF) -I$(B)/ -o $@ -l $(B)/os.lst src/os.asm
	@chmod go= $@ $(B)/os.lst
	@echo "image: $$(stat -c %s $@) bytes, of which the site: $$(stat -c %s $(B)/site.bin)"
	@python3 tools/jcc.py $(B)/os.lst $(HOT) || echo "(these jumps lie on 32-byte boundaries: see HOT in src/os.asm)"

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
