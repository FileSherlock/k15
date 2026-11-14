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
OURIP := $(shell python3 -c 'import ipaddress; print("0x" + ipaddress.IPv4Address("$(IP)").packed[::-1].hex())')
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
# COMPRESS=0: no file is also packed compressed
SITE ?= www
P80 ?= page
HSTS ?=
CACHE ?= 600
HEADERS ?=
COMPRESS ?= 1
# WIN=n: so many segments of a response may be on their way to a client at once
# NOTSO=1 (tests): a segment a frame, also where the card would cut frames into segments
# BIGSH=n (tests): each processor has 2^n buffers for the frames the card cuts up (default 3)
# RACE=n (tests): the timer stops in the middle of a connection it has in hand (tools/racetest.py)
WIN ?=
WINDEF := $(if $(WIN),-DWIN=$(WIN),) $(if $(WXTEST),-DWXTEST=$(WXTEST),) $(if $(ISNTOP),-DISNTOP=$(ISNTOP),) $(if $(ISNBITS),-DISNBITS=$(ISNBITS),) $(if $(KEYLIFE),-DKEYLIFE=$(KEYLIFE),) $(if $(STLIFE),-DSTLIFE=$(STLIFE),) $(if $(NOTSO),-DNOTSO,) $(if $(BIGSH),-DBIGSH=$(BIGSH),) $(if $(RACE),-DRACE=$(RACE),)

# the routines a handshake spends its time in: none of their jumps may lie on a 32-byte
# boundary (tools/jcc.py; of `xdh` and `seal` the jumps inside loops)
HOT := shablk xdh:loops cswap comb select vm fas fmul inv seal:loops ks64 gh1 aeskey aes4

# (the image, its listing and the disk hold the private key: for their owner's eyes only)
# The image: hand-written assembly (src/os.asm) -> flat binary, loaded at 1 MiB; and a
# disk image that boots it: the boot sector (src/boot.asm), then the image, padded
all: $(B)/disk.img

$(B)/ip: FORCE
	@mkdir -p $(B)
	@printf '%s' '$(IP)' > $@.$$$$; if cmp -s $@.$$$$ $@; then rm $@.$$$$; else mv $@.$$$$ $@; fi
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
PACKSET := $(SITE) $(P80) $(HSTS) $(CACHE) $(HEADERS) $(COMPRESS)
$(B)/site.conf: FORCE
	@mkdir -p $(B)
	@{ echo '$(PACKSET)'; find $(SITE) -type f -printf '%p %s %T@\n' | sort; } > $@.$$$$; \
	 if cmp -s $@.$$$$ $@; then rm $@.$$$$; else mv $@.$$$$ $@; fi
$(PACKED) &: tools/pack.py $(B)/site.conf $(GEN)
	P80=$(P80) HSTS=$(HSTS) CACHE=$(CACHE) HEADERS='$(HEADERS)' COMPRESS=$(COMPRESS) python3 tools/pack.py $(SITE) $(B)

$(B)/os.bin: src/os.asm $(GEN) $(PACKED) $(B)/ip
	nasm -f bin -DOURIP=$(OURIP) $(KNOCKDEF) $(TABLEDEF) $(DEBUGDEF) $(WINDEF) -I$(B)/ -o $@ -l $(B)/os.lst src/os.asm
	@chmod go= $@ $(B)/os.lst
	@echo "image: $$(stat -c %s $@) bytes, of which the site: $$(stat -c %s $(B)/site.bin)"
	@python3 tools/jcc.py $(B)/os.lst $(HOT) || echo "(these jumps lie on 32-byte boundaries: see HOT in src/os.asm)"

# asm crypto checked against pyca/cryptography on the host (the asm calls and pushes as it
# likes: no red zone; and it wants its buffers below 4 GiB: no PIE)
HOSTCC := gcc -no-pie -fno-pie -O1 -mno-red-zone
$(B)/test_asm: test/test_asm.c test/asm.h src/os.asm $(GEN)
	nasm -f elf64 -DHOST -I$(B)/ -o $(B)/os_host.o src/os.asm
	$(HOSTCC) -o $@ test/test_asm.c $(B)/os_host.o

test: $(B)/test_asm
	python3 tools/ec.py
	CERT=$(CERT) python3 test/test_crypto.py $(B)/test_asm

# The same object against what others have made (tools/outside.sh fetch gets it into ext/):
# Wycheproof's vectors and RFC 6979's (test/outside.py), and under Valgrind with every
# secret marked undefined, so that a jump or an address made of one is an error
# (test/ct.c; the runs after the first are the controls: each has one, which must be found)
EXT ?= ext
VG := VALGRIND_LIB=$(EXT)/valgrind/usr/libexec/valgrind $(EXT)/valgrind/usr/bin/valgrind -q --error-exitcode=9
outside: $(B)/test_asm
	CERT=$(CERT) python3 -I test/outside.py $(B)/test_asm $(EXT)/wycheproof/testvectors_v1
$(B)/ct: test/ct.c test/asm.h $(B)/test_asm
	$(HOSTCC) -I$(EXT)/valgrind/usr/include -o $@ test/ct.c $(B)/os_host.o
ct: $(B)/ct
	$(VG) $(B)/ct
	@for n in 1 2 3 4 5 6; do if $(VG) $(B)/ct $$n >/dev/null 2>&1; then echo "FAIL: control $$n went unnoticed"; exit 1; fi; done
	@echo "ok   nothing jumps on or indexes with a secret (and each of six controls that does is noticed)"

# what the curve and hash code cost natively (the same object the tests use, timed on this host)
bench: $(B)/test_asm test/bench.c
	$(HOSTCC) -o $(B)/bench_asm test/bench.c $(B)/os_host.o
	$(B)/bench_asm

.PHONY: all test outside ct bench FORCE
