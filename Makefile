# B: where generated files go. CERT: the server's identity (see tools/gen.py). Both can be
# set to build a second image, e.g. `make B=build-real CERT=cert-real`.
B ?= build
CERT ?= cert

# The image: hand-written assembly (src/os.asm) -> flat multiboot binary
all: $(B)/os.bin

# cert/ is made on the first build (a private CA and a leaf) or holds a real certificate
GEN := $(B)/gen.inc $(B)/ec.inc $(B)/regs.inc $(B)/conf.inc
ID := $(CERT)/server.key $(CERT)/server.pem
$(ID) &:
	@mkdir -p $(B)
	CERT=$(CERT) python3 tools/gen.py www/index.html $(B)

$(GEN) &: tools/gen.py tools/ec.py www/index.html $(ID)
	@mkdir -p $(B)
	CERT=$(CERT) python3 tools/gen.py www/index.html $(B)

$(B)/os.bin: src/os.asm $(GEN)
	nasm -f bin -I$(B)/ -o $@ -l $(B)/os.lst src/os.asm
	@echo "image: $$(stat -c %s $@) bytes"

# asm crypto checked against pyca/cryptography on the host (32-bit process)
$(B)/test_asm: test/test_asm.c src/os.asm $(GEN)
	nasm -f elf32 -DHOST -I$(B)/ -o $(B)/os_host.o src/os.asm
	gcc -m32 -no-pie -fno-pie -O1 -o $@ test/test_asm.c $(B)/os_host.o

test: $(B)/test_asm
	python3 tools/ec.py
	CERT=$(CERT) python3 test/test_crypto.py $(B)/test_asm

.PHONY: all test
