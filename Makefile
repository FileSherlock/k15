B := build

# The image: hand-written assembly (src/os.asm) -> flat multiboot binary
all: $(B)/os.bin

# cert/ is made on the first build (a private CA and a leaf) or holds a real certificate
GEN := $(B)/gen.inc $(B)/ec.inc $(B)/regs.inc
CERT := cert/server.key cert/server.pem
$(CERT) &:
	@mkdir -p $(B)
	python3 tools/gen.py www/index.html $(B)

$(GEN) &: tools/gen.py tools/ec.py www/index.html $(CERT)
	@mkdir -p $(B)
	python3 tools/gen.py www/index.html $(B)

$(B)/os.bin: src/os.asm $(GEN)
	nasm -f bin -o $@ -l $(B)/os.lst src/os.asm
	@echo "image: $$(stat -c %s $@) bytes"

# asm crypto checked against pyca/cryptography on the host (32-bit process)
$(B)/test_asm: test/test_asm.c src/os.asm $(GEN)
	nasm -f elf32 -DHOST -o $(B)/os_host.o src/os.asm
	gcc -m32 -no-pie -fno-pie -O1 -o $@ test/test_asm.c $(B)/os_host.o

test: $(B)/test_asm
	python3 tools/ec.py
	python3 test/test_crypto.py $(B)/test_asm

.PHONY: all test
