CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -c -masm=intel -Wall -Wno-unused-variable \
          -o Underlay_bof.o Underlay_bof.c \
          -I./include \
          -fno-asynchronous-unwind-tables \
          -fno-ident \
          -Os

all:
	$(CC) $(CFLAGS)
	@echo "[+] Underlay_bof.o ready"

clean:
	rm -f Underlay_bof.o
