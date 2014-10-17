all: snisrv

snisrv: snisrv.c
	clang -lcyassl -o snisrv snisrv.c

clean:
	rm -rf snisrv

.PHONY: all clean
