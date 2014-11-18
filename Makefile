all: snisvr

snisvr: snisvr.c
	clang -L/usr/local/lib -I/usr/local/include -lcyassl -o snisvr snisvr.c

clean:
	rm -rf snisvr

.PHONY: all clean
