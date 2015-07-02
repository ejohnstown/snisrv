all: snisvr

snisvr: snisvr.c
	clang -L/usr/local/lib -I/usr/local/include -lwolfssl -o snisvr snisvr.c

clean:
	rm -rf snisvr

.PHONY: all clean
