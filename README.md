# snisvr

Tool for testing SNI extensions with wolfSSL and the sniffer.

`snisvr` assumes that CyaSSL is installed in `/usr/local`. It uses the
certificates and keys found in `../cyassl/certs`.

Run it from the command line and it listens on port 11111. It will send one
blob of HTML back to the client depending on the server name provided in the
Client Hello. The command is simply `./snisvr`.

In another window run the CyaSSL example client. The `-S` option is used to
set the SNI. The snisvr tool exects this to be either `svrA`, `svrB`, or not
used.

    $ ./examples/client/client -g -S svrA

The server webpage should indicate itself as either Server A, Server B, or
generic, depending on the SNI.

The SSL sniffer should be run from its directory, `sslSniffer/sslSnifferTest`.
When run without command line options, it will first ask for the interface to
use, select `lo0`. Next, enter port 11111. Last enter the alternate SNI to
use. In this test use either `svrA` or `svrB`.

When SNI enabled, the sniffer by default will load the default key onto the
SSL_CTX, and will add on the same key associated to the provided name to be
used if the name is detected in the SNI.
