/* snisrv.c
 *
 * Copyright (C) 2014 wolfSSL Inc.
 *
 * snisrv is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * snisrv is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <cyassl/options.h>
#include <cyassl/ssl.h>
#include <cyassl/test.h>


const char* Key_Filename = "../cyassl/certs/server-key.pem";
const char* CA_Cert_Filename = "../cyassl/certs/ca-cert.pem";

const char* SvrA_Name = "svrA";
const char* SvrA_Cert_Filename = "../cyassl/certs/server-cert.pem";
const char* SvrA_Html =
    "<html>\r\n"
    "<head><title>Thanks!</title></head>\r\n"
    "<body>Hello world! I'm server A!</body>\r\n"
    "</html>\r\n";

const char* SvrB_Name = "svrB";
const char* SvrB_Cert_Filename = "../cyassl/certs/server-cert.pem";
const char* SvrB_Html =
    "<html>\r\n"
    "<head><title>Thanks!</title></head>\r\n"
    "<body>Hello world! I'm server B!</body>\r\n"
    "</html>\r\n";


const char* Default_Html =
    "<html>\r\n"
    "<head><title>Thanks!</title></head>\r\n"
    "<body>Hello world! I'm generic server!</body>\r\n"
    "</html>\r\n";

static inline void errsys(const char* msg)
{
    printf("snisrv error: %s\n", msg);
    if (msg)
        exit(1);
}


static CYASSL_CTX* setup_new_cyassl_ctx(const char* keyFilename,
                                        const char* certFilename,
                                        const char* caCertFilename,
                                        const char* hostName)
{
    CYASSL_CTX* newCtx = CyaSSL_CTX_new(CyaTLSv1_2_server_method());

    if (newCtx) {
        CyaSSL_CTX_load_verify_locations(newCtx, caCertFilename, NULL);
        CyaSSL_CTX_use_PrivateKey_file(newCtx, keyFilename, SSL_FILETYPE_PEM);
        CyaSSL_CTX_use_certificate_file(newCtx, certFilename, SSL_FILETYPE_PEM);
        if (hostName)
            CyaSSL_CTX_UseSNI(newCtx, CYASSL_SNI_HOST_NAME,
                              hostName, strlen(hostName));
    }

    return newCtx;
}


int
main(void)
{
    CYASSL_CTX* ctx;
    CYASSL* ssl;
    unsigned short port = 11111;
    int listenFd, clientFd, ret;
    unsigned char peek[1024];
    unsigned int peekSz = sizeof(peek);
    char serverName[128];
    unsigned int serverNameSz = sizeof(serverName);
    const char* html;

    CyaSSL_Init();

    tcp_accept(&listenFd, &clientFd, NULL, 11111, 0, 0);
    ret = recv(clientFd, peek, peekSz, MSG_PEEK);
    if (ret < 0)
        errsys("didn't peek correctly");
    else
        peekSz = (unsigned int)ret;

    ret = CyaSSL_SNI_GetFromBuffer(peek, peekSz, CYASSL_SNI_HOST_NAME,
                                   (unsigned char*)serverName, &serverNameSz);
    if (ret < 0)
        errsys("getting server name failed");

    serverName[serverNameSz] = 0;
    if (strcmp(serverName, SvrA_Name) == 0) {
        ctx = setup_new_cyassl_ctx(Key_Filename, SvrA_Cert_Filename,
                                   CA_Cert_Filename, SvrA_Name);
        if (ctx == NULL)
            errsys("unable to create server A ctx");
        html = SvrA_Html;
    }
    else if (strcmp(serverName, SvrB_Name) == 0) {
        ctx = setup_new_cyassl_ctx(Key_Filename, SvrB_Cert_Filename,
                                   CA_Cert_Filename, SvrB_Name);
        if (ctx == NULL)
            errsys("unable to create server B ctx");
        html = SvrB_Html;
    }
    else {
        ctx = setup_new_cyassl_ctx(Key_Filename, SvrA_Cert_Filename,
                                   CA_Cert_Filename, SvrA_Name);
        if (ctx == NULL)
            errsys("unable to create server default ctx");
        html = Default_Html;
    }

    ssl = CyaSSL_new(ctx);
    if (ssl == NULL)
        errsys("unable to create server session");

    if (CyaSSL_set_fd(ssl, clientFd) != SSL_SUCCESS)
        errsys("unable to set session's socket");

    peekSz = sizeof(peek);

    ret = CyaSSL_read(ssl, peek, peekSz);
    if (ret < 0)
        errsys("unable to receive data");

    ret = CyaSSL_write(ssl, html, strlen(html));
    if (ret < 0)
        errsys("unable to send data");

    ret = CyaSSL_shutdown(ssl);
    if (ret != SSL_SUCCESS)
        errsys("unable to shutdown connection");

    close(clientFd);
    close(listenFd);
    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);

    CyaSSL_Cleanup();
}

