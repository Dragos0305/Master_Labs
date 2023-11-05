#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "stdio.h"
#include "string.h"

int main()
{
    BIO * bio;
    SSL * ssl;
    SSL_CTX * ctx;

    int p;

    char * request = "GET / HTTP/1.0\r\nHost: www.verisign.com\r\n\r\n";
    char r[1024];

    /* Init library */

    SSL_library_init ();
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* TO DO context init */

    ctx = SSL_CTX_new(TLS_client_method());


    /* load trust store */


    if(! SSL_CTX_load_verify_locations(ctx, "TrustStore.pem", NULL))
    {
        fprintf(stderr, "Error loading trust store\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 0;
    }


    /* establish connection */

    bio = BIO_new_ssl_connect(ctx);
   
    /* Set SSL_MODE_AUTO_RETRY flag */

    BIO_get_ssl(bio, & ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* TO DO setup connection */
    BIO_set_conn_hostname(bio, "www.verisign.com:https");
    if(BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    /* TO DO check certificate */

    if(SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Certificate verification error: %s\n",
            X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Send request */

    BIO_write(bio, request, strlen(request));

    /* TO DO read answer and prepare output*/

    FILE* fp = fopen("response", "w");

    while (1) {
        p = BIO_read(bio, r, 1023);
        if (p <= 0) break;
        r[p] = 0;
        fprintf(fp, "%s", r);
    }
    fclose(fp);

    /* Close the connection and free the context */

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 0;
}
