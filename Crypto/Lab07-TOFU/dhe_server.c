#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#define MAXSIZE 4096
#define PUB_KEY_LEN 256
#define ERR_SOCKET 2
#define ERR_CONN 3

#define CHECK(assertion, call_description)  \
  do {                                      \
    if (!(assertion)) {                     \
      fprintf(stderr, "(%s, %d): ",         \
        __FILE__, __LINE__);                \
      perror(call_description);             \
      exit(EXIT_FAILURE);                   \
    }                                       \
  } while(0)



/**
 * Open file <filename>, read public Diffie-Hellman parameters P and G and store them in <pdhm>
 * @param pdhm Diffie-Hellman key exchange context
 * @param filename file from which to read P and G
 */
DH * __read_pg_from_file(const char * filename) {
    BIO * pbio;
    DH * pdh;

    /* Get DH modulus and generator (P and G) */
    pbio = BIO_new_file(filename, "r");
    CHECK(pbio != NULL, "BIO_new_file");

    /* Read P and G from f */
    pdh = PEM_read_bio_DHparams(pbio, NULL, NULL, NULL);
    CHECK(pdh != NULL, "PEM_read_bio_DHparams");

    BIO_free(pbio);
    return pdh;
}

/**
 * Open file <filename>, read private key from PEM format and return EVP_PKEY key
 */
EVP_PKEY* __read_privkey_from_file(const char * filename) {
    BIO* pbio;
    EVP_PKEY* pkey;

    /* Get Privte Key from file */
    pbio = BIO_new_file(filename, "r");
    CHECK(pbio != NULL, "BIO_new_file");

    /* Read Private Key from bio structure */
    // TODO: check PEM_read_bio_PrivateKey
    pkey = PEM_read_bio_PrivateKey(pbio, NULL, NULL, NULL);
    CHECK(pkey != NULL, "Read private key");
    BIO_free(pbio);
    return pkey;
}

/**
 * Open file <filename>, read public key from PEM format and return EVP_PKEY key
 */
EVP_PKEY* __read_pubkey_from_file(const char * filename) {
    BIO* pbio;
    EVP_PKEY* pkey;

    /* Get Public Key from file */
    pbio = BIO_new_file(filename, "r");
    CHECK(pbio != NULL, "BIO_new_file");

    /* Read Public Key from bio structure */
    // TODO: check PEM_read_bio_PUBKEY
    pkey = PEM_read_bio_PUBKEY(pbio, NULL, NULL, NULL);
    CHECK(pkey != NULL, "Read public key");
    BIO_free(pbio);
    return pkey;
}

void my_receive(int sockfd, char * buffer, int length) {
    int bytes_received = 0;
    int rc;
    while (bytes_received < length) {
        rc = recv(sockfd, buffer + bytes_received, length - bytes_received, 0);
        CHECK(rc >= 0, "recv");

        bytes_received += rc;
    }
}

int RSASign( RSA* rsa,
              const unsigned char* Msg,
              size_t MsgLen,
              unsigned char** EncMsg,
              size_t* MsgLenEnc) {
  EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
  EVP_PKEY* priKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(priKey, rsa);
  if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
      return 0;
  }
  if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
      return 0;
  }
  if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {
      return 0;
  }
  *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
  
  if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
      return 0;
  }
  EVP_MD_CTX_destroy(m_RSASignCtx);
  return 1;
}

int main(int argc, char* argv[]) {
    int k, n;
    int opt = 0;
    int listen_fd = 0;
    int connect_fd = 0;
    char buf[MAXSIZE];
    int file_fd;
    char file_size[256];
    int len = 0;
    unsigned char buf_pubkey_ours[256];
    unsigned char buf_pubkey_theirs[256];
    unsigned char buf_secret_key[256];
    BIGNUM *pub_key, *priv_key, *pub_key_theirs;
    unsigned int serv_port = 1337;
    char* serv_ip = "127.0.0.1";
    char* filename = "smallfile.dat";
    struct sockaddr_in client_addr, server_addr;
    socklen_t client_len;
    size_t bytes_sent, bytes_read;
    BIO *bio_out;
    BIO *bio_sock;
    BIO *bio_mem;
    unsigned char pubkeystring[2000];
    RSA *rsapriv;
    unsigned char *rsasign;
    size_t signlen;

    // get arg params
    while ((opt = getopt(argc, argv, "i:p:f:")) != -1) {
        switch (opt) {
            case 'i':
                serv_ip = optarg;
                break;
            case 'p':
                serv_port = atoi(optarg);
                break;
            case 'f':
                filename = optarg;
                break;
            default:
                fprintf(stderr, "Usage %s [-i IP] [-p PORT] [-f FILENAME]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Create a BIO for printf
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    // Create a BIO for memory
    bio_mem = BIO_new(BIO_s_mem());

    // read RSA private key from file
    EVP_PKEY* privkey = __read_privkey_from_file("private.pem");
    CHECK(privkey != NULL, "__read_privkey_from_file");

    // print RSA Private key to check all is fine
    // TODO , e.g. EVP_PKEY_print_private

    EVP_PKEY_print_private(bio_out, privkey, 0, NULL);    
    // read RSA public key from file
    EVP_PKEY* pubkey = __read_pubkey_from_file("public.pem");
    CHECK(pubkey != NULL, "__read_pubkey_from_file");

    // print RSA Public key to check all is fine
    // TODO , e.g. EVP_PKEY_print_public
    EVP_PKEY_print_public(bio_out, pubkey, 0, NULL);
    // get DH public key using fixed parameters
    DH * tdh = __read_pg_from_file("dhparam.pem");
    CHECK(DH_generate_key(tdh) != 0, "DH_generate_key");
    DH_get0_key(tdh, &pub_key, &priv_key);
    n =  BN_num_bytes(pub_key);
    printf("[server] Pub key has %d bytes\n", n);
    CHECK(PUB_KEY_LEN == n, "DH PUB KEY LEN");
    BN_bn2bin(pub_key, buf_pubkey_ours);
    printf("[server] Our public key is: ");
    for(k=0; k<n; k++)
      printf("%02X", buf_pubkey_ours[k]);
    printf("\n");

    /* Create new socket */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listen_fd >= 0, "socket");

    /* Setup sockaddr_in struct */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(serv_ip);
    server_addr.sin_port = htons(serv_port);

    /* Bind */
    CHECK(bind(listen_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) >= 0, "bind");

    /* Listen */
    CHECK(listen(listen_fd, 0) >= 0, "listen");

    printf("[server] Server listening on port %d...\n", serv_port);

    /* Accept incoming connections */
    while(1) {
        client_len = sizeof(client_addr);
        connect_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &client_len);
        CHECK(connect_fd >= 0, "accept");

        printf("[server] Got a request...\n");

        // Set up BIO sock for this connection
        bio_sock = BIO_new_socket(connect_fd, BIO_NOCLOSE);

        // First send our public RSA key
        printf("[server] Sending RSA public key...\n");
        CHECK(PEM_write_bio_PUBKEY(bio_mem, pubkey), "sending RSA pub key");
        len = BIO_pending(bio_mem);
        BIO_read(bio_mem, pubkeystring, len);
        len = send(connect_fd, pubkeystring, len, 0);
        printf("Sent %d bytes\n", len);

        // Then send our public DH share
        printf("[server] Sending DH public key share...\n");
        len = send(connect_fd, buf_pubkey_ours, n, 0);
        CHECK(len >= 0, "send");

			  // Create a signature over ouf public DH share
        printf("[server] Generating RSA signature over public key share...\n");
        // TODO:
        // 1) convert privkey to RSA (check EVP_PKEY_... functions)
        RSA* rsa_key_format = RSA_new();
        CHECK(rsa_key_format != NULL, "RSA alloc");
        rsa_key_format = EVP_PKEY_get1_RSA(privkey);        
        // 2) Use RSASign
        unsigned char* signature;
        size_t len;
        int rc = RSASign(rsa_key_format, buf_pubkey_ours, n, &signature, &len);
        for(int i=0;i<256;i++) {
           printf("%02x", signature[i]);
        }
        // Send signature to server (TODO)
        send(connect_fd, signature, len, 0);

				// Get the public key of the other party
        my_receive(connect_fd, buf_pubkey_theirs, 256);
        printf("[server] Received public key from client...\n");
        printf("[server] The received public key is: ");
        for(k=0; k<PUB_KEY_LEN; k++)
          printf("%02X", buf_pubkey_theirs[k]);
        printf("\n");

        // Obtain the secret key
        pub_key_theirs = BN_bin2bn(buf_pubkey_theirs, PUB_KEY_LEN, NULL);
        n = DH_compute_key(buf_secret_key, pub_key_theirs, tdh);
        printf("[client] Exchanged secret key has %d bytes\n", n);
        printf("[client] The exchanged secret key is: ");
        for(k=0; k<n; k++)
          printf("%02X", buf_secret_key[k]);
        printf("\n");
    }

    close(listen_fd);
    close(file_fd);


    DH_free(tdh);
    return 0;
}


