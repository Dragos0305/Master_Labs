#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
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

void my_receive(int sockfd, char * buffer, int length) {
    int bytes_received = 0;
    int rc;
    while (bytes_received < length) {
        rc = recv(sockfd, buffer + bytes_received, length - bytes_received, 0);
        CHECK(rc >= 0, "recv");

        bytes_received += rc;
    }
}

int RSAVerifySignature( RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         int* Authentic) {
  *Authentic = 0;
  EVP_PKEY* pubKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pubKey, rsa);
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
    return 0;
  }
  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
    return 0;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
  if (AuthStatus==1) {
    *Authentic = 1;
    EVP_MD_CTX_destroy(m_RSAVerifyCtx);
    return 1;
  } else if(AuthStatus==0){
    *Authentic = 0;
    EVP_MD_CTX_destroy(m_RSAVerifyCtx);
    return 1;
  } else{
    *Authentic = 0;
    EVP_MD_CTX_destroy(m_RSAVerifyCtx);
    return 0;
  }
}

int main(int argc, char* argv[]) {
    int opt = 0;
    int ret = 0;
    int k, n, len;
    int file_fd;
    int file_size;
    int total = 0;
    unsigned char buf_pubkey_ours[256];
    unsigned char buf_pubkey_theirs[256];
    unsigned char buf_secret_key[256];
    BIGNUM *pub_key, *priv_key, *pub_key_theirs;
    unsigned int server_port = 1337;
    struct sockaddr_in server_addr;
    socklen_t server_len;
    char* server_ip = "127.0.0.1";
    char* filename = "recv_file";
    int client_sockfd = 0;
    struct timeval start, connect_done, transfer_done;
    BIO *bio_sock;
    BIO *bio_out;
    BIO *bio_mem;
    EVP_PKEY *spubkey;
    RSA *rsa;
    unsigned char pubkeystring[2000];

    // Get arguments
    while ((opt = getopt(argc, argv, "i:p:f:")) != -1) {
        switch (opt) {
            case 'i':
                server_ip = optarg;
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'f':
                filename = optarg;
                break;
            default:
                fprintf(stderr, "Usage %s [-i SERVER_IP] [-p PORT] [-f RECV_FILENAME]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Create a BIO for printf
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    // Get public key using fixed parameters
    DH * tdh = __read_pg_from_file("dhparam.pem");
    CHECK(DH_generate_key(tdh) != 0, "DH_generate_key");
    DH_get0_key(tdh, &pub_key, &priv_key);
    n =  BN_num_bytes(pub_key);
    printf("[client] Pub key has %d bytes\n", n);
    CHECK(PUB_KEY_LEN == n, "DH PUB KEY LEN");
    BN_bn2bin(pub_key, buf_pubkey_ours);
    printf("[client] Our public key is: ");
    for(k=0; k<n; k++)
      printf("%02X", buf_pubkey_ours[k]);
    printf("\n");

    /* Open a TCP socket */
    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (client_sockfd < 0) {
        perror("Error in socket()");
        exit(ERR_SOCKET);
    }

    /* Setup sockaddr_in struct */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(server_port);

    server_len = sizeof(server_addr);

    /* Open file */
    file_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(file_fd >= 0, "open");

    /* Connect */
    gettimeofday(&start, NULL);
    ret = connect (client_sockfd, (struct sockaddr *) &server_addr, server_len);
    gettimeofday(&connect_done, NULL);
    CHECK(ret >= 0, "connect");

    printf("[client] Connected to %d\n", server_port);

    // Set up BIO sock for this connection
    bio_sock = BIO_new_socket(client_sockfd, BIO_NOCLOSE);

    // First get the server RSA public key
    printf("[client] Receiving server's RSA public key...\n");
    my_receive(client_sockfd, pubkeystring, 451);
    printf("[client] Received RSA public key from server...\n");

    // If all goes well, print the server public key
    bio_mem = BIO_new_mem_buf(pubkeystring, 451); // hard-coded for now
    spubkey = PEM_read_bio_PUBKEY(bio_mem, NULL, NULL, NULL);
    CHECK(spubkey != NULL, "PEM_read_bio_PUBKEY");
    // TODO print public key from server (check EVP_PKEY_print...)
    printf("[server] Public key from ther server: \n");
    EVP_PKEY_print_public(bio_out, spubkey, 0, NULL);
    // Send our public key
    printf("[client] Sending public key...\n");
    len = send(client_sockfd, buf_pubkey_ours, n, 0);
    CHECK(len >= 0, "send");

    // Get the other party public key
    my_receive(client_sockfd, buf_pubkey_theirs, 256);
    printf("[client] Received public key from server...\n");
    printf("[client] The received public key is: ");
    for(k=0; k<PUB_KEY_LEN; k++)
      printf("%02X", buf_pubkey_theirs[k]);
    printf("\n");

    // Receive RSA signature from server
    // TODO
    unsigned char* signature = malloc(256);
    my_receive(client_sockfd, signature, 256);

    printf("[server]Received signature is: \n");
    for(int i=0;i<256;i++) {
      printf("%02x", signature[i]);
    }
    // Verify signature
    // TODO: use RSAVerifySignature(...)
    RSA *rsa_pub = EVP_PKEY_get1_RSA(spubkey); 
    int Auth=0;
    RSAVerifySignature(rsa_pub, signature, sizeof(signature), buf_pubkey_theirs, PUB_KEY_LEN, &Auth);
    printf("Auth is =>>>>>> %d\n", Auth);

    // Obtain the secret key
    pub_key_theirs = BN_bin2bn(buf_pubkey_theirs, PUB_KEY_LEN, NULL);
    n = DH_compute_key(buf_secret_key, pub_key_theirs, tdh);
    printf("[client] Exchanged secret key has %d bytes\n", n);
    printf("[client] The exchanged secret key is: ");
    for(k=0; k<n; k++)
      printf("%02X", buf_secret_key[k]);
    printf("\n");

    

    DH_free(tdh);
    return 0;
}


