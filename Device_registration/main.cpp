#define HAVE_ECC
#define WOLFSSL_DER_TO_PEM
// #define HAVE_ECC_KOBLITZ
#define MAX_CERT_SIZE 4096
#define TEST_ECC_KEY_SZ 32
#ifdef HAVE_ECC_KOBLITZ
#define TEST_ECC_KEY_CURVE ECC_SECP256K1
#else
#define TEST_ECC_KEY_CURVE ECC_SECP256R1
#endif

#define XSTRINGIFY(a) STRINGIFY(a)
#define STRINGIFY(a) #a

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

class HttpsConnector
{
public:
    int tlsConnect(const char *hostAddr, int hostPort);
};

int HttpsConnector::tlsConnect(const char *hostAddr, int hostPort)
{
    struct sockaddr_in serv_addr;
    struct hostent *server;
    int sockfd;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        herror("ERROR opening socket");
    }
    else
    {
        server = gethostbyname(hostAddr);
        if (server == NULL)
        {
            fprintf(stderr, "ERROR, no such host\n");
            exit(0);
        }
        else
        {
            bzero((char *)&serv_addr, sizeof(serv_addr));
            serv_addr.sin_family = AF_INET;
            bcopy((char *)server->h_addr,
                  (char *)&serv_addr.sin_addr.s_addr,
                  server->h_length);
            serv_addr.sin_port = htons(hostPort);
            if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
                herror("ERROR connecting");
        }
    }
    printf("Connect socket success.\n");
    return sockfd;
}

class CertManager
{
public:
    int genKey(ecc_key &key);
    void makeCsr();
    int storeKey_PEM(ecc_key &key);
    int storePubKey_PEM(ecc_key &key);
};

int CertManager::genKey(ecc_key &key)
{
    WC_RNG rng;
    int ret;
    // wolfSSL_Debugging_ON();
    ret = wolfCrypt_Init();
    if (ret != 0)
    {
        printf("wolfCrypt_Init error %s (%d)\n", wc_GetErrorString(ret), ret);
        return -1;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0)
    {
        printf("wc_InitRng error %s (%d)\n", wc_GetErrorString(ret), ret);
        return -1;
    }

    ret = wc_ecc_init(&key);
    if (ret != 0)
    {
        printf("wc_ecc_init error %s (%d)\n", wc_GetErrorString(ret), ret);
        return -1;
    }

    ret = wc_ecc_make_key_ex(&rng, TEST_ECC_KEY_SZ, &key, TEST_ECC_KEY_CURVE);
    if (ret != 0)
    {
        printf("wc_ecc_make_key_ex error %s (%d)\n", wc_GetErrorString(ret), ret);
        return -1;
    }
    printf("ECC Key Generated: %d bits, curve %s\n", TEST_ECC_KEY_SZ * 8, XSTRINGIFY(TEST_ECC_KEY_CURVE));
    wc_FreeRng(&rng);
    return 0;
}
int CertManager::storeKey_PEM(ecc_key &key)
{
    int ret;
    byte der[MAX_CERT_SIZE];
    word32 derSz;
    byte pem[MAX_CERT_SIZE];
    word32 pemSz;
    memset(der, 0, sizeof(der));
    FILE *fp;
    ret = wc_EccKeyToDer(&key, der, sizeof(der));
    if (ret < 0)
    {
        printf("wc_EccKeyToDer error %s (%d)\n", wc_GetErrorString(ret), ret);
        return -1;
    }
    derSz = ret;
    memset(pem, 0, sizeof(pem));
    ret = wc_DerToPem(der, derSz, pem, sizeof(pem), ECC_PRIVATEKEY_TYPE);
    if (ret < 0)
    {
        printf("wc_DerToPem error %s (%d)\n", wc_GetErrorString(ret), ret);
        return -1;
    }
    pemSz = ret;
    fp = fopen("./" XSTRINGIFY(TEST_ECC_KEY_CURVE) ".pem", "wb");
    if (!fp)
    {
        printf("Error openening %s for write\n",
               "./" XSTRINGIFY(TEST_ECC_KEY_CURVE) ".pem");
        return -1;
    }
    fwrite(pem, pemSz, 1, fp);
    fclose(fp);
    return 0;
};
int CertManager::storePubKey_PEM(ecc_key &key)
{
    int ret;
    byte der[MAX_CERT_SIZE];
    word32 derSz;
    byte pem[MAX_CERT_SIZE];
    word32 pemSz;
    FILE *fp;
    //Extract publickey
    memset(der, 0, sizeof(der));
    ret = wc_EccPublicKeyToDer(&key, der, sizeof(der), TEST_ECC_KEY_CURVE);
    if (ret < 0)
    {
        printf("wc_EccPublicKeyToDer error %s (%d)\n", wc_GetErrorString(ret), ret);
        return -1;
    }
    derSz = ret;
    memset(pem, 0, sizeof(pem));
    ret = wc_DerToPem(der, derSz, pem, sizeof(pem), ECC_PUBLICKEY_TYPE);
    if (ret < 0)
    {
        /* try old type */
        ret = wc_DerToPem(der, derSz, pem, sizeof(pem), PUBLICKEY_TYPE);
    }
    if (ret < 0)
    {
        printf("wc_DerToPem error %s (%d)\n", wc_GetErrorString(ret), ret);
        return -1;
    }
    pemSz = ret;
    fp = fopen("./" XSTRINGIFY(TEST_ECC_KEY_CURVE) "_pub.pem", "wb");
    if (!fp)
    {
        printf("Error openening %s for write\n",
               "./" XSTRINGIFY(TEST_ECC_KEY_CURVE) "_pub.pem");
        return -1;
    }
    fwrite(pem, pemSz, 1, fp);
    fclose(fp);
    printf("ECC Public Key Exported to %s\n",
           "./" XSTRINGIFY(TEST_ECC_KEY_CURVE) "_pub.pem");
    return 0;
};

int main()
{
    CertManager cert;
    HttpsConnector https;
    ecc_key key;
    int sockfd;
    char buffer[100] = "GET / HTTP/1.1\r\n\r\n";
    //generate keypair and store in to key
    cert.genKey(key);
    cert.storeKey_PEM(key);
    cert.storePubKey_PEM(key);
    sockfd = https.tlsConnect("127.0.0.1", 3000);
    int n = write(sockfd, buffer, strlen(buffer));
    printf("Number of bytes write to socket: %i\n",n);
    if (n < 0)
        herror("ERROR writing to socket");
    close(sockfd);
    sockfd = https.tlsConnect("127.0.0.1", 3000);
    n = write(sockfd, buffer, strlen(buffer));
    printf("Number of bytes write to socket: %i\n",n);
    if (n < 0)
        herror("ERROR writing to socket");
    close(sockfd);
    wc_ecc_free(&key);
    wolfCrypt_Cleanup();
    return 0;
};