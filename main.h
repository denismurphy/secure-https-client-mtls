#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

// MbedTLS headers
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// PSA Crypto header
#include "psa/crypto.h"

#define SERVER_NAME "www.example.com"
#define SERVER_PORT "443"
#define GET_HEADER "GET /mtls-endpoint?query=1 HTTP/1.1"
#define HOST_HEADER "Host: www.example.com"

#define GET_REQUEST GET_HEADER "\r\n" HOST_HEADER "\r\n\r\n"
#define DEBUG_LEVEL 1
#define MAX_RESPONSE_SIZE 200

// Structure to hold all the context variables for TLS communication
typedef struct {

    // Network socket
    mbedtls_net_context server_file_descriptor;

    // Entropy context for random number generation
    mbedtls_entropy_context entropy;

    // Deterministic Random Bit Generator
    // ctr = Counter
    // drbg = Deterministic Random Bit Generator.
    mbedtls_ctr_drbg_context ctr_drbg;

    // SSL context
    mbedtls_ssl_context ssl;

    // SSL configuration
    mbedtls_ssl_config conf;

    // CA certificate
    mbedtls_x509_crt ca_cert;

    // Client certificate
    mbedtls_x509_crt client_cert;

    // Private key context
    mbedtls_pk_context private_key;

} TLSContext;

// Function prototypes

/**
 * @brief Custom debug function to output debug information
 *
 * @param context Context (usually stdout)
 * @param level Debug level
 * @param file Source file where the debug message originated
 * @param line Line number in the source file
 * @param str Debug message
 */
static void my_debug(void *context, int level, const char *file, int line, const char *str);

/**
 * @brief Initialise the TLS context and seed the random number generator
 *
 * @param context Pointer to the TLSContext structure
 * @return int 0 on success, non-zero on failure
 */
static int initialise_context(TLSContext *context);

/**
 * @brief Load and parse certificates and private key
 *
 * @param context Pointer to the TLSContext structure
 * @return int 0 on success, non-zero on failure
 */
static int setup_certificates(TLSContext *context);

/**
 * @brief Set up the network connection and configure SSL settings
 *
 * @param context Pointer to the TLSContext structure
 * @return int 0 on success, non-zero on failure
 */
static int setup_connection(TLSContext *context);

/**
 * @brief Perform the SSL/TLS handshake
 *
 * @param context Pointer to the TLSContext structure
 * @return int 0 on success, non-zero on failure
 */
static int perform_handshake(TLSContext *context);

/**
 * @brief Exchange data with the server
 *
 * @param context Pointer to the TLSContext structure
 * @return int 0 on success, non-zero on failure
 */
static int exchange_data(TLSContext *context);

/**
 * @brief Clean up and free resources
 *
 * @param context Pointer to the TLSContext structure
 */
static void cleanup(TLSContext *context);

#endif //MAIN_H
