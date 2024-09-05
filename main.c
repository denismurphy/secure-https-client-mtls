#include "main.h"
#include "certs.h"

int main(void)
{
    int result = 1;

    TLSContext context;

    // Initialise the PSA Crypto library
    psa_status_t psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        printf("Failed to initialise PSA Crypto: %d\n", (int)psa_status);
        return EXIT_FAILURE;
    }

    // Initialise the TLS context
    if ((result = initialise_context(&context)) != 0)
        goto exit;

    // Set up certificates and keys
    if ((result = setup_certificates(&context)) != 0)
        goto exit;

    // Set up the network connection and SSL configuration
    if ((result = setup_connection(&context)) != 0)
        goto exit;

    // Perform the SSL/TLS handshake
    if ((result = perform_handshake(&context)) != 0)
        goto exit;

    // Exchange data with the server
    result = exchange_data(&context);

exit:
    // Clean up and free resources
    cleanup(&context);
    return (result == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

// Custom debug function to output debug information
static void my_debug(void *context, int level, const char *file, int line, const char *str)
{
    ((void) level);
    fprintf((FILE *)context, "%s:%04d: %s", file, line, str);
    fflush((FILE *)context);
}

// Initialise the TLS context and seed the random number generator
static int initialise_context(TLSContext *context)
{
    const char *pers = "mbed TLS client";

    // Initialise MbedTLS structures
    mbedtls_net_init(&context->server_file_descriptor);
    mbedtls_ssl_init(&context->ssl);
    mbedtls_ssl_config_init(&context->conf);
    mbedtls_x509_crt_init(&context->ca_cert);
    mbedtls_x509_crt_init(&context->client_cert);
    mbedtls_pk_init(&context->private_key);
    mbedtls_ctr_drbg_init(&context->ctr_drbg);
    mbedtls_entropy_init(&context->entropy);

    // Set debug threshold
    mbedtls_debug_set_threshold(DEBUG_LEVEL);

    printf("\nSeeding the random number generator... ");
    // Seed the random number generator
    int result = mbedtls_ctr_drbg_seed(&context->ctr_drbg, mbedtls_entropy_func, &context->entropy,
                               (const unsigned char *) pers, strlen(pers));
    if (result != 0) {
        printf("failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", result);
        return result;
    }
    printf("ok\n");

    return 0;
}

// Load and parse certificates and private key
static int setup_certificates(TLSContext *context)
{
    int result;

    printf("Loading the CA root certificate ... ");
    // Parse CA certificate
    result = mbedtls_x509_crt_parse(&context->ca_cert, (const unsigned char *)ca_cert, strlen(ca_cert) + 1);
    if (result < 0) {
        printf("failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", (unsigned int) -result);
        return result;
    }
    printf("ok\n");

    printf("Loading the client certificate and private key ... ");
    // Parse client certificate
    result = mbedtls_x509_crt_parse(&context->client_cert, (const unsigned char *)client_cert, strlen(client_cert) + 1);
    if (result != 0) {
        printf("failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", (unsigned int) -result);
        return result;
    }

    // Parse client private key
    result = mbedtls_pk_parse_key(&context->private_key, (const unsigned char *)client_key, strlen(client_key) + 1,
                               NULL, 0, mbedtls_ctr_drbg_random, &context->ctr_drbg);
    if (result != 0) {
        printf("failed\n  !  mbedtls_pk_parse_key returned -0x%x\n\n", (unsigned int) -result);
        return result;
    }
    printf("ok\n");

    return 0;
}

// Set up the network connection and configure SSL settings
static int setup_connection(TLSContext *context)
{
    int result;

    printf("Connecting to %s on port %s... ", SERVER_NAME, SERVER_PORT);
    // Establish a TCP connection
    if ((result = mbedtls_net_connect(&context->server_file_descriptor, SERVER_NAME,
                                   SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        printf("failed\n  ! mbedtls_net_connect returned %d\n\n", result);
        return result;
    }
    printf("ok\n");

    printf("Setting up the SSL/TLS structure... ");
    // Set up SSL/TLS configuration
    if ((result = mbedtls_ssl_config_defaults(&context->conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf("failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", result);
        return result;
    }
    printf("ok\n");

    // Set up SSL/TLS settings
    mbedtls_ssl_conf_authmode(&context->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&context->conf, &context->ca_cert, NULL);
    mbedtls_ssl_conf_rng(&context->conf, mbedtls_ctr_drbg_random, &context->ctr_drbg);
    mbedtls_ssl_conf_dbg(&context->conf, my_debug, stdout);

    // Set client certificate and private key
    if ((result = mbedtls_ssl_conf_own_cert(&context->conf, &context->client_cert, &context->private_key)) != 0) {
        printf("failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", result);
        return result;
    }

    // Set up SSL context
    if ((result = mbedtls_ssl_setup(&context->ssl, &context->conf)) != 0) {
        printf("failed\n  ! mbedtls_ssl_setup returned %d\n\n", result);
        return result;
    }

    // Set hostname for SNI (Server Name Indication)
    if ((result = mbedtls_ssl_set_hostname(&context->ssl, SERVER_NAME)) != 0) {
        printf("failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", result);
        return result;
    }

    // Set up I/O functions for network communication
    mbedtls_ssl_set_bio(&context->ssl, &context->server_file_descriptor, mbedtls_net_send, mbedtls_net_recv, NULL);

    return 0;
}

// Perform the SSL/TLS handshake
static int perform_handshake(TLSContext *context)
{
    int result;

    printf("Performing the SSL/TLS handshake...\n");
    while ((result = mbedtls_ssl_handshake(&context->ssl)) != 0) {
        if (result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf("failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int) -result);
            return result;
        }
    }
    printf("ok\n");

    // Verify the server's certificate
    printf("Verifying peer X.509 certificate...");
    uint32_t flags = mbedtls_ssl_get_verify_result(&context->ssl);
    if (flags != 0) {
        char verifying_buffer[512];
        printf("\nVerification warnings... \n");
        mbedtls_x509_crt_verify_info(verifying_buffer, sizeof(verifying_buffer), "", flags);
        printf("%s\n", verifying_buffer);
    } else {
        printf("ok\n");
    }

    return 0;
}

static void print_text_content(const unsigned char *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if ((i + 1) % 8 == 0 || i + 1 == length) {

            // If we've printed 16 bytes, print the ASCII representation
            if ((i + 1) % 16 == 0) {

                // Print ASCII characters for the last 16 bytes
                for (size_t j = i - 15; j <= i; j++) {
                    if (isprint(buffer[j])) {
                        printf("%c", buffer[j]);  // Print printable characters
                    }
                    else {
                        printf(" ");  // Print space for non-printable characters
                    }
                }
            }
            // If we've reached the end of the buffer
            else if (i + 1 == length) {
                // Print ASCII characters for the last partial line
                for (size_t j = i - (i % 16); j <= i; j++) {
                    if (isprint(buffer[j])) {
                        printf("%c", buffer[j]);  // Print printable characters
                    } else {
                        printf(" ");  // Print dot for non-printable characters
                    }
                }
            }
        }
    }
}

static void print_hex_and_ascii(const unsigned char *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        // Print offset at the beginning of each line (every 16 bytes)
        if (i % 16 == 0) {
            printf("%04zx: ", i);
        }

        // Print the byte in hexadecimal format
        printf("%02x ", buffer[i]);

        // Add extra space after every 8 bytes for readability
        if ((i + 1) % 8 == 0 || i + 1 == length) {
            printf(" ");

            // If we've printed 16 bytes, print the ASCII representation
            if ((i + 1) % 16 == 0) {
                printf("|");
                // Print ASCII characters for the last 16 bytes
                for (size_t j = i - 15; j <= i; j++) {
                    if (isprint(buffer[j])) {
                        printf("%c", buffer[j]);  // Print printable characters
                    } else {
                        printf(".");  // Print dot for non-printable characters
                    }
                }
                printf("|\n");  // End the line after ASCII representation
            }
            // If we've reached the end of the buffer
            else if (i + 1 == length) {
                // Add extra space if we're in the first half of a 16-byte line
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }

                // Fill the rest of the line with spaces to align ASCII output
                for (size_t j = (i + 1) % 16; j < 16; j++) {
                    printf("   ");
                }

                printf("|");
                // Print ASCII characters for the last partial line
                for (size_t j = i - (i % 16); j <= i; j++) {
                    if (isprint(buffer[j])) {
                        printf("%c", buffer[j]);  // Print printable characters
                    } else {
                        printf(".");  // Print dot for non-printable characters
                    }
                }
                printf("|\n");  // End the last line
            }
        }
    }
}

// Exchange data with the server
static int exchange_data(TLSContext *context)
{
    int result, length;
    unsigned char buffer[1024];

    printf("> Write to %s \n", SERVER_NAME);

    print_text_content((const unsigned char *)GET_REQUEST, strlen(GET_REQUEST));
    printf("\n");

    result = mbedtls_ssl_write(&context->ssl, (const unsigned char *)GET_REQUEST, strlen(GET_REQUEST));
    if (result <= 0) {
        printf("failed\n  ! mbedtls_ssl_write returned %d\n\n", result);
        return result;
    }
    length = result;
    printf("%d bytes written\n", length);

    printf("< Read from %s \n", SERVER_NAME);
    do {
        length = sizeof(buffer) - 1;
        memset(buffer, 0, sizeof(buffer));
        result = mbedtls_ssl_read(&context->ssl, buffer, length);

        if (result > 0) {
            printf("Received %d bytes:\n", result);
            print_text_content(buffer, result);
            printf("\n");
        }

        if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            break;

        if (result < 0) {
            printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", result);
            return result;
        }

        if (result == 0) {
            printf("\n\nEOF\n\n");
            break;
        }

    } while (1);

    mbedtls_ssl_close_notify(&context->ssl);
    return 0;
}

// Clean up and free resources
static void cleanup(TLSContext *context)
{
    mbedtls_net_free(&context->server_file_descriptor);
    mbedtls_x509_crt_free(&context->ca_cert);
    mbedtls_x509_crt_free(&context->client_cert);
    mbedtls_pk_free(&context->private_key);
    mbedtls_ssl_free(&context->ssl);
    mbedtls_ssl_config_free(&context->conf);
    mbedtls_ctr_drbg_free(&context->ctr_drbg);
    mbedtls_entropy_free(&context->entropy);
}