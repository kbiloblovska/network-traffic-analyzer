#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>

#include "../include/application.h"

//helpers
static void print_hex_preview(
    const u_char *data,
    bpf_u_int32 length
) {
    const bpf_u_int32 max_preview = 32;

    bpf_u_int32 bytes_to_print = length;

    if (bytes_to_print > max_preview) {
        bytes_to_print = max_preview;
    }

    printf("Payload Preview  : ");

    for (bpf_u_int32 i = 0; i < bytes_to_print; i++) {
        printf("%02X ", data[i]);
    }

    if (length > max_preview) {
        printf("...");
    }

    printf("\n");
}

static int starts_with(
    const u_char *payload,
    bpf_u_int32 payload_length,
    const char *text
) {
    size_t text_length = strlen(text);

    if (payload_length < text_length) {
        return 0;
    }

    return memcmp(
        payload,
        text,
        text_length
    ) == 0;
}

//HTTP
static int is_http_request(
    const u_char *payload,
    bpf_u_int32 payload_length
) {
    static const char *methods[] = {
        "GET ",
        "POST ",
        "HEAD ",
        "PUT ",
        "DELETE ",
        "OPTIONS ",
        "PATCH ",
        "CONNECT ",
        "TRACE "
    };

    size_t method_count =
        sizeof(methods) / sizeof(methods[0]);

    for (size_t i = 0; i < method_count; i++) {
        if (starts_with(
                payload,
                payload_length,
                methods[i]
            )) {
            return 1;
        }
    }

    return 0;
}


static int is_http_response(
    const u_char *payload,
    bpf_u_int32 payload_length
) {
    if (starts_with(
            payload,
            payload_length,
            "HTTP/1.0"
        )) {
        return 1;
    }

    if (starts_with(
            payload,
            payload_length,
            "HTTP/1.1"
        )) {
        return 1;
    }

    if (starts_with(
            payload,
            payload_length,
            "HTTP/2"
        )) {
        return 1;
    }

    return 0;
}


//TLS
static int is_tls(
    const u_char *payload,
    bpf_u_int32 payload_length
) {
    if (payload_length < 3) {
        return 0;
    }

    /*
     * TLS record content types:
     *
     * 20 = Change Cipher Spec
     * 21 = Alert
     * 22 = Handshake
     * 23 = Application Data
     */

    uint8_t content_type = payload[0];

    if (content_type < 20 || content_type > 23) {
        return 0;
    }

    uint8_t major_version = payload[1];

    if (major_version != 3) {
        return 0;
    }

    return 1;
}

//DNS
static int is_probably_dns(
    const u_char *payload,
    bpf_u_int32 payload_length,
    uint16_t source_port,
    uint16_t destination_port
) {
    if (payload_length < 12) {
        return 0;
    }

    if (source_port != 53 &&
        destination_port != 53) {
        return 0;
    }

    /*
     * DNS header:
     *
     * 0-1   Transaction ID
     * 2-3   Flags
     * 4-5   Questions
     * 6-7   Answer RRs
     * 8-9   Authority RRs
     * 10-11 Additional RRs
     */

    return 1;
}

static void print_dns_info(
    const u_char *payload,
    bpf_u_int32 payload_length
) {
    if (payload_length < 12) {
        return;
    }

    uint16_t transaction_id =
        ((uint16_t)payload[0] << 8) |
        payload[1];

    uint16_t flags =
        ((uint16_t)payload[2] << 8) |
        payload[3];

    uint16_t questions =
        ((uint16_t)payload[4] << 8) |
        payload[5];

    uint16_t answers =
        ((uint16_t)payload[6] << 8) |
        payload[7];

    uint16_t authority =
        ((uint16_t)payload[8] << 8) |
        payload[9];

    uint16_t additional =
        ((uint16_t)payload[10] << 8) |
        payload[11];

    printf("Transaction ID   : 0x%04X\n",
           transaction_id);

    printf("Flags            : 0x%04X\n",
           flags);

    printf("Questions        : %u\n",
           questions);

    printf("Answers          : %u\n",
           answers);

    printf("Authority RRs    : %u\n",
           authority);

    printf("Additional RRs   : %u\n",
           additional);
}

void analyze_application_tcp(
    const u_char *payload,
    bpf_u_int32 payload_length,
    uint16_t source_port,
    uint16_t destination_port
) {
    if (payload == NULL || payload_length == 0) {
        return;
    }

    printf("\n");
    printf("Application\n");
    printf("----------------------------------------\n");

    printf("Payload Length   : %u bytes\n",
           payload_length);

    if (is_http_request(
            payload,
            payload_length
        )) {

        printf("Protocol         : HTTP\n");
        printf("Type             : Request\n");

        if (starts_with(
                payload,
                payload_length,
                "GET "
            )) {
            printf("Method           : GET\n");
        }
        else if (starts_with(
                    payload,
                    payload_length,
                    "POST "
                )) {
            printf("Method           : POST\n");
        }
        else if (starts_with(
                    payload,
                    payload_length,
                    "HEAD "
                )) {
            printf("Method           : HEAD\n");
        }
        else if (starts_with(
                    payload,
                    payload_length,
                    "PUT "
                )) {
            printf("Method           : PUT\n");
        }
        else if (starts_with(
                    payload,
                    payload_length,
                    "DELETE "
                )) {
            printf("Method           : DELETE\n");
        }
        else if (starts_with(
                    payload,
                    payload_length,
                    "OPTIONS "
                )) {
            printf("Method           : OPTIONS\n");
        }
        else if (starts_with(
                    payload,
                    payload_length,
                    "PATCH "
                )) {
            printf("Method           : PATCH\n");
        }
        else if (starts_with(
                    payload,
                    payload_length,
                    "CONNECT "
                )) {
            printf("Method           : CONNECT\n");
        }
        else if (starts_with(
                    payload,
                    payload_length,
                    "TRACE "
                )) {
            printf("Method           : TRACE\n");
        }

        print_hex_preview(payload, payload_length);

        return;
    }

    if (is_http_response(
            payload,
            payload_length
        )) {

        printf("Protocol         : HTTP\n");
        printf("Type             : Response\n");

        print_hex_preview(payload, payload_length);

        return;
    }

    if (is_tls(
            payload,
            payload_length
        )) {

        printf("Protocol         : TLS\n");
        printf("Encrypted data   : Yes\n");

        print_hex_preview(payload, payload_length);

        return;
    }

    printf("Protocol         : Unknown\n");

    print_hex_preview(payload, payload_length);
}

void analyze_application_udp(
    const u_char *payload,
    bpf_u_int32 payload_length,
    uint16_t source_port,
    uint16_t destination_port
) {
    if (payload == NULL || payload_length == 0) {
        return;
    }

    printf("\n");
    printf("Application\n");
    printf("----------------------------------------\n");

    printf("Payload Length   : %u bytes\n",
           payload_length);

    if (is_probably_dns(
            payload,
            payload_length,
            source_port,
            destination_port
        )) {

        printf("Protocol         : DNS\n");

        print_dns_info(
            payload,
            payload_length
        );

        print_hex_preview(
            payload,
            payload_length
        );

        return;
    }

    printf("Protocol         : Unknown\n");

    print_hex_preview(
        payload,
        payload_length
    );
}