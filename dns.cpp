// ISA project 2019: DNS resolver
// Tomáš Zálešák
// xzales13
//
// Sources:     https://tools.ietf.org/html/rfc3596
//              https://tools.ietf.org/html/rfc1035
//              https://wis.fit.vutbr.cz/FIT/st/cfs.php?file=%2Fcourse%2FISA-IT%2Fexamples%2Fexamples.zip&cid=13349
//              - sending and receiving datagram
//              https://en.wikipedia.org/wiki/Reverse_DNS_lookup
//              - reverse lookup implementation
//              https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
//              - structs DNS_HEADER, QUESTION, R_DATA, RES_RECORD, QUERY
//              https://support.microsoft.com/sr-latn-me/help/831226/how-to-use-the-dnsquery-function-to-resolve-host-names-and-host-addres
//              - reverseIP function
//              https://stackoverflow.com/questions/784417/reversing-a-string-in-c/784538#784538
//              - reverse_string function

#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>

using namespace std;

// DNS header structure
struct DNS_HEADER {
    unsigned short id; // identification number

    unsigned char rd : 1;     // recursion desired
    unsigned char tc : 1;     // truncated message
    unsigned char aa : 1;     // authoritive answer
    unsigned char opcode : 4; // purpose of message
    unsigned char qr : 1;     // query/response flag

    unsigned char rcode : 4; // response code
    unsigned char cd : 1;    // checking disabled
    unsigned char ad : 1;    // authenticated data
    unsigned char z : 1;     // its z! reserved
    unsigned char ra : 1;    // recursion available

    unsigned short q_count;    // number of question entries
    unsigned short ans_count;  // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count;  // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION {
    unsigned short qtype;
    unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA {
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD {
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//Structure of a Query
typedef struct {
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

// Function prototypes
// parse and return args
void get_arguments(int argc,
                   char **argv,
                   int *help_flag,
                   int *recursion_flag,
                   int *reverse_query_flag,
                   int *AAAA_flag,
                   int *server_flag,
                   char **server,
                   int *port_flag,
                   int *port,
                   char **address);

// write help to stdout
void help();

// write msg to stderr and exit with code
void error_exit(int code, const char *msg);

// show arguments, for debugging purposes
void show_arguments(const int *help_flag,
                    const int *recursion_flag,
                    const int *reverse_query_flag,
                    const int *AAAA_flag,
                    const int *server_flag,
                    char **server,
                    const int *port_flag,
                    const int *port,
                    char **address);

// changes www.fit.vutbr.cz -> 3www3fit5vutbr2cz0
void change_hostname_to_dns_query_name(char *query_name, char **address);

// reverses ipv4
void reverse_IP(char *pIP);

// reverses string
void reverse_string(char *str);

// returns dns name from response, count will carry the number of bytes of the name
u_char *read_raw_name(unsigned char *reader, unsigned char *buffer, int *count);

// qtype int to string representation
const char *type2char(int type);

// retruns parsed query name from dns format in a query
unsigned char *change_query_name_to_hostname(unsigned char *name);

int main(int argc, char *argv[]) {
    // argument values
    int help_flag = 0;
    int recursion_flag = 0;
    int reverse_query_flag = 0;
    int AAAA_flag = 0;
    int server_flag = 0;
    char *server;
    int port_flag = 0;
    int port = 0;
    char *address;

    // intialize args
    get_arguments(argc,
                  argv,
                  &help_flag,
                  &recursion_flag,
                  &reverse_query_flag,
                  &AAAA_flag,
                  &server_flag,
                  &server,
                  &port_flag,
                  &port,
                  &address);

    if (help_flag)
        help();
    if (!port_flag)
        port = 53;

    struct sockaddr_in server_address {};
    struct hostent *server_entity;

    memset(&server_address, 0, sizeof(server_address));

    // get ip address of dns server
    if ((server_entity = gethostbyname(server)) == nullptr)
        error_exit(EXIT_FAILURE, "gethostbyname() failed\n");

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);

    memcpy(&server_address.sin_addr, server_entity->h_addr, server_entity->h_length);

    char str[INET_ADDRSTRLEN];

    // get string represenattion of server address to str
    inet_ntop(AF_INET, &(server_address.sin_addr), str, INET_ADDRSTRLEN);

    // create socket
    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0)
        error_exit(EXIT_FAILURE, "Cannot create socket");

    // dns query setup and fill it according to DNS documentation
    char query[255];
    int query_len;

    struct DNS_HEADER dns_header {};

    char query_name[255];
    int index_after_query_name;

    unsigned short query_type;
    unsigned short query_class;

    if (AAAA_flag)
        query_type = htons(28); // ipv6 type
    else if (reverse_query_flag)
        query_type = htons(12); // PTR type
    else
        query_type = htons(1); // A type

    query_class = htons(1); // internet

    dns_header.id = (unsigned short) htons(getpid());
    dns_header.qr = 0;
    dns_header.opcode = 0;
    dns_header.aa = 0;
    dns_header.tc = 0;
    if (recursion_flag) {
        dns_header.rd = 1;
    } else
        dns_header.rd = 0;
    dns_header.ra = 0;
    dns_header.z = 0;
    dns_header.ad = 0;
    dns_header.cd = 0;
    dns_header.rcode = 0;
    dns_header.q_count = htons(1);
    dns_header.ans_count = 0;
    dns_header.auth_count = 0;
    dns_header.add_count = 0;

    // set empty string of query name
    memset(query_name, '\0', 255);

    if (reverse_query_flag) {
        // IPv4 dns query name setup
        if (strchr(address, '.') != nullptr) {
            char buf[255];
            int ret_func_val;
            ret_func_val = inet_pton(AF_INET, address, &buf);
            if (ret_func_val < 1)
                error_exit(EXIT_FAILURE, "Wrong IPv4 address");

            char reversed_ip[255];
            strcpy(reversed_ip, address);
            reverse_IP(reversed_ip);
            char *p = &reversed_ip[0];
            change_hostname_to_dns_query_name(query_name, &p);
        }
            // IPv6 dns query name setup
        else if (strchr(address, ':') != nullptr) {
            unsigned char addr[16];
            int ret_func_val;
            // check ipv6 address
            ret_func_val = inet_pton(AF_INET6, address, &addr);
            if (ret_func_val < 1)
                error_exit(EXIT_FAILURE, "Wrong IPv6 address");

            // get long version of ipv6
            char long_ipv6[40];
            sprintf(long_ipv6, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    (int) addr[0], (int) addr[1],
                    (int) addr[2], (int) addr[3],
                    (int) addr[4], (int) addr[5],
                    (int) addr[6], (int) addr[7],
                    (int) addr[8], (int) addr[9],
                    (int) addr[10], (int) addr[11],
                    (int) addr[12], (int) addr[13],
                    (int) addr[14], (int) addr[15]);

            // reverse and add .ip6.arpa
            char reversed_ip_6[255];
            reverse_string(long_ipv6);
            sprintf(reversed_ip_6,
                    "%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.IP6.ARPA",
                    long_ipv6[0], long_ipv6[1], long_ipv6[2], long_ipv6[3], long_ipv6[5], long_ipv6[6], long_ipv6[7],
                    long_ipv6[8],
                    long_ipv6[10], long_ipv6[11], long_ipv6[12], long_ipv6[13], long_ipv6[15], long_ipv6[16],
                    long_ipv6[17], long_ipv6[18],
                    long_ipv6[20], long_ipv6[21], long_ipv6[22], long_ipv6[23], long_ipv6[25], long_ipv6[26],
                    long_ipv6[27], long_ipv6[28],
                    long_ipv6[30], long_ipv6[31], long_ipv6[32], long_ipv6[33], long_ipv6[35], long_ipv6[36],
                    long_ipv6[37], long_ipv6[38]);

            char *p = &reversed_ip_6[0];
            change_hostname_to_dns_query_name(query_name, &p);
        } else {
            error_exit(EXIT_FAILURE, "Expected IPv4 or IPv6");
        }
    } else {
        change_hostname_to_dns_query_name(query_name, &address);
    }

    // count index where to continue in putting data
    index_after_query_name = 12 + strlen(query_name) + 1;

    query_len = index_after_query_name + 4;
    memset(query, '\0', query_len);

    // copy data to query
    memcpy(query, &dns_header, 12);
    memcpy(&query[12], &query_name, strlen(query_name) + 1);
    memcpy(&query[index_after_query_name], &query_type, 2);
    memcpy(&query[index_after_query_name + 2], &query_class, 2);

    // send datagram to dns server
    int returned_value;
    returned_value = sendto(socket_fd, query, query_len, 0, (struct sockaddr *) &server_address,
                            sizeof(server_address));
    if (returned_value < 0)
        error_exit(EXIT_FAILURE, "Cannot send query");

    // set max time to wait for the response datagram
    struct timeval timeout {};
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    returned_value = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof timeout);
    if (returned_value < 0)
        error_exit(EXIT_FAILURE, "Timeout could not be set");

    // receive response or exit
    unsigned char response[65536];
    socklen_t response_length;
    returned_value = recvfrom(socket_fd, response, sizeof(response), 0, (struct sockaddr *) &server_address,
                              &response_length);
    if (returned_value < 0)
        error_exit(EXIT_FAILURE, "Receive error");

    struct DNS_HEADER *dns_response = nullptr;
    dns_response = (struct DNS_HEADER *) response;

    // check response code for errors
    if (ntohs(dns_response->rcode) == 1) {
        error_exit(EXIT_FAILURE, "Format error");
    } else if (ntohs(dns_response->rcode) == 2) {
        error_exit(EXIT_FAILURE, "Server failure");
    } else if (ntohs(dns_response->rcode) == 3) {
        error_exit(EXIT_FAILURE, "Name Error");
    } else if (ntohs(dns_response->rcode) == 4) {
        error_exit(EXIT_FAILURE, "Not Implemented");
    } else if (ntohs(dns_response->rcode) == 5) {
        error_exit(EXIT_FAILURE, "Refused");
    }

    // print dns query info
    if (dns_response->aa)
        printf("Authoritative: Yes, ");
    else
        printf("Authoritative: No, ");
    if (dns_response->ra && dns_response->rd)
        printf("Recursive: Yes, ");
    else
        printf("Recursive: No, ");
    if (dns_response->tc)
        printf("Truncated: Yes\n");
    else
        printf("Truncated: No\n");

    // pointer to the last read data in response
    unsigned char *reader;
    int stop = 0;
    struct RES_RECORD answer {};

    // print question section
    printf("Question section (%d)\n", ntohs(dns_response->q_count));
    reader = &response[sizeof(struct DNS_HEADER)];
    answer.name = read_raw_name(reader, response, &stop);

    reader = reader + stop;
    unsigned short s;
    memcpy(&s, reader, 2);
    const char *c = type2char(s);

    printf("  %s, ", change_query_name_to_hostname(answer.name));
    string namestr = reinterpret_cast<const char *>(change_query_name_to_hostname(answer.name));

    printf("%s, ", c);
    reader += 2;
    printf("IN\n");
    reader += 2;

    stop = 0; // counter of bytes to skip
    // print answer section
    printf("Answer section (%d)\n", ntohs(dns_response->ans_count));
    for (int i = 0; i < ntohs(dns_response->ans_count); i++) {
        stop = 0;
        answer.name = read_raw_name(reader, response, &stop);
        printf("  %s, ", change_query_name_to_hostname(answer.name));
        reader = reader + stop;

        unsigned short s1;
        memcpy(&s1, reader, 2);
        const char *c1 = type2char(s1);
        printf("%s, ", c1);
        reader += 2;

        printf("IN, ");
        reader += 2;

        u_int32_t s2;
        memcpy(&s2, reader, 4);
        printf("%d, ", ntohl(s2));
        reader = reader + 4;

        u_int16_t s3;
        memcpy(&s3, reader, 2);
        s3 = ntohs(s3);
        printf("%d, ", s3);
        reader = reader + 2;

        if (strcmp(c1, "A") == 0) {
            struct in_addr ipv4
                    {
                    };
            char type_A_string[INET_ADDRSTRLEN];
            memcpy(&ipv4, reader, 4);
            inet_ntop(AF_INET, &ipv4, type_A_string, INET_ADDRSTRLEN);
            printf("%s", type_A_string);
            reader = reader + 4;
        } else if (strcmp(c1, "AAAA") == 0) {
            struct in6_addr ipv6
                    {
                    };
            char type_AAAA_string[INET6_ADDRSTRLEN];
            memcpy(&ipv6, reader, 16);
            inet_ntop(AF_INET6, &ipv6, type_AAAA_string, INET6_ADDRSTRLEN);
            printf("%s", type_AAAA_string);
            reader = reader + 16;
        } else {
            answer.name = read_raw_name(reader, response, &stop);
            printf("%s", change_query_name_to_hostname(answer.name));
            reader = reader + stop;
        }
        printf("\n");
    }

    // print authority section
    printf("Authority section (%d)\n", ntohs(dns_response->auth_count));
    for (int i = 0; i < ntohs(dns_response->auth_count); i++) {
        stop = 0;
        answer.name = read_raw_name(reader, response, &stop);
        printf("  %s, ", change_query_name_to_hostname(answer.name));
        reader = reader + stop;

        unsigned short s1;
        memcpy(&s1, reader, 2);
        const char *c1 = type2char(s1);
        printf("%s, ", c1);
        reader += 2;

        printf("IN, ");
        reader += 2;

        u_int32_t s2;
        memcpy(&s2, reader, 4);
        printf("%d, ", ntohl(s2));
        reader = reader + 4;

        u_int16_t s3;
        memcpy(&s3, reader, 2);
        s3 = ntohs(s3);
        printf("%d, ", s3);
        reader = reader + 2;

        if (strcmp(c1, "A") == 0) {
            struct in_addr ipv4
                    {
                    };
            char type_A_string[INET_ADDRSTRLEN];
            memcpy(&ipv4, reader, 4);
            inet_ntop(AF_INET, &ipv4, type_A_string, INET_ADDRSTRLEN);
            printf("%s", type_A_string);
            reader = reader + 4;
        } else if (strcmp(c1, "AAAA") == 0) {
            struct in6_addr ipv6
                    {
                    };
            char type_AAAA_string[INET6_ADDRSTRLEN];
            memcpy(&ipv6, reader, 16);
            inet_ntop(AF_INET6, &ipv6, type_AAAA_string, INET6_ADDRSTRLEN);
            printf("%s", type_AAAA_string);
            reader = reader + 16;
        } else {
            answer.name = read_raw_name(reader, response, &stop);
            printf("%s", change_query_name_to_hostname(answer.name));
            reader = reader + stop;
        }
        printf("\n");
    }

    // print additional section
    printf("Additional section (%d)\n", ntohs(dns_response->add_count));
    for (int i = 0; i < ntohs(dns_response->add_count); i++) {
        stop = 0;
        answer.name = read_raw_name(reader, response, &stop);
        printf("  %s, ", change_query_name_to_hostname(answer.name));
        reader = reader + stop;

        unsigned short s1;
        memcpy(&s1, reader, 2);
        const char *c1 = type2char(s1);
        printf("%s, ", c1);
        reader += 2;

        printf("IN, ");
        reader += 2;

        u_int32_t s2;
        memcpy(&s2, reader, 4);
        printf("%d, ", ntohl(s2));
        reader = reader + 4;

        u_int16_t s3;
        memcpy(&s3, reader, 2);
        s3 = ntohs(s3);
        printf("%d, ", s3);
        reader = reader + 2;

        if (strcmp(c1, "A") == 0) {
            struct in_addr ipv4
                    {
                    };
            char type_A_string[INET_ADDRSTRLEN];
            memcpy(&ipv4, reader, 4);
            inet_ntop(AF_INET, &ipv4, type_A_string, INET_ADDRSTRLEN);
            printf("%s", type_A_string);
            reader = reader + 4;
        } else if (strcmp(c1, "AAAA") == 0) {
            struct in6_addr ipv6
                    {
                    };
            char type_AAAA_string[INET6_ADDRSTRLEN];
            memcpy(&ipv6, reader, 16);
            inet_ntop(AF_INET6, &ipv6, type_AAAA_string, INET6_ADDRSTRLEN);
            printf("%s", type_AAAA_string);
            reader = reader + 16;
        } else {
            answer.name = read_raw_name(reader, response, &stop);
            printf("%s", change_query_name_to_hostname(answer.name));
            reader = reader + stop;
        }
        printf("\n");
    }
    exit(EXIT_SUCCESS);
}

void get_arguments(int argc,
                   char **argv,
                   int *help_flag,
                   int *recursion_flag,
                   int *reverse_query_flag,
                   int *AAAA_flag,
                   int *server_flag,
                   char **server,
                   int *port_flag,
                   int *port,
                   char **address) {
    if ((argc == 2) && (strcmp(argv[1], "-h") == 0)) {
        help();
    }
    if (argc < 4) {
        help();
        error_exit(EXIT_FAILURE, "Too few arguments");
    }
    if (argc > 9) {
        help();
        error_exit(EXIT_FAILURE, "Too many arguments");
    }

    *address = argv[argc - 1];

    int c;
    while ((c = getopt(argc, argv, "hrx6s:p:")) != -1) {
        switch (c) {
            case 'h':
                *help_flag = 1;
                break;
            case 's':
                *server_flag = 1;
                *server = optarg;
                break;
            case 'r':
                *recursion_flag = 1;
                break;
            case 'x':
                *reverse_query_flag = 1;
                break;
            case '6':
                *AAAA_flag = 1;
                break;
            case 'p':
                *port_flag = 1;
                try {
                    *port = stoi(optarg);
                }
                catch (...) {
                    error_exit(EXIT_FAILURE, "Cannot parse port number");
                }
                break;
            default:
                help();
                error_exit(EXIT_FAILURE, "Wrong arguments");
                break;
        }
    }
}

void help() {
    cout << "Použití: dns [-r] [-x] [-6] -s server [-p port] adresa\n";
    cout << "   -r: Požadována rekurze (Recursion Desired = 1)\n";
    cout << "   -x: Reverzní dotaz místo přímého.\n";
    cout << "   -6: Dotaz typu AAAA místo výchozího A.\n";
    cout << "   -s: IP adresa nebo doménové jméno serveru, kam se má zaslat dotaz.\n";
    cout << "   -p port: Číslo portu, na který se má poslat dotaz, výchozí 53.\n";
    exit(EXIT_SUCCESS);
}

void error_exit(int code, const char *msg) {
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(code);
}

void show_arguments(const int *help_flag,
                    const int *recursion_flag,
                    const int *reverse_query_flag,
                    const int *AAAA_flag,
                    const int *server_flag,
                    char **server,
                    const int *port_flag,
                    const int *port,
                    char **address) {
    cout << "help_flag              " << *help_flag << "\n";
    cout << "recursion_flag         " << *recursion_flag << "\n";
    cout << "reverse_query_flag     " << *reverse_query_flag << "\n";
    cout << "AAAA_flag              " << *AAAA_flag << "\n";
    cout << "server_flag            " << *server_flag << "\n";
    cout << "server                 " << *server << "\n";
    cout << "port_flag              " << *port_flag << "\n";
    cout << "port                   " << *port << "\n";
    cout << "address                " << *address << "\n";
}

void change_hostname_to_dns_query_name(char *query_name, char **address) {
    unsigned int previous_index = 0;
    int length;

    strcpy(&query_name[1], *address);

    while ((length = strcspn(&query_name[previous_index + 1], ".")) != 0) {
        query_name[previous_index] = length;
        previous_index = previous_index + length + 1;
    }
    if (strlen(*address) != previous_index - 1)
        query_name[previous_index] = 0;
}

// https://support.microsoft.com/sr-latn-me/help/831226/how-to-use-the-dnsquery-function-to-resolve-host-names-and-host-addres
void reverse_IP(char *pIP) {
    char seps[] = ".";
    char *token;
    char pIPSec[4][4];
    int i = 0;
    token = strtok(pIP, seps);
    while (token != nullptr) {
        /* While there are "." characters in "string" */
        sprintf(pIPSec[i], "%s", token);
        /* Get next "." character: */
        token = strtok(nullptr, seps);
        i++;
    }
    sprintf(pIP, "%s.%s.%s.%s.%s", pIPSec[3], pIPSec[2], pIPSec[1], pIPSec[0], "IN-ADDR.ARPA");
}

// https://stackoverflow.com/questions/784417/reversing-a-string-in-c/784538#784538
void reverse_string(char *str) {
    /* skip null */
    if (str == 0) {
        return;
    }

    /* skip empty string */
    if (*str == 0) {
        return;
    }

    /* get range */
    char *start = str;
    char *end = start + strlen(str) - 1; /* -1 for \0 */
    char temp;

    /* reverse */
    while (end > start) {
        /* swap */
        temp = *start;
        *start = *end;
        *end = temp;

        /* move */
        ++start;
        --end;
    }
}

// source https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168 [few changes from original]
u_char *read_raw_name(unsigned char *reader, unsigned char *buffer, int *count) {
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;

    *count = 1;
    name = (unsigned char *) malloc(256);

    name[0] = '\0';

    //read dns raw names
    while (*reader != 0) {
        if (*reader >= 192) {
            offset = (*reader) * 256 + *(reader + 1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        } else {
            name[p++] = *reader;
        }

        reader = reader + 1;

        if (jumped == 0) {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }

    name[p] = '\0'; //string complete
    if (jumped == 1) {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    return name;
}

const char *type2char(int type) {
    type = ntohs(type);
    switch (type) {
        case 1:
            return "A";
        case 2:
            return "NS";
        case 3:
            return "MD";
        case 4:
            return "MF";
        case 5:
            return "CNAME";
        case 6:
            return "SOA";
        case 7:
            return "MB";
        case 8:
            return "MG";
        case 9:
            return "MR";
        case 10:
            return "NULL";
        case 11:
            return "WKS";
        case 12:
            return "PTR";
        case 13:
            return "HINFO";
        case 14:
            return "MINFO";
        case 15:
            return "MX";
        case 16:
            return "TXT";
        case 28:
            return "AAAA";
        default:
            return NULL;
    }
}

unsigned char *change_query_name_to_hostname(unsigned char *name) {
    unsigned int p;
    for (int i = 0; i < (int) strlen((const char *) name); i++) {
        p = name[i];
        for (int j = 0; j < (int) p; j++) {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    return name;
}
