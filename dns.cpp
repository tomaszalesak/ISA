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
struct DNS_HEADER
{
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
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

// function prototypes
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
void help();
void error_exit(int code, const char *msg);
void show_arguments(const int *help_flag,
                    const int *recursion_flag,
                    const int *reverse_query_flag,
                    const int *AAAA_flag,
                    const int *server_flag,
                    char **server,
                    const int *port_flag,
                    const int *port,
                    char **address);
void change_hostname_to_dns_query_name(char *query_name, char **address);
void reverse_IP(char *pIP);
void reverse_string(char *str);
int get_name_from_response(char *name, unsigned char *response, unsigned char *dns_name, int query_len, int type);
u_char *ReadName(unsigned char *reader, unsigned char *buffer, int *count);

int main(int argc, char *argv[])
{
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

    // show_arguments(&help_flag,
    //                &recursion_flag,
    //                &reverse_query_flag,
    //                &AAAA_flag,
    //                &server_flag,
    //                &server,
    //                &port_flag,
    //                &port,
    //                &address);

    if (help_flag)
        help();
    if (!port_flag)
        port = 53;

    struct sockaddr_in server_address;
    struct hostent *server_entity;

    memset(&server_address, 0, sizeof(server_address));

    if ((server_entity = gethostbyname(server)) == nullptr)
        error_exit(EXIT_FAILURE, "gethostbyname() failed\n");

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);

    memcpy(&server_address.sin_addr, server_entity->h_addr, server_entity->h_length);

    char str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(server_address.sin_addr), str, INET_ADDRSTRLEN);

    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0)
        error_exit(EXIT_FAILURE, "Cannot create socket");

    char query[255];
    int query_len;

    struct DNS_HEADER dns_header;

    char query_name[255];
    int index_after_query_name;

    unsigned short query_type;
    unsigned short query_class;

    if (AAAA_flag)
        query_type = htons(28);
    else if (reverse_query_flag)
        query_type = htons(12);
    else
        query_type = htons(1);

    query_class = htons(1); // internet

    dns_header.id = (unsigned short)htons(getpid());
    dns_header.qr = 0;
    dns_header.opcode = 0;
    dns_header.aa = 0;
    dns_header.tc = 0;
    if (recursion_flag)
    {
        dns_header.rd = 1;
        //printf("r %d yes\n", dns_header.rd);
    }
    else
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

    memset(query_name, '\0', 255);
    int type = 0;

    if (reverse_query_flag)
    {
        // IPv4
        if (strchr(address, '.') != nullptr)
        {
            type = 4;
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
        // IPv6
        else if (strchr(address, ':') != nullptr)
        {
            type = 6;
            unsigned char addr[16];
            int ret_func_val;
            ret_func_val = inet_pton(AF_INET6, address, &addr);
            if (ret_func_val < 1)
                error_exit(EXIT_FAILURE, "Wrong IPv6 address");

            char str[40];
            sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    (int)addr[0], (int)addr[1],
                    (int)addr[2], (int)addr[3],
                    (int)addr[4], (int)addr[5],
                    (int)addr[6], (int)addr[7],
                    (int)addr[8], (int)addr[9],
                    (int)addr[10], (int)addr[11],
                    (int)addr[12], (int)addr[13],
                    (int)addr[14], (int)addr[15]);

            char reversed_ip_6[255];
            reverse_string(str);
            sprintf(reversed_ip_6, "%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.IP6.ARPA",
                    str[0], str[1], str[2], str[3], str[5], str[6], str[7], str[8],
                    str[10], str[11], str[12], str[13], str[15], str[16], str[17], str[18],
                    str[20], str[21], str[22], str[23], str[25], str[26], str[27], str[28],
                    str[30], str[31], str[32], str[33], str[35], str[36], str[37], str[38]);

            char *p = &reversed_ip_6[0];
            change_hostname_to_dns_query_name(query_name, &p);
        }
        else
        {
            error_exit(EXIT_FAILURE, "Expected IPv4 or IPv6");
        }
    }
    else
    {
        change_hostname_to_dns_query_name(query_name, &address);
    }

    index_after_query_name = 12 + strlen(query_name) + 1;

    query_len = index_after_query_name + 4;
    memset(query, '\0', query_len);

    memcpy(query, &dns_header, 12);
    memcpy(&query[12], &query_name, strlen(query_name) + 1);
    memcpy(&query[index_after_query_name], &query_type, 2);
    memcpy(&query[index_after_query_name + 2], &query_class, 2);

    int returned_value;
    returned_value = sendto(socket_fd, query, query_len, 0, (struct sockaddr *)&server_address, sizeof(server_address));
    if (returned_value < 0)
        error_exit(EXIT_FAILURE, "Cannot send query");

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    returned_value = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof timeout);
    if (returned_value < 0)
        error_exit(EXIT_FAILURE, "Timeout could not be set");

    unsigned char response[65536];
    socklen_t response_length;
    returned_value = recvfrom(socket_fd, response, sizeof(response), 0, (struct sockaddr *)&server_address, &response_length);
    if (returned_value < 0)
        error_exit(EXIT_FAILURE, "Receive error");

    struct DNS_HEADER *dns_response = NULL;
    dns_response = (struct DNS_HEADER *)response;
    if (ntohs(dns_response->rcode) == 1)
    {
        error_exit(EXIT_FAILURE, "Format error");
    }
    else if (ntohs(dns_response->rcode) == 2)
    {
        error_exit(EXIT_FAILURE, "Server failure");
    }
    else if (ntohs(dns_response->rcode) == 3)
    {
        error_exit(EXIT_FAILURE, "Name Error");
    }
    else if (ntohs(dns_response->rcode) == 4)
    {
        error_exit(EXIT_FAILURE, "Not Implemented");
    }
    else if (ntohs(dns_response->rcode) == 5)
    {
        error_exit(EXIT_FAILURE, "Refused");
    }

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

    unsigned char *reader = &response[sizeof(struct DNS_HEADER) + (strlen((const char *)query_name) + 1) + sizeof(struct QUESTION)];
    int stop = 0;

    printf("Question section (%d)\n", ntohs(dns_response->q_count));

    struct RES_RECORD answer;

    printf("Answer section (%d)\n", ntohs(dns_response->ans_count));
    for (int i = 0; i < ntohs(dns_response->ans_count); i++)
    {
        answer.name = ReadName(reader, response, &stop);
        reader = reader + stop;
        printf("  %s., ", answer.name);

        unsigned short x;
        unsigned char y;
        memcpy(&x, reader, 2);
        printf("%d, ", ntohs(x));
        reader += 2;

        memcpy(&x, reader, 2);
        printf("%d, ", ntohs(x));
        reader += 2;

        memcpy(&y, reader, 4);
        printf("%d, ", ntohs(y));
        reader += 4;

        memcpy(&x, reader, 2);
        printf("%d, ", ntohs(x));
        reader += 2;

        char ipAddress[INET_ADDRSTRLEN];
        memcpy(&y, reader, 4);
        inet_ntop(AF_INET, &y, ipAddress, INET_ADDRSTRLEN);
        printf("%d\n", ipAddress);
        reader += 4;
    }

    printf("Authority section (%d)\n", ntohs(dns_response->auth_count));
    printf("Additional section (%d)\n", ntohs(dns_response->add_count));

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
                   char **address)
{
    if ((argc == 2) && (strcmp(argv[1], "-h") == 0))
    {
        help();
    }
    if (argc < 4)
    {
        error_exit(EXIT_FAILURE, "Too few arguments");
    }
    if (argc > 9)
    {
        error_exit(EXIT_FAILURE, "Too many arguments");
    }

    *address = argv[argc - 1];

    int c;
    while ((c = getopt(argc, argv, "hrx6s:p:")) != -1)
    {
        switch (c)
        {
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
            try
            {
                *port = stoi(optarg);
            }
            catch (...)
            {
                error_exit(EXIT_FAILURE, "Cannot parse port number");
            }
            break;
        default:
            error_exit(EXIT_FAILURE, "Wrong arguments");
            break;
        }
    }
}

void help()
{
    cout << "Help";
    exit(EXIT_SUCCESS);
}

void error_exit(int code, const char *msg)
{
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
                    char **address)
{
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

void change_hostname_to_dns_query_name(char *query_name, char **address)
{
    // www.fit.vutbr.cz -> 3www3fit5vutbr2cz0
    unsigned int previous_index = 0;
    int length;

    strcpy(&query_name[1], *address);

    while ((length = strcspn(&query_name[previous_index + 1], ".")) != 0)
    {
        //cout << length << "\n";
        query_name[previous_index] = length;
        previous_index = previous_index + length + 1;
    }
    if (strlen(*address) != previous_index - 1)
        query_name[previous_index] = 0;
}

void reverse_IP(char *pIP)
{
    char seps[] = ".";
    char *token;
    char pIPSec[4][4];
    int i = 0;
    token = strtok(pIP, seps);
    while (token != NULL)
    {
        /* While there are "." characters in "string" */
        sprintf(pIPSec[i], "%s", token);
        /* Get next "." character: */
        token = strtok(NULL, seps);
        i++;
    }
    sprintf(pIP, "%s.%s.%s.%s.%s", pIPSec[3], pIPSec[2], pIPSec[1], pIPSec[0], "IN-ADDR.ARPA");
}

void reverse_string(char *str)
{
    /* skip null */
    if (str == 0)
    {
        return;
    }

    /* skip empty string */
    if (*str == 0)
    {
        return;
    }

    /* get range */
    char *start = str;
    char *end = start + strlen(str) - 1; /* -1 for \0 */
    char temp;

    /* reverse */
    while (end > start)
    {
        /* swap */
        temp = *start;
        *start = *end;
        *end = temp;

        /* move */
        ++start;
        --end;
    }
}

int get_name_from_response(char *name, unsigned char *response, unsigned char *dns_name, int query_len, int type)
{
    if (dns_name[0] == 0 && dns_name[1] == 0 && dns_name[2] == 2 && dns_name[3] == 0)
    {
        strcpy(name, ".");
        return 1;
    }

    unsigned short offset;
    memcpy(&offset, dns_name, 2);
    offset = ntohs(offset);

    int bytes = 2;
    int data_len;

    if (offset >= 0b1100000000000000)
        // offset
        offset -= 0b1100000000000000;
    else
    {
        // no offset
        data_len = offset;
        offset = dns_name - response + 2;
        bytes += data_len;
    }

    int section_len = 0;
    int i = 0;

    if (type == 4)
    {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &response[offset], ip, INET_ADDRSTRLEN);
        strcpy(name, ip);
        return bytes;
    }
    else if (type == 6)
    {
        char ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &response[offset], ip6, INET6_ADDRSTRLEN);
        strcpy(name, ip6);
        return bytes;
    }
    else
    {
        char hostname[255];
        memset(hostname, '\0', sizeof(hostname));
        i = 0;
        do
        {
            section_len = response[offset + i];
            memcpy(&hostname[i], (char *)&response[offset + i + 1], section_len); // Offset in message + char position + 1 because of section len in index 0
            hostname[i + section_len] = '.';

            if (section_len >= 0b11000000) // If there is a offset link instead of section length
            {
                char linkedName[255];
                get_name_from_response(linkedName, response, &response[offset + i], query_len, type);
                memcpy(&hostname[i], linkedName, strlen(linkedName) + 1);
            }

            i += section_len + 1;
        } while (section_len != 0);
        hostname[i - 1] = '\0'; // Add end of string

        // --- Return result ---
        strcpy(name, hostname);

        return bytes;
    }
}

u_char *ReadName(unsigned char *reader, unsigned char *buffer, int *count)
{
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name = (unsigned char *)malloc(256);

    name[0] = '\0';

    //read the names in 3www6google3com format
    while (*reader != 0)
    {
        if (*reader >= 192)
        {
            offset = (*reader) * 256 + *(reader + 1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++] = *reader;
        }

        reader = reader + 1;

        if (jumped == 0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }

    name[p] = '\0'; //string complete
    if (jumped == 1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //now convert 3www6google3com0 to www.google.com
    for (i = 0; i < (int)strlen((const char *)name); i++)
    {
        p = name[i];
        for (j = 0; j < (int)p; j++)
        {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0'; //remove the last dot
    return name;
}
