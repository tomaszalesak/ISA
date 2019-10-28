#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <cstring>
#include <string>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fstream>
#include <netdb.h>
#include <errno.h>

using namespace std;

//DNS header structure
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

    get_arguments(argc, argv, &help_flag, &recursion_flag, &reverse_query_flag, &AAAA_flag, &server_flag, &server, &port_flag, &port, &address);
    show_arguments(&help_flag, &recursion_flag, &reverse_query_flag, &AAAA_flag, &server_flag, &server, &port_flag, &port, &address);
    if (help_flag)
        help();
    if (!port_flag)
        port = 53;

    struct sockaddr_in server_address;
    struct hostent *servent;
    memset(&server_address, 0, sizeof(server_address));
    if ((servent = gethostbyname(server)) == NULL)
        error_exit(EXIT_FAILURE, "gethostbyname() failed\n");
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    memcpy(&server_address.sin_addr, servent->h_addr, servent->h_length);
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(server_address.sin_addr), str, INET_ADDRSTRLEN);
    cout << str << "\n";

    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0)
        error_exit(EXIT_FAILURE, "Cannot create socket");

    char query[255];
    int query_len;

    struct DNS_HEADER dns;

    char query_name[255];
    int index_after_query_name;

    unsigned short query_type;
    unsigned short query_class;

    if (AAAA_flag)
        query_type = htons(28);
    else
        query_type = htons(1);

    query_class = htons(1); // internet

    dns.id = (unsigned short)htons(getpid());
    dns.qr = 0;     // This is a query
    dns.opcode = 0; // This is a standard query
    dns.aa = 0;     // Not Authoritative
    dns.tc = 0;     // This message is not truncated
    if (recursion_flag)
        dns.rd = 1; // Recursion Desired
    else
        dns.rd = 0;
    dns.ra = 0;
    dns.z = 0;
    dns.ad = 0;
    dns.cd = 0;
    dns.rcode = 0;
    dns.q_count = htons(1); // 1 question
    dns.ans_count = 0;
    dns.auth_count = 0;
    dns.add_count = 0;

    memset(query_name, '\0', 255);

    // -- Classic version --
    // www.fit.vutbr.cz -> 3www3fit5vutbr2cz0
    strcpy(&query_name[1], address);

    int prevIndex = 0;
    int len;
    while ((len = strcspn(&query_name[prevIndex + 1], ".")) != 0)
    {
        cout << len << "\n";
        query_name[prevIndex] = len;
        prevIndex += len + 1;
    }
    if (strlen(address) + 1 != prevIndex) // Dot and end of name
        query_name[prevIndex] = 0;        // Change it to null byte
    
    cout << query_name << "\n";

    index_after_query_name = 12 + strlen(query_name) + 1;

    query_len = index_after_query_name + 4;
    memset(query, '\0', query_len);

    memcpy(query, &dns, 12);
    memcpy(&query[12], &query_name, strlen(query_name) + 1);
    memcpy(&query[index_after_query_name], &query_type, 2);
    memcpy(&query[index_after_query_name + 2], &query_class, 2);

    int n;
    n = sendto(socket_fd, query, query_len, 0, (struct sockaddr *)&server_address, sizeof(server_address));
    if (n < 0)
        error_exit(EXIT_FAILURE, "Cannot send query");

    struct timeval tv;
    tv.tv_sec = 4;
    tv.tv_usec = 0;
    n = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof tv);
    if (n < 0)
        error_exit(EXIT_FAILURE, "Timeout");

    unsigned char response[65536];
    socklen_t responseLen;
    n = recvfrom(socket_fd, response, sizeof(response), 0, (struct sockaddr *)&server_address, &responseLen);
    if (n < 0)
    {
        if (errno == 11)
            error_exit(EXIT_FAILURE, "Timeout");
        else
            error_exit(EXIT_FAILURE, "Receive error");
    }
    
	unsigned short answerCount;
	memcpy(&answerCount, &response[6], 2);
	answerCount = ntohs(answerCount);
    cout << answerCount << "\n";
	
	unsigned short authorityCount;
	memcpy(&authorityCount, &response[8], 2);
	authorityCount = ntohs(authorityCount);
    cout << authorityCount << "\n";
	
	unsigned short additionalCount;
	memcpy(&additionalCount, &response[10], 2);
	additionalCount = ntohs(additionalCount);
    cout << additionalCount << "\n";




    exit(EXIT_SUCCESS);
}

void get_arguments(int argc, char **argv, int *help_flag, int *recursion_flag, int *reverse_query_flag, int *AAAA_flag, int *server_flag, char **server, int *port_flag, int *port, char **address)
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
