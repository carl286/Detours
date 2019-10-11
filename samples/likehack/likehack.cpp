//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (likehack.cpp of likehack.dll)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  This DLL will detour the Windows SleepEx API so that TimedSleep function
//  gets called instead.  TimedSleepEx records the before and after times, and
//  calls the real SleepEx API through the TrueSleepEx function pointer.
//
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windows.h>
#include "detours.h"

#pragma comment (lib, "Ws2_32.lib")

static LONG dwSlept = 0;
static DWORD (WINAPI * TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

static void printSocket(SOCKET socket)
{

  SOCKADDR_IN          ServerAddr;
#pragma warning(push) 
#pragma warning(disable:4996) 
	int ret = getsockname(socket, (SOCKADDR*)&ServerAddr, (int*)sizeof(ServerAddr));
  printf("ret for get sock name %d\n", ret);

	printf("Client: Receiver IP(s) used: %s\n", inet_ntoa(ServerAddr.sin_addr));

	printf("Client: Receiver port used: %d\n", htons(ServerAddr.sin_port));
  #pragma warning(pop) 

}

DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    DWORD dwBeg = GetTickCount();
    DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
    DWORD dwEnd = GetTickCount();

    InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);

    return ret;
}

// https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
/*
SOCKET WSAAPI socket(
  int af,
  int type,
  int protocol
);
*/
static SOCKET (WSAAPI* TrueSocket)(
  int af,
  int type,
  int protocol
) = socket;

SOCKET WSAAPI HackSocket(
  int af,
  int type,
  int protocol
)
{
    printf("Come to HackSocket.\n");
    printf("af: %d, type: %d, protocol: %d\n",af, type, protocol);
    fflush(stdout);

    SOCKET ret = TrueSocket(af, type, protocol);
    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw

SOCKET WSAAPI WSASocketW(
  int                 af,
  int                 type,
  int                 protocol,
  LPWSAPROTOCOL_INFOW lpProtocolInfo,
  GROUP               g,
  DWORD               dwFlags
);

*/

static SOCKET (WSAAPI* TrueWSASocketW)(
  int                 af,
  int                 type,
  int                 protocol,
  LPWSAPROTOCOL_INFOW lpProtocolInfo,
  GROUP               g,
  DWORD               dwFlags
) = WSASocketW;

SOCKET WSAAPI HackWSASocketW(
  int                 af,
  int                 type,
  int                 protocol,
  LPWSAPROTOCOL_INFOW lpProtocolInfo,
  GROUP               g,
  DWORD               dwFlags
)
{
    printf("Come to HackWSASocketW\n");
    printf("af: %d, type: %d, protocol: %d\n",af, type, protocol);
    fflush(stdout);
    SOCKET ret = TrueWSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags);
    printf("socket: %lld \n", (__int64)ret);
    fflush(stdout);
    return ret;
}

/*

https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-bind
int WSAAPI bind(
  SOCKET         s,
  const sockaddr *name,
  int            namelen
);
*/

static int (WSAAPI* TrueBind)(
  SOCKET         s,
  const sockaddr *addr,
  int            namelen
) = bind;

int HackBind(
  SOCKET         s,
  const sockaddr *addr,
  int            namelen
)
{
    printf("Come to HackBind\n");
    fflush(stdout);

    printf("ORG socket %lld\n", (__int64)s);
    			printf("AF_INET (IPv4)\n");
			struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*) addr;
      #pragma warning(push) 
#pragma warning(disable:4996) 
			printf("\tIPv4 address %s\n",
				inet_ntoa(sockaddr_ipv4->sin_addr));
#pragma warning(pop)

    int ret = TrueBind(s, addr, namelen);
    printf("After Bind: Ret: %d\n", ret);
    printSocket(s);

    
    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect
int WSAAPI connect(
  SOCKET         s,
  const sockaddr *name,
  int            namelen
);
*/

static int (WSAAPI* TrueConnect)(
  SOCKET         s,
  const sockaddr *name,
  int            namelen
) = connect;

int WSAAPI HackConnect(
  SOCKET         s,
  const sockaddr *name,
  int            namelen
)
{
    printf("Come to HackConnect\n");
    fflush(stdout);

    int ret = TrueConnect(s, name, namelen);
    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen
int WSAAPI listen(
  SOCKET s,
  int    backlog
);
*/

static int (WSAAPI* TrueListen)(
  SOCKET s,
  int    backlog
) = listen;

int WSAAPI HackListen(
  SOCKET s,
  int    backlog
)
{
    printf("Come to HackListen\n");
    fflush(stdout);
    int ret = TrueListen(s, backlog);
    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-getsockname
int WSAAPI getsockname(
  SOCKET   s,
  sockaddr *name,
  int      *namelen
);
*/

static int (WSAAPI* TrueGetSockName)(
  SOCKET   s,
  sockaddr *name,
  int      *namelen
) = getsockname;

int WSAAPI HackGetSockName(
  SOCKET   s,
  sockaddr *name,
  int      *namelen
)
{
    printf("Come to HackGetSockName\n");
    fflush(stdout);
    int ret = TrueGetSockName(s, name, namelen);
    return ret;
}


// https://docs.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfow
static INT (WSAAPI* TrueGetAddrInfoW)(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW * pHints, PADDRINFOW * ppResult) = GetAddrInfoW;

INT WSAAPI HackGetAddrInfoW(
  PCWSTR          pNodeName,
  PCWSTR          pServiceName,
  const ADDRINFOW *pHints,
  PADDRINFOW      *ppResult
)
{
    printf("Come to HackGetAddrInfoW.\n");
    fflush(stdout);
    /*
    printf("pNodeName:.\n");
    wprintf(pNodeName);
    printf("pServiceName");
    wprintf(pServiceName);
    */
    INT ret = TrueGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexw
INT WSAAPI GetAddrInfoExW(
  PCWSTR                             pName,
  PCWSTR                             pServiceName,
  DWORD                              dwNameSpace,
  LPGUID                             lpNspId,
  const ADDRINFOEXW                  *hints,
  PADDRINFOEXW                       *ppResult,
  timeval                            *timeout,
  LPOVERLAPPED                       lpOverlapped,
  LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
  LPHANDLE                           lpHandle
);
*/

static INT (WSAAPI* TrueGetAddrInfoExW)(
  PCWSTR                             pName,
  PCWSTR                             pServiceName,
  DWORD                              dwNameSpace,
  LPGUID                             lpNspId,
  const ADDRINFOEXW                  *hints,
  PADDRINFOEXW                       *ppResult,
  timeval                            *timeout,
  LPOVERLAPPED                       lpOverlapped,
  LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
  LPHANDLE                           lpHandle
) = GetAddrInfoExW;

INT WSAAPI HackGetAddrInfoExW(
  PCWSTR                             pName,
  PCWSTR                             pServiceName,
  DWORD                              dwNameSpace,
  LPGUID                             lpNspId,
  const ADDRINFOEXW                  *hints,
  PADDRINFOEXW                       *ppResult,
  timeval                            *timeout,
  LPOVERLAPPED                       lpOverlapped,
  LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
  LPHANDLE                           lpHandle
)
{
    printf("Come to HackGetAddrInfoExW\n");
    fflush(stdout);

    wprintf(pName);
    printf("\n");
    fflush(stdout);

    if (pServiceName != NULL)
    {
      wprintf(pServiceName);
      printf("\n");
    }

    printf("dwNameSpace %d\n",dwNameSpace );

    INT ret = TrueGetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, hints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpHandle);

    printf("TrueGetAddrInfoExW ret: %d\n", ret);
    if (*ppResult)
    {
          printf("*ppResult not empty\n");
    }
    else
    {
          printf("*ppResult empty\n");
    }

    for (PADDRINFOEXW ptr = *ppResult; ptr != NULL; ptr = ptr->ai_next)

	{

		wprintf(L"\tFlags: 0x%x\n", ptr->ai_flags);
		wprintf(L"\tFamily: ");

		switch (ptr->ai_family)

		{

		case AF_UNSPEC:

			wprintf(L"Unspecified\n");

			break;

		case AF_INET:

			wprintf(L"AF_INET (IPv4)\n");

			break;

		case AF_INET6:

			wprintf(L"AF_INET6 (IPv6)\n");

			break;

		default:

			wprintf(L"Other %ld\n", ptr->ai_family);

			break;

		}



		wprintf(L"\tSocket type: ");

		switch (ptr->ai_socktype)

		{

		case 0:

			wprintf(L"Unspecified\n");

			break;

		case SOCK_STREAM:

			wprintf(L"SOCK_STREAM (stream)\n");

			break;

		case SOCK_DGRAM:

			wprintf(L"SOCK_DGRAM (datagram) \n");

			break;

		case SOCK_RAW:

			wprintf(L"SOCK_RAW (raw) \n");

			break;

		case SOCK_RDM:

			wprintf(L"SOCK_RDM (reliable message datagram)\n");

			break;

		case SOCK_SEQPACKET:

			wprintf(L"SOCK_SEQPACKET (pseudo-stream packet)\n");

			break;

		default:

			wprintf(L"Other %ld\n", ptr->ai_socktype);

			break;

		}



		wprintf(L"\tProtocol: ");

		switch (ptr->ai_protocol)

		{

		case 0:

			wprintf(L"Unspecified\n");

			break;

		case IPPROTO_TCP:

			wprintf(L"IPPROTO_TCP (TCP)\n");

			break;

		case IPPROTO_UDP:

			wprintf(L"IPPROTO_UDP (UDP) \n");

			break;

		default:

			wprintf(L"Other %ld\n", ptr->ai_protocol);

			break;

		}

		wprintf(L"\tLength of this sockaddr: %zu\n", ptr->ai_addrlen);

		wprintf(L"\tCanonical name: %s\n", ptr->ai_canonname);

	}

    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-gethostbyname
hostent *WSAAPI gethostbyname(
  const char *name
);
*/

#pragma warning(push) 
#pragma warning(disable:4996) 
static hostent * (WSAAPI* TrueGetHostByName)(
  const char *name
) = gethostbyname;

hostent *WSAAPI HackGetHostByName(
  const char *name
)
{
  printf("Come to HackGetHostByName");
  if (name != NULL)
  {
    printf(name);
  }
  hostent * ret = gethostbyname(name);
  return ret;
}
#pragma warning(pop) 

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnect
int WSAAPI WSAConnect(
  SOCKET         s,
  const sockaddr *name,
  int            namelen,
  LPWSABUF       lpCallerData,
  LPWSABUF       lpCalleeData,
  LPQOS          lpSQOS,
  LPQOS          lpGQOS
);
*/

static int (WSAAPI* TrueWSAConnect)(
  SOCKET         s,
  const sockaddr *name,
  int            namelen,
  LPWSABUF       lpCallerData,
  LPWSABUF       lpCalleeData,
  LPQOS          lpSQOS,
  LPQOS          lpGQOS
) = WSAConnect;

int WSAAPI HackWSAConnect(
  SOCKET         s,
  const sockaddr *name,
  int            namelen,
  LPWSABUF       lpCallerData,
  LPWSABUF       lpCalleeData,
  LPQOS          lpSQOS,
  LPQOS          lpGQOS
)
{
    printf("Come to HackWSAConnect\n");
    fflush(stdout);
    /*
    if (name != NULL)
    {
        printf("%u\n", name->sa_family);
        printf("%s\n", name->sa_data);
    }
    */
    int ret = TrueWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS,lpGQOS);

    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnectbylist
BOOL WSAConnectByList(
  SOCKET               s,
  PSOCKET_ADDRESS_LIST SocketAddress,
  LPDWORD              LocalAddressLength,
  LPSOCKADDR           LocalAddress,
  LPDWORD              RemoteAddressLength,
  LPSOCKADDR           RemoteAddress,
  const timeval        *timeout,
  LPWSAOVERLAPPED      Reserved
);
*/
static BOOL (PASCAL* TrueWSAConnectByList)(
  SOCKET               s,
  PSOCKET_ADDRESS_LIST SocketAddress,
  LPDWORD              LocalAddressLength,
  LPSOCKADDR           LocalAddress,
  LPDWORD              RemoteAddressLength,
  LPSOCKADDR           RemoteAddress,
  const timeval        *timeout,
  LPWSAOVERLAPPED      Reserved
) = WSAConnectByList;

BOOL HackWSAConnectByList(
  SOCKET               s,
  PSOCKET_ADDRESS_LIST SocketAddress,
  LPDWORD              LocalAddressLength,
  LPSOCKADDR           LocalAddress,
  LPDWORD              RemoteAddressLength,
  LPSOCKADDR           RemoteAddress,
  const timeval        *timeout,
  LPWSAOVERLAPPED      Reserved
)
{
    printf("Come to HackWSAConnectByList\n");
    fflush(stdout);
    BOOL ret = TrueWSAConnectByList(s, SocketAddress, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);
    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_connectex

*/
/*
static 
BOOL
(PASCAL* 
TrueConnectEx)(SOCKET s, const struct sockaddr * name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverLapped) = LpfnConnectex;

static 
BOOL
PASCAL
HackConnectEx(SOCKET s, const struct sockaddr * name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverLapped)
{
    BOOL ret = TrueConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    return ret;
}
*/

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-sendto
int WSAAPI sendto(
  SOCKET         s,
  const char     *buf,
  int            len,
  int            flags,
  const sockaddr *to,
  int            tolen
);
*/
static int (WSAAPI* TrueSendTo)(
  SOCKET         s,
  const char     *buf,
  int            len,
  int            flags,
  const sockaddr *to,
  int            tolen
) = sendto;

int WSAAPI HackSendTo(
  SOCKET         s,
  const char     *buf,
  int            len,
  int            flags,
  const sockaddr *to,
  int            tolen
)
{
    printf("Come to sendto\n");
    printf(buf);
    int ret = TrueSendTo(s, buf, len, flags, to, tolen);
    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendto
int WSAAPI WSASendTo(
  SOCKET                             s,
  LPWSABUF                           lpBuffers,
  DWORD                              dwBufferCount,
  LPDWORD                            lpNumberOfBytesSent,
  DWORD                              dwFlags,
  const sockaddr                     *lpTo,
  int                                iTolen,
  LPWSAOVERLAPPED                    lpOverlapped,
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);
*/

static int (WSAAPI* TrueWSASendTo)(
  SOCKET                             s,
  LPWSABUF                           lpBuffers,
  DWORD                              dwBufferCount,
  LPDWORD                            lpNumberOfBytesSent,
  DWORD                              dwFlags,
  const sockaddr                     *lpTo,
  int                                iTolen,
  LPWSAOVERLAPPED                    lpOverlapped,
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) = WSASendTo;

int WSAAPI HackWSASendTo(
  SOCKET                             s,
  LPWSABUF                           lpBuffers,
  DWORD                              dwBufferCount,
  LPDWORD                            lpNumberOfBytesSent,
  DWORD                              dwFlags,
  const sockaddr                     *lpTo,
  int                                iTolen,
  LPWSAOVERLAPPED                    lpOverlapped,
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
    printf("Come to HackWSASendTo\n");
    fflush(stdout);
    int ret = TrueWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);

    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasend
int WSAAPI WSASend(
  SOCKET                             s,
  LPWSABUF                           lpBuffers,
  DWORD                              dwBufferCount,
  LPDWORD                            lpNumberOfBytesSent,
  DWORD                              dwFlags,
  LPWSAOVERLAPPED                    lpOverlapped,
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);
*/
static int (WSAAPI* TrueWSASend)(
  SOCKET                             s,
  LPWSABUF                           lpBuffers,
  DWORD                              dwBufferCount,
  LPDWORD                            lpNumberOfBytesSent,
  DWORD                              dwFlags,
  LPWSAOVERLAPPED                    lpOverlapped,
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) = WSASend;

int WSAAPI HackWSASend(
  SOCKET                             s,
  LPWSABUF                           lpBuffers,
  DWORD                              dwBufferCount,
  LPDWORD                            lpNumberOfBytesSent,
  DWORD                              dwFlags,
  LPWSAOVERLAPPED                    lpOverlapped,
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
    printf("Come to HackWSASend\n");
    fflush(stdout);
    printSocket(s);
    int ret = TrueWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
    return ret;
}



/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecv
int WSAAPI WSARecv(
  SOCKET                             s,
  LPWSABUF                           lpBuffers,
  DWORD                              dwBufferCount,
  LPDWORD                            lpNumberOfBytesRecvd,
  LPDWORD                            lpFlags,
  LPWSAOVERLAPPED                    lpOverlapped,
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);
*/

static int (WSAAPI* TrueWSARecv)(
  SOCKET                             s,
  LPWSABUF                           lpBuffers,
  DWORD                              dwBufferCount,
  LPDWORD                            lpNumberOfBytesRecvd,
  LPDWORD                            lpFlags,
  LPWSAOVERLAPPED                    lpOverlapped,
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) = WSARecv;

int WSAAPI HackWSARecv(
  SOCKET                             s,
  LPWSABUF                           lpBuffers,
  DWORD                              dwBufferCount,
  LPDWORD                            lpNumberOfBytesRecvd,
  LPDWORD                            lpFlags,
  LPWSAOVERLAPPED                    lpOverlapped,
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
    printf("Come to HackWSARecv\n");
    fflush(stdout);
    int ret = TrueWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send
 int WSAAPI send(
  SOCKET     s,
  const char *buf,
  int        len,
  int        flags
);
 */

static int (WSAAPI* TrueSend)(
  SOCKET     s,
  const char *buf,
  int        len,
  int        flags
) = send;

int WSAAPI HackSend(
  SOCKET     s,
  const char *buf,
  int        len,
  int        flags
)
{
    printf("Come to HackSend\n");
    fflush(stdout);
    int ret = TrueSend(s, buf, len, flags);
    return ret;
}

/*
https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recv

int WSAAPI recv(
  SOCKET s,
  char   *buf,
  int    len,
  int    flags
);

*/

static int (WSAAPI* TrueRecv)(
  SOCKET s,
  char   *buf,
  int    len,
  int    flags
) = recv;

int WSAAPI HackRecv(
  SOCKET s,
  char   *buf,
  int    len,
  int    flags
)
{
    printf("Come to HackRecv\n");
    fflush(stdout);
    int ret = TrueRecv(s, buf, len, flags);
    return ret;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

        printf("likehack" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
               " Starting.\n");
        fflush(stdout);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueSleepEx, TimedSleepEx);
        DetourAttach(&(PVOID&)TrueSocket, HackSocket);
        DetourAttach(&(PVOID&)TrueWSASocketW, HackWSASocketW);
        DetourAttach(&(PVOID&)TrueBind, HackBind);
        DetourAttach(&(PVOID&)TrueConnect, HackConnect);
        DetourAttach(&(PVOID&)TrueListen, HackListen);
        DetourAttach(&(PVOID&)TrueGetSockName, HackGetSockName);
        DetourAttach(&(PVOID&)TrueGetAddrInfoW, HackGetAddrInfoW);
        DetourAttach(&(PVOID&)TrueGetAddrInfoExW, HackGetAddrInfoExW);
        DetourAttach(&(PVOID&)TrueGetHostByName, HackGetHostByName);
        DetourAttach(&(PVOID&)TrueWSAConnect, HackWSAConnect);
        DetourAttach(&(PVOID&)TrueWSAConnectByList, HackWSAConnectByList);
        // DetourAttach(&(PVOID&)TrueConnectEx, HackConnectEx);
        DetourAttach(&(PVOID&)TrueSendTo, HackSendTo);
        DetourAttach(&(PVOID&)TrueWSASendTo, HackWSASendTo);
        DetourAttach(&(PVOID&)TrueWSASend, HackWSASend);
        DetourAttach(&(PVOID&)TrueWSARecv, HackWSARecv);
        DetourAttach(&(PVOID&)TrueSend, HackSend);
        DetourAttach(&(PVOID&)TrueRecv, HackRecv);
        error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            printf("likehack" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                   " Detoured SleepEx().\n");
        }
        else {
            printf("likehack" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                   " Error detouring SleepEx(): %d\n", error);
        }
        fflush(stdout);
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueSleepEx, TimedSleepEx);
        DetourDetach(&(PVOID&)TrueSocket, HackSocket);
        DetourDetach(&(PVOID&)TrueWSASocketW, HackWSASocketW);
        DetourDetach(&(PVOID&)TrueBind, HackBind);
        DetourDetach(&(PVOID&)TrueConnect, HackConnect);
        DetourDetach(&(PVOID&)TrueListen, HackListen);
        DetourDetach(&(PVOID&)TrueGetSockName, HackGetSockName);
        DetourDetach(&(PVOID&)TrueGetAddrInfoW, HackGetAddrInfoW);
        DetourDetach(&(PVOID&)TrueGetAddrInfoExW, HackGetAddrInfoExW);
        DetourDetach(&(PVOID&)TrueGetHostByName, HackGetHostByName);
        DetourDetach(&(PVOID&)TrueWSAConnect, HackWSAConnect);
        DetourDetach(&(PVOID&)TrueWSAConnectByList, HackWSAConnectByList);
        // DetourDetach(&(PVOID&)TrueConnectEx, HackConnectEx);
        DetourDetach(&(PVOID&)TrueSendTo, HackSendTo);
        DetourDetach(&(PVOID&)TrueWSASendTo, HackWSASendTo);
        DetourDetach(&(PVOID&)TrueWSASend, HackWSASend);
        DetourDetach(&(PVOID&)TrueSend, HackSend);
        DetourDetach(&(PVOID&)TrueRecv, HackRecv);
        error = DetourTransactionCommit();

        printf("likehack" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
               " Removed SleepEx() (result=%d), slept %d ticks.\n", error, dwSlept);
        fflush(stdout);
    }
    return TRUE;
}

//
///////////////////////////////////////////////////////////////// End of File.
