#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <iphlpapi.h>
#include <windns.h>
#include <wlanapi.h>
#include <shellapi.h>
#include <wchar.h>
#include <stdio.h>
#include "minhook/include/MinHook.h"

static WCHAR self[MAX_PATH], helper[MAX_PATH], image[MAX_PATH], icmp[MAX_PATH], hookDll[MAX_PATH];
static BOOL full;

static WCHAR idGuid[64], idName[32], idProduct[32], idSus[64], idHw[64], idSqm[64];
static WCHAR sysLocale[LOCALE_NAME_MAX_LENGTH] = L"en-US", nlsLang[8], nlsLocale[16];
static LCID sysLcid;
static DWORD idInstall, idSeed, gatePort;
static ULONGLONG idInstallTime, tickOffset;

static void *volatile imports[5];

static const WCHAR *base(const WCHAR *p) {
	const WCHAR *b = p;
	for (; *p; p++)
		if (*p == L'\\' || *p == L'/')
			b = p + 1;
	return b;
}

static BOOL allowed(const WCHAR *name) {
	IN_ADDR a4;
	IN6_ADDR a6;
	return _wcsicmp(name, L"localhost") == 0 || InetPtonW(AF_INET, name, &a4) == 1 || InetPtonW(AF_INET6, name, &a6) == 1;
}

static BOOL allowedA(const char *name) {
	WCHAR w[256];
	return MultiByteToWideChar(CP_UTF8, 0, name, -1, w, 256) && allowed(w);
}

static BOOL routeCall(const void *req, DWORD n, void *resp, DWORD cap, DWORD *got) {
	return CallNamedPipeW(L"\\\\.\\pipe\\airlock-route", (LPVOID)req, n, resp, cap, got, 5000);
}

static BOOL resolve(const char *name, char *ip) {
	BYTE req[256], resp[1 + 16 * 4];
	DWORD got;
	size_t n = strlen(name);
	if (n == 0 || n >= sizeof req)
		return FALSE;
	req[0] = 'R';
	memcpy(req + 1, name, n);
	if (!routeCall(req, (DWORD)n + 1, resp, sizeof resp, &got) || got < 5 || resp[0] == 0)
		return FALSE;
	return InetNtopA(AF_INET, resp + 1, ip, 16) != NULL;
}

static BOOL resolveW(PCWSTR name, WCHAR *ip) {
	char n[256], a[16];
	return WideCharToMultiByte(CP_UTF8, 0, name, -1, n, sizeof n, NULL, NULL) && resolve(n, a) && MultiByteToWideChar(CP_UTF8, 0, a, -1, ip, 16);
}

static BOOL resolvable(int family, int flags) {
	return family != AF_INET6 && !(flags & AI_NUMERICHOST);
}

typedef INT(WSAAPI *getaddrinfo_t)(PCSTR, PCSTR, const ADDRINFOA *, PADDRINFOA *);
static getaddrinfo_t real_getaddrinfo;
static INT WSAAPI my_getaddrinfo(PCSTR name, PCSTR service, const ADDRINFOA *hints, PADDRINFOA *result) {
	char ip[16];
	if (name && !allowedA(name)) {
		if (!resolvable(hints ? hints->ai_family : 0, hints ? hints->ai_flags : 0) || !resolve(name, ip)) {
			WSASetLastError(WSAHOST_NOT_FOUND);
			return WSAHOST_NOT_FOUND;
		}
		name = ip;
	}
	return real_getaddrinfo(name, service, hints, result);
}

typedef INT(WSAAPI *GetAddrInfoW_t)(PCWSTR, PCWSTR, const ADDRINFOW *, PADDRINFOW *);
static GetAddrInfoW_t real_GetAddrInfoW;
static INT WSAAPI my_GetAddrInfoW(PCWSTR name, PCWSTR service, const ADDRINFOW *hints, PADDRINFOW *result) {
	WCHAR ip[16];
	if (name && !allowed(name)) {
		if (!resolvable(hints ? hints->ai_family : 0, hints ? hints->ai_flags : 0) || !resolveW(name, ip)) {
			WSASetLastError(WSAHOST_NOT_FOUND);
			return WSAHOST_NOT_FOUND;
		}
		name = ip;
	}
	return real_GetAddrInfoW(name, service, hints, result);
}

typedef INT(WSAAPI *GetAddrInfoExW_t)(PCWSTR, PCWSTR, DWORD, LPGUID, const ADDRINFOEXW *, PADDRINFOEXW *, struct timeval *, LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);
static GetAddrInfoExW_t real_GetAddrInfoExW;
static INT WSAAPI my_GetAddrInfoExW(PCWSTR name, PCWSTR service, DWORD space, LPGUID id, const ADDRINFOEXW *hints, PADDRINFOEXW *result, struct timeval *timeout, LPOVERLAPPED ov, LPLOOKUPSERVICE_COMPLETION_ROUTINE done, LPHANDLE handle) {
	WCHAR ip[16];
	if (name && !allowed(name)) {
		if (!resolvable(hints ? hints->ai_family : 0, hints ? hints->ai_flags : 0) || !resolveW(name, ip)) {
			WSASetLastError(WSAHOST_NOT_FOUND);
			return WSAHOST_NOT_FOUND;
		}
		name = ip;
	}
	return real_GetAddrInfoExW(name, service, space, id, hints, result, timeout, ov, done, handle);
}

typedef INT(WSAAPI *GetAddrInfoExA_t)(PCSTR, PCSTR, DWORD, LPGUID, const ADDRINFOEXA *, PADDRINFOEXA *, struct timeval *, LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);
static GetAddrInfoExA_t real_GetAddrInfoExA;
static INT WSAAPI my_GetAddrInfoExA(PCSTR name, PCSTR service, DWORD space, LPGUID id, const ADDRINFOEXA *hints, PADDRINFOEXA *result, struct timeval *timeout, LPOVERLAPPED ov, LPLOOKUPSERVICE_COMPLETION_ROUTINE done, LPHANDLE handle) {
	char ip[16];
	if (name && !allowedA(name)) {
		if (!resolvable(hints ? hints->ai_family : 0, hints ? hints->ai_flags : 0) || !resolve(name, ip)) {
			WSASetLastError(WSAHOST_NOT_FOUND);
			return WSAHOST_NOT_FOUND;
		}
		name = ip;
	}
	return real_GetAddrInfoExA(name, service, space, id, hints, result, timeout, ov, done, handle);
}

typedef struct hostent *(WSAAPI *gethostbyname_t)(const char *);
static gethostbyname_t real_gethostbyname;
static struct hostent *WSAAPI my_gethostbyname(const char *name) {
	char ip[16];
	if (!name)
		return NULL;
	if (!allowedA(name)) {
		if (!resolve(name, ip)) {
			WSASetLastError(WSAHOST_NOT_FOUND);
			return NULL;
		}
		name = ip;
	}
	return real_gethostbyname(name);
}

#define GONE INVALID_SOCKET

typedef struct {
	SOCKET s;
	SOCKADDR_STORAGE to;
	int len;
} peer;

static peer peers[4096];
static SRWLOCK peersLock = SRWLOCK_INIT;

static peer *findPeer(SOCKET s, BOOL add) {
	size_t n = sizeof peers / sizeof *peers;
	peer *free = NULL;
	for (size_t i = 0, h = (s >> 2) % n; i < n; i++, h = (h + 1) % n) {
		if (peers[h].s == s)
			return &peers[h];
		if (peers[h].s == GONE && !free)
			free = &peers[h];
		if (peers[h].s == 0) {
			if (!free)
				free = &peers[h];
			break;
		}
	}
	if (add && free)
		free->s = s;
	return add ? free : NULL;
}

static int gateAddr(int family, SOCKADDR_STORAGE *g) {
	memset(g, 0, sizeof *g);
	if (family == AF_INET) {
		SOCKADDR_IN *a = (SOCKADDR_IN *)g;
		a->sin_family = AF_INET;
		a->sin_port = htons(gatePort);
		a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		return sizeof *a;
	}
	SOCKADDR_IN6 *a = (SOCKADDR_IN6 *)g;
	a->sin6_family = AF_INET6;
	a->sin6_port = htons(gatePort);
	a->sin6_addr.s6_addr[10] = a->sin6_addr.s6_addr[11] = 0xff;
	a->sin6_addr.s6_addr[12] = 127;
	a->sin6_addr.s6_addr[15] = 1;
	return sizeof *a;
}

static int reroute(SOCKET s, const struct sockaddr *to, int len, SOCKADDR_STORAGE *gate, int *glen) {
	BYTE req[9] = {'C'}, ok = 1;
	DWORD got = 0;
	int type, tl = sizeof type, ll;
	SOCKADDR_STORAGE local;
	const BYTE *ip;
	USHORT port, lport;
	if (!to)
		return 0;
	if (to->sa_family == AF_INET && len >= (int)sizeof(SOCKADDR_IN)) {
		ip = (const BYTE *)&((const SOCKADDR_IN *)to)->sin_addr;
		port = ((const SOCKADDR_IN *)to)->sin_port;
	} else if (to->sa_family == AF_INET6 && len >= (int)sizeof(SOCKADDR_IN6) && IN6_IS_ADDR_V4MAPPED(&((const SOCKADDR_IN6 *)to)->sin6_addr)) {
		ip = ((const SOCKADDR_IN6 *)to)->sin6_addr.s6_addr + 12;
		port = ((const SOCKADDR_IN6 *)to)->sin6_port;
	} else
		return 0;
	if (ip[0] == 127 || (ip[0] | ip[1] | ip[2] | ip[3]) == 0)
		return 0;
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &tl) != 0 || type != SOCK_STREAM)
		return 0;
	ll = sizeof local;
	if (getsockname(s, (struct sockaddr *)&local, &ll) != 0) {
		memset(&local, 0, sizeof local);
		local.ss_family = to->sa_family;
		if (bind(s, (struct sockaddr *)&local, to->sa_family == AF_INET ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6)) != 0)
			return -1;
		ll = sizeof local;
		if (getsockname(s, (struct sockaddr *)&local, &ll) != 0)
			return -1;
	}
	lport = local.ss_family == AF_INET ? ((SOCKADDR_IN *)&local)->sin_port : ((SOCKADDR_IN6 *)&local)->sin6_port;
	if (!lport)
		return -1;
	memcpy(req + 1, &lport, 2);
	memcpy(req + 3, ip, 4);
	memcpy(req + 7, &port, 2);
	if (!routeCall(req, sizeof req, &ok, 1, &got) || got != 1 || ok != 0)
		return -1;
	AcquireSRWLockExclusive(&peersLock);
	peer *p = findPeer(s, TRUE);
	if (p) {
		p->len = len < (int)sizeof p->to ? len : (int)sizeof p->to;
		memcpy(&p->to, to, p->len);
	}
	ReleaseSRWLockExclusive(&peersLock);
	*glen = gateAddr(to->sa_family, gate);
	return 1;
}

typedef int(WSAAPI *connect_t)(SOCKET, const struct sockaddr *, int);
static connect_t real_connect;
static int WSAAPI my_connect(SOCKET s, const struct sockaddr *to, int len) {
	SOCKADDR_STORAGE g;
	int gl;
	switch (reroute(s, to, len, &g, &gl)) {
	case 1:
		return real_connect(s, (struct sockaddr *)&g, gl);
	case -1:
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}
	return real_connect(s, to, len);
}

typedef int(WSAAPI *WSAConnect_t)(SOCKET, const struct sockaddr *, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
static WSAConnect_t real_WSAConnect;
static int WSAAPI my_WSAConnect(SOCKET s, const struct sockaddr *to, int len, LPWSABUF caller, LPWSABUF callee, LPQOS sqos, LPQOS gqos) {
	SOCKADDR_STORAGE g;
	int gl;
	switch (reroute(s, to, len, &g, &gl)) {
	case 1:
		return real_WSAConnect(s, (struct sockaddr *)&g, gl, caller, callee, sqos, gqos);
	case -1:
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}
	return real_WSAConnect(s, to, len, caller, callee, sqos, gqos);
}

static LPFN_CONNECTEX real_ConnectEx;
static BOOL PASCAL my_ConnectEx(SOCKET s, const struct sockaddr *to, int len, PVOID buf, DWORD n, LPDWORD sent, LPOVERLAPPED ov) {
	SOCKADDR_STORAGE g;
	int gl;
	switch (reroute(s, to, len, &g, &gl)) {
	case 1:
		return real_ConnectEx(s, (struct sockaddr *)&g, gl, buf, n, sent, ov);
	case -1:
		WSASetLastError(WSAEACCES);
		return FALSE;
	}
	return real_ConnectEx(s, to, len, buf, n, sent, ov);
}

typedef int(WSAAPI *WSAIoctl_t)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static WSAIoctl_t real_WSAIoctl;
static int WSAAPI my_WSAIoctl(SOCKET s, DWORD code, LPVOID in, DWORD inLen, LPVOID out, DWORD outLen, LPDWORD ret, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE done) {
	static const GUID connectEx = WSAID_CONNECTEX;
	int r = real_WSAIoctl(s, code, in, inLen, out, outLen, ret, ov, done);
	if (r == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER && in && inLen >= sizeof(GUID) && out && outLen >= sizeof(void *) && memcmp(in, &connectEx, sizeof(GUID)) == 0 && *(LPFN_CONNECTEX *)out != my_ConnectEx) {
		real_ConnectEx = *(LPFN_CONNECTEX *)out;
		*(LPFN_CONNECTEX *)out = my_ConnectEx;
	}
	return r;
}

typedef int(WSAAPI *getpeername_t)(SOCKET, struct sockaddr *, int *);
static getpeername_t real_getpeername;
static int WSAAPI my_getpeername(SOCKET s, struct sockaddr *name, int *len) {
	int r = real_getpeername(s, name, len);
	if (r != 0 || !name || !len)
		return r;
	AcquireSRWLockShared(&peersLock);
	peer *p = findPeer(s, FALSE);
	if (p && *len >= p->len) {
		memcpy(name, &p->to, p->len);
		*len = p->len;
	}
	ReleaseSRWLockShared(&peersLock);
	return r;
}

typedef int(WSAAPI *closesocket_t)(SOCKET);
static closesocket_t real_closesocket;
static int WSAAPI my_closesocket(SOCKET s) {
	AcquireSRWLockExclusive(&peersLock);
	peer *p = findPeer(s, FALSE);
	if (p)
		p->s = GONE;
	ReleaseSRWLockExclusive(&peersLock);
	return real_closesocket(s);
}

typedef DNS_STATUS(WINAPI *DnsQuery_W_t)(PCWSTR, WORD, DWORD, PVOID, PDNS_RECORD *, PVOID *);
static DnsQuery_W_t real_DnsQuery_W;
static DNS_STATUS WINAPI my_DnsQuery_W(PCWSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORD *records, PVOID *reserved) {
	if (!name || !allowed(name))
		return DNS_ERROR_RCODE_NAME_ERROR;
	return real_DnsQuery_W(name, type, options, extra, records, reserved);
}

typedef DNS_STATUS(WINAPI *DnsQuery_A_t)(PCSTR, WORD, DWORD, PVOID, PDNS_RECORD *, PVOID *);
static DnsQuery_A_t real_DnsQuery_A, real_DnsQuery_UTF8;
static DNS_STATUS WINAPI my_DnsQuery_A(PCSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORD *records, PVOID *reserved) {
	if (!name || !allowedA(name))
		return DNS_ERROR_RCODE_NAME_ERROR;
	return real_DnsQuery_A(name, type, options, extra, records, reserved);
}
static DNS_STATUS WINAPI my_DnsQuery_UTF8(PCSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORD *records, PVOID *reserved) {
	if (!name || !allowedA(name))
		return DNS_ERROR_RCODE_NAME_ERROR;
	return real_DnsQuery_UTF8(name, type, options, extra, records, reserved);
}

typedef struct {
	ULONG Version;
	PCWSTR QueryName;
} dns_request;

typedef DNS_STATUS(WINAPI *DnsQueryEx_t)(dns_request *, PDNS_QUERY_RESULT, PVOID);
static DnsQueryEx_t real_DnsQueryEx;
static DNS_STATUS WINAPI my_DnsQueryEx(dns_request *request, PDNS_QUERY_RESULT result, PVOID cancel) {
	if (request && (!request->QueryName || !allowed(request->QueryName))) {
		if (result) {
			result->QueryStatus = DNS_ERROR_RCODE_NAME_ERROR;
			result->pQueryRecords = NULL;
		}
		return DNS_ERROR_RCODE_NAME_ERROR;
	}
	return real_DnsQueryEx(request, result, cancel);
}

static void fakeMac(BYTE *m, ULONG n) {
	if (n != 6 || !(m[0] | m[1] | m[2] | m[3] | m[4] | m[5]))
		return;
	DWORD h = 2166136261u ^ idSeed;
	for (int i = 3; i < 6; i++)
		h = (h ^ m[i]) * 16777619u;
	h ^= h >> 15, h *= 0x2c1b3c6du, h ^= h >> 12;
	m[3] = (BYTE)(h >> 16), m[4] = (BYTE)(h >> 8), m[5] = (BYTE)h;
}

typedef ULONG(WINAPI *GetAdaptersAddresses_t)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
static GetAdaptersAddresses_t real_GetAdaptersAddresses;
static ULONG WINAPI my_GetAdaptersAddresses(ULONG family, ULONG flags, PVOID reserved, PIP_ADAPTER_ADDRESSES list, PULONG size) {
	ULONG r = real_GetAdaptersAddresses(family, flags, reserved, list, size);
	if (r != NO_ERROR || !list)
		return r;
	for (PIP_ADAPTER_ADDRESSES p = list; p; p = p->Next) {
		fakeMac(p->PhysicalAddress, p->PhysicalAddressLength);
		BYTE *d = p->Dhcpv6ClientDuid;
		if (p->Dhcpv6ClientDuidLength == 14 && d[0] == 0 && d[1] == 1) {
			*(DWORD *)(d + 4) ^= idSeed;
			fakeMac(d + 8, 6);
		}
	}
	return NO_ERROR;
}

typedef ULONG(WINAPI *GetAdaptersInfo_t)(PIP_ADAPTER_INFO, PULONG);
static GetAdaptersInfo_t real_GetAdaptersInfo;
static ULONG WINAPI my_GetAdaptersInfo(PIP_ADAPTER_INFO info, PULONG size) {
	ULONG r = real_GetAdaptersInfo(info, size);
	if (r != NO_ERROR || !info)
		return r;
	for (PIP_ADAPTER_INFO p = info; p; p = p->Next)
		fakeMac(p->Address, p->AddressLength);
	return NO_ERROR;
}

static void fakeRow2(MIB_IF_ROW2 *row) {
	fakeMac(row->PhysicalAddress, row->PhysicalAddressLength);
	fakeMac(row->PermanentPhysicalAddress, row->PhysicalAddressLength);
}

typedef NETIO_STATUS(NETIOAPI_API_ *GetIfTable2_t)(PMIB_IF_TABLE2 *);
static GetIfTable2_t real_GetIfTable2;
static NETIO_STATUS NETIOAPI_API_ my_GetIfTable2(PMIB_IF_TABLE2 *table) {
	NETIO_STATUS r = real_GetIfTable2(table);
	if (r == NO_ERROR && table && *table)
		for (ULONG i = 0; i < (*table)->NumEntries; i++)
			fakeRow2(&(*table)->Table[i]);
	return r;
}

typedef NETIO_STATUS(NETIOAPI_API_ *GetIfTable2Ex_t)(MIB_IF_TABLE_LEVEL, PMIB_IF_TABLE2 *);
static GetIfTable2Ex_t real_GetIfTable2Ex;
static NETIO_STATUS NETIOAPI_API_ my_GetIfTable2Ex(MIB_IF_TABLE_LEVEL level, PMIB_IF_TABLE2 *table) {
	NETIO_STATUS r = real_GetIfTable2Ex(level, table);
	if (r == NO_ERROR && table && *table)
		for (ULONG i = 0; i < (*table)->NumEntries; i++)
			fakeRow2(&(*table)->Table[i]);
	return r;
}

typedef NETIO_STATUS(NETIOAPI_API_ *GetIfEntry2_t)(PMIB_IF_ROW2);
static GetIfEntry2_t real_GetIfEntry2;
static NETIO_STATUS NETIOAPI_API_ my_GetIfEntry2(PMIB_IF_ROW2 row) {
	NETIO_STATUS r = real_GetIfEntry2(row);
	if (r == NO_ERROR && row)
		fakeRow2(row);
	return r;
}

typedef NETIO_STATUS(NETIOAPI_API_ *GetIfEntry2Ex_t)(ULONG, PMIB_IF_ROW2);
static GetIfEntry2Ex_t real_GetIfEntry2Ex;
static NETIO_STATUS NETIOAPI_API_ my_GetIfEntry2Ex(ULONG level, PMIB_IF_ROW2 row) {
	NETIO_STATUS r = real_GetIfEntry2Ex(level, row);
	if (r == NO_ERROR && row)
		fakeRow2(row);
	return r;
}

typedef DWORD(WINAPI *GetIfTable_t)(PMIB_IFTABLE, PULONG, BOOL);
static GetIfTable_t real_GetIfTable;
static DWORD WINAPI my_GetIfTable(PMIB_IFTABLE table, PULONG size, BOOL order) {
	DWORD r = real_GetIfTable(table, size, order);
	if (r == NO_ERROR && table)
		for (DWORD i = 0; i < table->dwNumEntries; i++)
			fakeMac(table->table[i].bPhysAddr, table->table[i].dwPhysAddrLen);
	return r;
}

typedef DWORD(WINAPI *GetIfEntry_t)(PMIB_IFROW);
static GetIfEntry_t real_GetIfEntry;
static DWORD WINAPI my_GetIfEntry(PMIB_IFROW row) {
	DWORD r = real_GetIfEntry(row);
	if (r == NO_ERROR && row)
		fakeMac(row->bPhysAddr, row->dwPhysAddrLen);
	return r;
}

static DWORD WINAPI my_SendARP(IPAddr dst, IPAddr src, PVOID mac, PULONG len) {
	return ERROR_BAD_NET_NAME;
}

static NETIO_STATUS NETIOAPI_API_ my_ResolveIpNetEntry2(PMIB_IPNET_ROW2 row, const SOCKADDR_INET *src) {
	return ERROR_BAD_NET_NAME;
}

typedef DWORD(WINAPI *WlanGetNetworkBssList_t)(HANDLE, const GUID *, const PDOT11_SSID, DOT11_BSS_TYPE, BOOL, PVOID, PWLAN_BSS_LIST *);
static WlanGetNetworkBssList_t real_WlanGetNetworkBssList;
static DWORD WINAPI my_WlanGetNetworkBssList(HANDLE h, const GUID *iface, const PDOT11_SSID ssid, DOT11_BSS_TYPE type, BOOL secure, PVOID reserved, PWLAN_BSS_LIST *list) {
	DWORD r = real_WlanGetNetworkBssList(h, iface, ssid, type, secure, reserved, list);
	if (r == ERROR_SUCCESS && list && *list)
		for (DWORD i = 0; i < (*list)->dwNumberOfItems; i++)
			fakeMac((*list)->wlanBssEntries[i].dot11Bssid, 6);
	return r;
}

typedef DWORD(WINAPI *WlanQueryInterface_t)(HANDLE, const GUID *, WLAN_INTF_OPCODE, PVOID, PDWORD, PVOID *, PWLAN_OPCODE_VALUE_TYPE);
static WlanQueryInterface_t real_WlanQueryInterface;
static DWORD WINAPI my_WlanQueryInterface(HANDLE h, const GUID *iface, WLAN_INTF_OPCODE op, PVOID reserved, PDWORD size, PVOID *data, PWLAN_OPCODE_VALUE_TYPE type) {
	DWORD r = real_WlanQueryInterface(h, iface, op, reserved, size, data, type);
	if (r == ERROR_SUCCESS && op == wlan_intf_opcode_current_connection && data && *data && size && *size >= sizeof(WLAN_CONNECTION_ATTRIBUTES))
		fakeMac(((PWLAN_CONNECTION_ATTRIBUTES)*data)->wlanAssociationAttributes.dot11Bssid, 6);
	return r;
}

static ULONG WINAPI my_GetIpNetTable(PVOID table, PULONG size, BOOL order) {
	return ERROR_NO_DATA;
}

static ULONG WINAPI my_GetIpNetTable2(ADDRESS_FAMILY family, PVOID *table) {
	if (table)
		*table = NULL;
	return ERROR_NOT_FOUND;
}

#define S_OVERFLOW ((LONG)0x80000005)
#define S_TOO_SMALL ((LONG)0xC0000023)
#define S_NOT_FOUND ((LONG)0xC0000034)
#define S_DENIED ((LONG)0xC0000022)

typedef struct {
	USHORT Length, MaximumLength;
	PWSTR Buffer;
} ustring;

enum { SZ, DW, QW, BIN, HIDE };

static const DWORD directBlob[14] = {0x46, 1, 1}, zero;

typedef struct {
	const WCHAR *key, *value;
	int kind;
	const void *data;
} fake;

#define CV L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
#define WU L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate"
#define TCP L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define NLS L"SYSTEM\\CurrentControlSet\\Control\\Nls\\"
#define INET L"USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"

static const fake fakes[] = {
	{L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", SZ, idGuid},
	{L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId", SZ, idSqm},
	{CV, L"ProductId", SZ, idProduct},
	{CV, L"InstallDate", DW, &idInstall},
	{CV, L"InstallTime", QW, &idInstallTime},
	{CV, L"RegisteredOwner", SZ, L"user"},
	{CV, L"RegisteredOrganization", SZ, L""},
	{CV, L"DigitalProductId", HIDE, NULL},
	{CV, L"DigitalProductId4", HIDE, NULL},
	{WU, L"SusClientId", SZ, idSus},
	{WU, L"SusClientIdValidation", HIDE, NULL},
	{L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", L"HwProfileGuid", SZ, idHw},
	{L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", L"ComputerName", SZ, idName},
	{L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", L"ComputerName", SZ, idName},
	{TCP, L"Hostname", SZ, idName},
	{TCP, L"NV Hostname", SZ, idName},
	{NLS L"Language", L"Default", SZ, nlsLang},
	{NLS L"Language", L"InstallLanguage", SZ, nlsLang},
	{NLS L"Locale", L"", SZ, nlsLocale},
	{INET, L"ProxyEnable", DW, &zero},
	{INET, L"ProxyServer", HIDE, NULL},
	{INET L"\\Connections", L"DefaultConnectionSettings", BIN, directBlob},
	{INET L"\\Connections", L"SavedLegacySettings", BIN, directBlob},
};

typedef LONG(NTAPI *NtQueryKey_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NtQueryKey_t NtQueryKey;

static BOOL keyIs(HANDLE key, const WCHAR *want) {
	static const WCHAR root[] = L"\\REGISTRY\\MACHINE\\", user[] = L"\\REGISTRY\\USER\\";
	BYTE buf[2048];
	ULONG got;
	WCHAR path[1024];
	if (NtQueryKey(key, 3, buf, sizeof buf - 2, &got) < 0)
		return FALSE;
	ULONG n = *(ULONG *)buf / 2;
	WCHAR *name = (WCHAR *)(buf + 4);
	size_t r = wcslen(root), u = wcslen(user);
	if (n >= 1000)
		return FALSE;
	if (n > u && _wcsnicmp(name, user, u) == 0) {
		WCHAR *rest = wmemchr(name + u, L'\\', n - u);
		if (!rest)
			return FALSE;
		swprintf(path, 1024, L"USER%.*ls", (int)(name + n - rest), rest);
		return _wcsicmp(path, want) == 0;
	}
	if (n < r || _wcsnicmp(name, root, r) != 0)
		return FALSE;
	wmemcpy(path, name + r, n - r);
	path[n - r] = 0;
	if (_wcsnicmp(path, L"SYSTEM\\", 7) == 0) {
		WCHAR *rest = wcschr(path + 7, L'\\');
		WCHAR tail[1024];
		lstrcpynW(tail, rest ? rest : L"", 1024);
		swprintf(path, 1024, L"SYSTEM\\CurrentControlSet%ls", tail);
	} else if (_wcsnicmp(path, L"SOFTWARE\\WOW6432Node\\", 21) == 0) {
		memmove(path + 9, path + 21, (wcslen(path + 21) + 1) * sizeof(WCHAR));
	}
	return _wcsicmp(path, want) == 0;
}

static const fake *lookup(HANDLE key, const WCHAR *name, ULONG bytes) {
	ULONG n = bytes / 2;
	for (size_t i = 0; i < sizeof fakes / sizeof *fakes; i++)
		if (wcslen(fakes[i].value) == n && _wcsnicmp(fakes[i].value, name, n) == 0 && keyIs(key, fakes[i].key))
			return &fakes[i];
	return NULL;
}

static LONG answer(const fake *f, const WCHAR *name, ULONG nameBytes, ULONG cls, PVOID info, ULONG len, PULONG result) {
	ULONG type = REG_NONE, size = 0, head, off;
	const void *data = NULL;
	switch (f->kind) {
	case SZ:
		type = REG_SZ, data = f->data, size = (wcslen(f->data) + 1) * sizeof(WCHAR);
		break;
	case DW:
		type = REG_DWORD, data = f->data, size = 4;
		break;
	case QW:
		type = REG_QWORD, data = f->data, size = 8;
		break;
	case BIN:
		type = REG_BINARY, data = f->data, size = sizeof directBlob;
		break;
	}
	switch (cls) {
	case 1:
		head = 20 + nameBytes, off = (head + 7) & ~7u;
		break;
	case 2:
		head = off = 12;
		break;
	case 4:
		head = off = 8;
		break;
	default:
		return 1;
	}
	if (result)
		*result = off + size;
	if (len < head || !info)
		return S_TOO_SMALL;
	ULONG *h = info;
	switch (cls) {
	case 1:
		h[0] = 0, h[1] = type, h[2] = off, h[3] = size, h[4] = nameBytes;
		memcpy(h + 5, name, nameBytes);
		break;
	case 2:
		h[0] = 0, h[1] = type, h[2] = size;
		break;
	case 4:
		h[0] = type, h[1] = size;
		break;
	}
	if (len < off + size)
		return S_OVERFLOW;
	memcpy((BYTE *)info + off, data, size);
	return 0;
}

static ULONG mix(ULONG x);

static BOOL serialish(const BYTE *s, ULONG n, int step) {
	ULONG k = 0;
	for (ULONG i = 0; i < n && s[i] && s[i] != '\n'; i += step) {
		BYTE c = s[i];
		if (step == 2 && (i + 1 >= n || s[i + 1]))
			return FALSE;
		if (c == ' ' || c == '-' || c == '_' || c == '.')
			continue;
		if (!(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z'))
			return FALSE;
		k++;
	}
	return k >= 4;
}

static void fakeSerial(BYTE *s, ULONG n, int step) {
	if (!serialish(s, n, step))
		return;
	DWORD h = 2166136261u ^ idSeed, k = 0;
	BOOL hex = TRUE;
	for (ULONG i = 0; i < n && s[i] && s[i] != '\n'; i += step)
		if ((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'A' && s[i] <= 'Z')) {
			h = (h ^ s[i]) * 16777619u;
			hex &= s[i] <= 'F';
		}
	for (ULONG i = 0; i < n && s[i] && s[i] != '\n'; i += step) {
		BOOL digit = s[i] >= '0' && s[i] <= '9', upper = s[i] >= 'A' && s[i] <= 'Z';
		if ((!digit && !upper) || k++ < 4)
			continue;
		ULONG r = mix(h + k);
		s[i] = hex ? "0123456789ABCDEF"[r % 16] : digit ? '0' + r % 10 : 'A' + r % 26;
	}
}

static void fakeGuid(BYTE *g) {
	BOOL blank = TRUE;
	for (int i = 1; i < 16; i++)
		blank &= g[i] == g[0];
	if (blank && (g[0] == 0 || g[0] == 0xFF))
		return;
	for (int i = 0; i < 4; i++)
		((ULONG *)g)[i] ^= mix(0x6D1D0000 + i);
}

static void fakeSmbios(BYTE *p, ULONG n) {
	BYTE *end = p + n;
	while (p + 4 <= end) {
		BYTE type = p[0], len = p[1], idx[2] = {0};
		BYTE *str = p + len, *q = str;
		if (len < 4 || str + 1 >= end)
			break;
		while (q + 1 < end && (q[0] || q[1]))
			q++;
		if (q + 1 >= end)
			break;
		switch (type) {
		case 1:
			if (len >= 0x18)
				fakeGuid(p + 8);
			idx[0] = len > 7 ? p[7] : 0;
			break;
		case 2:
		case 3:
			idx[0] = len > 7 ? p[7] : 0, idx[1] = len > 8 ? p[8] : 0;
			break;
		case 4:
			idx[0] = len > 0x20 ? p[0x20] : 0, idx[1] = len > 0x21 ? p[0x21] : 0;
			break;
		case 17:
			idx[0] = len > 0x18 ? p[0x18] : 0, idx[1] = len > 0x19 ? p[0x19] : 0;
			break;
		}
		for (int j = 0; j < 2; j++) {
			BYTE *s = str;
			for (int k = 1; idx[j] && k < idx[j] && s < q; k++)
				s += strlen((char *)s) + 1;
			if (idx[j] && s < q)
				fakeSerial(s, (ULONG)strlen((char *)s), 1);
		}
		if (type == 127)
			break;
		p = q + 2;
	}
}

static void fakeEdid(BYTE *e, ULONG n) {
	static const BYTE head[] = {0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0};
	if (n < 128 || memcmp(e, head, sizeof head) != 0)
		return;
	if (*(ULONG *)(e + 12))
		*(ULONG *)(e + 12) ^= mix(0xED1D);
	for (int d = 54; d <= 108; d += 18)
		if (e[d] == 0 && e[d + 1] == 0 && e[d + 2] == 0 && e[d + 3] == 0xFF)
			fakeSerial(e + d + 5, 13, 1);
	BYTE sum = 0;
	for (int i = 0; i < 127; i++)
		sum += e[i];
	e[127] = (BYTE)(0x100 - sum);
}

static void scrub(const WCHAR *name, ULONG nameBytes, ULONG type, BYTE *data, ULONG size) {
	ULONG n = nameBytes / 2;
	if (n == 4 && _wcsnicmp(name, L"EDID", 4) == 0 && type == REG_BINARY)
		fakeEdid(data, size);
	else if (n == 10 && _wcsnicmp(name, L"SMBiosData", 10) == 0 && type == REG_BINARY && size > 8)
		fakeSmbios(data + 8, size - 8);
	else if (n == 12 && _wcsnicmp(name, L"SerialNumber", 12) == 0 && type == REG_SZ)
		fakeSerial(data, size, 2);
}

static void scrubInfo(const WCHAR *name, ULONG nameBytes, ULONG cls, PVOID info, ULONG len) {
	ULONG *h = info;
	if (cls == 1 && len >= 20 && h[2] <= len && h[3] <= len - h[2])
		scrub(name, nameBytes, h[1], (BYTE *)info + h[2], h[3]);
	else if (cls == 2 && len >= 12 && h[2] <= len - 12)
		scrub(name, nameBytes, h[1], (BYTE *)info + 12, h[2]);
	else if (cls == 4 && len >= 8 && h[1] <= len - 8)
		scrub(name, nameBytes, h[0], (BYTE *)info + 8, h[1]);
}

typedef LONG(NTAPI *NtQueryValueKey_t)(HANDLE, ustring *, ULONG, PVOID, ULONG, PULONG);
static NtQueryValueKey_t real_NtQueryValueKey;
static LONG NTAPI my_NtQueryValueKey(HANDLE key, ustring *value, ULONG cls, PVOID info, ULONG len, PULONG result) {
	const fake *f = value && value->Buffer ? lookup(key, value->Buffer, value->Length) : NULL;
	if (f) {
		if (f->kind == HIDE)
			return S_NOT_FOUND;
		LONG s = answer(f, value->Buffer, value->Length, cls, info, len, result);
		if (s != 1)
			return s;
	}
	LONG s = real_NtQueryValueKey(key, value, cls, info, len, result);
	if (s >= 0 && f == NULL && value && value->Buffer && info)
		scrubInfo(value->Buffer, value->Length, cls, info, len);
	return s;
}

typedef LONG(NTAPI *NtEnumerateValueKey_t)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
static NtEnumerateValueKey_t real_NtEnumerateValueKey;
static LONG NTAPI my_NtEnumerateValueKey(HANDLE key, ULONG index, ULONG cls, PVOID info, ULONG len, PULONG result) {
	ULONG basic[160], got;
	BOOL named = cls != 0 && real_NtEnumerateValueKey(key, index, 0, basic, sizeof basic, &got) >= 0;
	if (named) {
		const fake *f = lookup(key, (WCHAR *)(basic + 3), basic[2]);
		if (f) {
			LONG s = answer(f, (WCHAR *)(basic + 3), basic[2], cls, info, len, result);
			if (s != 1)
				return s;
		}
	}
	LONG s = real_NtEnumerateValueKey(key, index, cls, info, len, result);
	if (s >= 0 && named && info)
		scrubInfo((WCHAR *)(basic + 3), basic[2], cls, info, len);
	return s;
}

static ULONG mix(ULONG x) {
	ULONGLONG z = ((ULONGLONG)x << 32 | idSeed) + 0x9E3779B97F4A7C15ULL;
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return (ULONG)(z ^ (z >> 31));
}

typedef LONG(NTAPI *NtQueryVolumeInformationFile_t)(HANDLE, PVOID, PVOID, ULONG, ULONG);
static NtQueryVolumeInformationFile_t real_NtQueryVolumeInformationFile;
static LONG NTAPI my_NtQueryVolumeInformationFile(HANDLE file, PVOID io, PVOID info, ULONG len, ULONG cls) {
	LONG s = real_NtQueryVolumeInformationFile(file, io, info, len, cls);
	if ((s >= 0 || s == S_OVERFLOW) && info) {
		if (cls == 1 && len >= 12) {
			memcpy(info, &idInstallTime, 8);
			ULONG *serial = (ULONG *)((BYTE *)info + 8);
			*serial = mix(*serial);
		} else if (cls == 8) {
			for (ULONG i = 0; i + 4 <= len && i < 64; i += 4)
				*(ULONG *)((BYTE *)info + i) = mix(i);
		}
	}
	return s;
}

typedef LONG(NTAPI *NtQueryInformationFile_t)(HANDLE, PVOID, PVOID, ULONG, ULONG);
static NtQueryInformationFile_t real_NtQueryInformationFile;
static LONG NTAPI my_NtQueryInformationFile(HANDLE file, PVOID io, PVOID info, ULONG len, ULONG cls) {
	LONG s = real_NtQueryInformationFile(file, io, info, len, cls);
	if (cls == 59 && s >= 0 && info && len >= 8) {
		ULONG *serial = info;
		serial[0] = mix(serial[0]);
		if (serial[1])
			serial[1] = mix(serial[1] ^ 0xA5A5A5A5);
	}
	return s;
}

typedef LONG(NTAPI *NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
static NtQuerySystemInformation_t real_NtQuerySystemInformation;
static LONG NTAPI my_NtQuerySystemInformation(ULONG cls, PVOID info, ULONG len, PULONG result) {
	ULONG *t = info;
	if (cls == 76 && t && len >= 16 && t[0] == 0x41435049 && t[1] == 1 && (t[2] == 0x4D44534D || t[2] == 0x4D53444D))
		return S_NOT_FOUND;
	LONG s = real_NtQuerySystemInformation(cls, info, len, result);
	if (cls == 3 && s >= 0 && info && len >= sizeof(LONGLONG))
		*(LONGLONG *)info -= tickOffset * 10000;
	if (cls == 76 && s >= 0 && t && len >= 24 && t[0] == 0x52534D42 && t[1] == 1 && t[3] > 8 && t[3] <= len - 16)
		fakeSmbios((BYTE *)(t + 4) + 8, t[3] - 8);
	return s;
}

typedef ULONGLONG(WINAPI *GetTickCount64_t)(void);
static GetTickCount64_t real_GetTickCount64;
static ULONGLONG WINAPI my_GetTickCount64(void) {
	return real_GetTickCount64() + tickOffset;
}

static DWORD WINAPI my_GetTickCount(void) {
	return (DWORD)my_GetTickCount64();
}

typedef LONG(NTAPI *NtQueryDefaultLocale_t)(BOOLEAN, LCID *);
static NtQueryDefaultLocale_t real_NtQueryDefaultLocale;
static LONG NTAPI my_NtQueryDefaultLocale(BOOLEAN user, LCID *lcid) {
	LONG s = real_NtQueryDefaultLocale(user, lcid);
	if (s >= 0 && !user)
		*lcid = sysLcid;
	return s;
}

static LONG NTAPI my_NtQueryInstallUILanguage(LANGID *lang) {
	*lang = LANGIDFROMLCID(sysLcid);
	return 0;
}

static LCID WINAPI my_GetSystemDefaultLCID(void) {
	return sysLcid;
}

static LANGID WINAPI my_GetSystemDefaultLangID(void) {
	return LANGIDFROMLCID(sysLcid);
}

static int WINAPI my_GetSystemDefaultLocaleName(LPWSTR name, int len) {
	int n = (int)wcslen(sysLocale) + 1;
	if (!name || len < n) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}
	wmemcpy(name, sysLocale, n);
	return n;
}

typedef BOOL(WINAPI *DeviceIoControl_t)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static DeviceIoControl_t real_DeviceIoControl;
static BOOL WINAPI my_DeviceIoControl(HANDLE dev, DWORD code, LPVOID in, DWORD inLen, LPVOID out, DWORD outLen, LPDWORD ret, LPOVERLAPPED ov) {
	STORAGE_PROPERTY_QUERY *q = in;
	BOOL storage = code == IOCTL_STORAGE_QUERY_PROPERTY && q && inLen >= 8;
	if (storage && (q->PropertyId == StorageDeviceIdProperty || q->PropertyId == StorageDeviceUniqueIdProperty)) {
		SetLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}
	BOOL ok = real_DeviceIoControl(dev, code, in, inLen, out, outLen, ret, ov);
	if (ok && storage && q->PropertyId == StorageDeviceProperty && q->QueryType == PropertyStandardQuery && out && outLen >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
		STORAGE_DEVICE_DESCRIPTOR *d = out;
		DWORD n = ret ? *ret : outLen;
		if (d->SerialNumberOffset && d->SerialNumberOffset < n && n <= outLen)
			fakeSerial((BYTE *)out + d->SerialNumberOffset, n - d->SerialNumberOffset, 1);
	}
	DWORD n = ret ? *ret : 0;
	BYTE *o = out, *i = in;
	if (!ok || !o || n > outLen)
		return ok;
	if (storage && (q->PropertyId == 49 || q->PropertyId == 50) && n >= 32) {
		ULONG *pd = (ULONG *)(o + 8), off = pd[4], size = pd[5];
		if (pd[0] == 3 && pd[1] == 1 && off <= n - 8 && size <= n - 8 - off) {
			BYTE *data = o + 8 + off;
			if (pd[2] == 1 && size >= 24)
				fakeSerial(data + 4, 20, 1);
			else if (pd[2] == 0 && size >= 128) {
				fakeGuid(data + 104);
				*(ULONG *)(data + 120) ^= mix(0xE064), *(ULONG *)(data + 124) ^= mix(0xE065);
			}
		}
	} else if (code == SMART_RCV_DRIVE_DATA && i && inLen >= 11 && i[10] == ID_CMD && n >= 16 + 40)
		fakeSerial(o + 16 + 20, 20, 1);
	else if (code == IOCTL_DISK_GET_DRIVE_LAYOUT_EX && n >= 48) {
		ULONG style = *(ULONG *)o, count = *(ULONG *)(o + 4);
		if (style == PARTITION_STYLE_MBR)
			*(ULONG *)(o + 8) ^= mix(0xD15C);
		else if (style == PARTITION_STYLE_GPT)
			fakeGuid(o + 8);
		for (ULONG k = 0; k < count && 48 + (k + 1) * 144 <= n; k++)
			if (*(ULONG *)(o + 48 + k * 144) == PARTITION_STYLE_GPT)
				fakeGuid(o + 48 + k * 144 + 32 + 16);
	} else if (code == IOCTL_DISK_GET_PARTITION_INFO_EX && n >= 144 && *(ULONG *)o == PARTITION_STYLE_GPT)
		fakeGuid(o + 32 + 16);
	return ok;
}

static WCHAR realName[MAX_COMPUTERNAME_LENGTH + 1];

typedef struct {
	ustring Name;
	PSID Sid;
} trust;

typedef struct {
	ULONG Entries;
	trust *Domains;
} domains;

static void renameDomains(domains *list) {
	for (ULONG i = 0; list && i < list->Entries; i++) {
		ustring *n = &list->Domains[i].Name;
		if (n->Buffer && n->Length == wcslen(realName) * 2 && _wcsnicmp(n->Buffer, realName, n->Length / 2) == 0) {
			n->Buffer = idName;
			n->Length = n->MaximumLength = wcslen(idName) * 2;
		}
	}
}

typedef LONG(NTAPI *LsaLookupSids_t)(HANDLE, ULONG, PSID *, domains **, PVOID *);
static LsaLookupSids_t real_LsaLookupSids;
static LONG NTAPI my_LsaLookupSids(HANDLE policy, ULONG count, PSID *sids, domains **list, PVOID *names) {
	LONG s = real_LsaLookupSids(policy, count, sids, list, names);
	if (s >= 0 && list)
		renameDomains(*list);
	return s;
}

typedef LONG(NTAPI *LsaLookupSids2_t)(HANDLE, ULONG, ULONG, PSID *, domains **, PVOID *);
static LsaLookupSids2_t real_LsaLookupSids2;
static LONG NTAPI my_LsaLookupSids2(HANDLE policy, ULONG options, ULONG count, PSID *sids, domains **list, PVOID *names) {
	LONG s = real_LsaLookupSids2(policy, options, count, sids, list, names);
	if (s >= 0 && list)
		renameDomains(*list);
	return s;
}

typedef BOOL(WINAPI *LookupAccountSidW_t)(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
static LookupAccountSidW_t real_LookupAccountSidW;
static BOOL WINAPI my_LookupAccountSidW(LPCWSTR system, PSID sid, LPWSTR name, LPDWORD nameLen, LPWSTR domain, LPDWORD domainLen, PSID_NAME_USE use) {
	DWORD cap = domainLen ? *domainLen : 0;
	BOOL ok = real_LookupAccountSidW(system, sid, name, nameLen, domain, domainLen, use);
	if (ok && domain && _wcsicmp(domain, realName) == 0 && wcslen(idName) < cap) {
		lstrcpyW(domain, idName);
		*domainLen = wcslen(idName);
	}
	return ok;
}

static BOOL readId(LPCWSTR name, WCHAR *out, DWORD cap) {
	DWORD size = cap * sizeof(WCHAR);
	return RegGetValueW(HKEY_CURRENT_USER, L"Software\\Airlock", name, RRF_RT_REG_SZ, NULL, out, &size) == ERROR_SUCCESS && *out;
}

static BOOL loadIdentity(void) {
	DWORD size = sizeof idInstall;
	if (!readId(L"MachineGuid", idGuid, 64) || !readId(L"ComputerName", idName, 32) || !readId(L"ProductId", idProduct, 32) || !readId(L"SusClientId", idSus, 64) || !readId(L"HwProfileGuid", idHw, 64) || !readId(L"SqmMachineId", idSqm, 64))
		return FALSE;
	if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Airlock", L"InstallDate", RRF_RT_REG_DWORD, NULL, &idInstall, &size) != ERROR_SUCCESS)
		return FALSE;
	size = sizeof idSeed;
	if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Airlock", L"Seed", RRF_RT_REG_DWORD, NULL, &idSeed, &size) != ERROR_SUCCESS)
		return FALSE;
	size = sizeof gatePort;
	if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Airlock", L"Gate", RRF_RT_REG_DWORD, NULL, &gatePort, &size) != ERROR_SUCCESS)
		return FALSE;
	idInstallTime = (ULONGLONG)idInstall * 10000000ULL + 116444736000000000ULL;
	DWORD boot = 0;
	size = sizeof boot;
	RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", L"BootId", RRF_RT_REG_DWORD, NULL, &boot, &size);
	ULONGLONG x = ((ULONGLONG)idSeed << 32 | boot) * 0x9E3779B97F4A7C15ULL;
	x = (x ^ x >> 30) * 0xBF58476D1CE4E5B9ULL;
	x ^= x >> 31;
	tickOffset = (2 * 3600 + x % (5 * 86400)) * 1000ULL;
	WCHAR lang[LOCALE_NAME_MAX_LENGTH];
	if (GetEnvironmentVariableW(L"AIRLOCK_LANG", lang, LOCALE_NAME_MAX_LENGTH) - 1 < LOCALE_NAME_MAX_LENGTH - 1)
		wcscpy(sysLocale, lang);
	if (!(sysLcid = LocaleNameToLCID(sysLocale, 0)))
		return FALSE;
	swprintf(nlsLang, 8, L"%04X", LANGIDFROMLCID(sysLcid));
	swprintf(nlsLocale, 16, L"%08X", sysLcid);
	size = sizeof realName;
	if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", L"ComputerName", RRF_RT_REG_SZ, NULL, realName, &size) != ERROR_SUCCESS)
		return FALSE;
	NtQueryKey = (NtQueryKey_t)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryKey");
	return NtQueryKey != NULL;
}

static BOOL openLink(LPCWSTR file) {
	WCHAR url[4096], line[4400];
	if (!file)
		return FALSE;
	size_t n = wcslen(file);
	if (*file == L'"') {
		file++, n--;
		if (n && file[n - 1] == L'"')
			n--;
	}
	if (n == 0 || n >= 4096)
		return FALSE;
	wmemcpy(url, file, n);
	url[n] = 0;
	if ((_wcsnicmp(url, L"https://", 8) && _wcsnicmp(url, L"http://", 7)) || wcschr(url, L'"'))
		return FALSE;
	swprintf(line, 4400, L"\"%ls\" browser-host \"%ls\"", helper, url);
	STARTUPINFOW si = {sizeof si};
	PROCESS_INFORMATION pi;
	if (!CreateProcessW(helper, line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
		return FALSE;
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return TRUE;
}

typedef HINSTANCE(WINAPI *ShellExecuteW_t)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
static ShellExecuteW_t real_ShellExecuteW;
static HINSTANCE WINAPI my_ShellExecuteW(HWND wnd, LPCWSTR verb, LPCWSTR file, LPCWSTR params, LPCWSTR dir, INT show) {
	if ((!verb || _wcsicmp(verb, L"open") == 0) && openLink(file))
		return (HINSTANCE)42;
	return real_ShellExecuteW(wnd, verb, file, params, dir, show);
}

typedef BOOL(WINAPI *ShellExecuteExW_t)(SHELLEXECUTEINFOW *);
static ShellExecuteExW_t real_ShellExecuteExW;
static BOOL WINAPI my_ShellExecuteExW(SHELLEXECUTEINFOW *e) {
	if (e && !(e->fMask & (SEE_MASK_CLASSNAME | SEE_MASK_CLASSKEY | SEE_MASK_IDLIST)) && (!e->lpVerb || _wcsicmp(e->lpVerb, L"open") == 0) && openLink(e->lpFile)) {
		e->hInstApp = (HINSTANCE)42;
		if (e->fMask & SEE_MASK_NOCLOSEPROCESS)
			e->hProcess = NULL;
		return TRUE;
	}
	return real_ShellExecuteExW(e);
}

static DWORD WINAPI no_icmp(void) {
	SetLastError(ERROR_ACCESS_DENIED);
	return 0;
}

static BOOL WINAPI no_tray(DWORD message, PNOTIFYICONDATAW data) {
	return TRUE;
}

static BOOL inject(HANDLE proc, LPCWSTR dll) {
	SIZE_T size = (wcslen(dll) + 1) * sizeof(WCHAR);
	LPVOID mem = VirtualAllocEx(proc, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!mem)
		return FALSE;
	BOOL ok = FALSE;
	LPTHREAD_START_ROUTINE load = (LPTHREAD_START_ROUTINE)(void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	HANDLE t;
	if (WriteProcessMemory(proc, mem, dll, size, NULL) && (t = CreateRemoteThread(proc, NULL, 0, load, mem, 0, NULL))) {
		DWORD code = 0;
		ok = WaitForSingleObject(t, 15000) == WAIT_OBJECT_0 && GetExitCodeThread(t, &code) && code != 0;
		CloseHandle(t);
	}
	if (ok)
		VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
	return ok;
}

static BOOL claudeApp(const WCHAR *path) {
	WCHAR dir[MAX_PATH];
	if (_wcsicmp(base(path), L"claude.exe") != 0)
		return FALSE;
	lstrcpynW(dir, path, MAX_PATH);
	*(WCHAR *)base(dir) = 0;
	size_t n = wcslen(dir);
	if (n)
		dir[n - 1] = 0;
	WCHAR *app = (WCHAR *)base(dir);
	if (_wcsnicmp(app, L"app-", 4) != 0)
		return FALSE;
	*app = 0;
	n = wcslen(dir);
	if (n)
		dir[n - 1] = 0;
	return _wcsicmp(base(dir), L"AnthropicClaude") == 0;
}

static LPCWSTR choose(LPCWSTR app, LPCWSTR cmd) {
	WCHAR first[MAX_PATH] = L"", child[MAX_PATH], own[MAX_PATH];
	if (app && *app) {
		lstrcpynW(first, app, MAX_PATH);
	} else if (cmd) {
		const WCHAR *s = cmd, *e;
		if (*s == L'"')
			e = wcschr(++s, L'"');
		else
			e = wcschr(s, L' ');
		size_t n = e ? (size_t)(e - s) : wcslen(s);
		if (n >= MAX_PATH)
			return icmp;
		wmemcpy(first, s, n);
		first[n] = 0;
	}
	if (!GetFullPathNameW(first, MAX_PATH, child, NULL))
		return icmp;
	if (_wcsicmp(child, helper) == 0)
		return NULL;
	if (cmd && wcsstr(cmd, L"--type=") && !wcsstr(cmd, L"network.mojom.NetworkService") && !wcsstr(cmd, L"node.mojom.NodeService"))
		return NULL;
	if (!claudeApp(child)) {
		if (!full || _wcsicmp(base(child), base(image)) != 0)
			return icmp;
		lstrcpyW(own, image);
		*(WCHAR *)base(own) = 0;
		*(WCHAR *)base(child) = 0;
		if (_wcsicmp(child, own) != 0)
			return icmp;
	}
	return hookDll;
}

typedef BOOL(WINAPI *CreateProcessInternalW_t)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);
static CreateProcessInternalW_t real_CreateProcessInternalW;
static BOOL WINAPI my_CreateProcessInternalW(HANDLE token, LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi, PHANDLE newToken) {
	LPCWSTR dll = choose(app, cmd);
	if (!real_CreateProcessInternalW(token, app, cmd, pa, ta, inherit, dll ? flags | CREATE_SUSPENDED : flags, env, dir, si, pi, newToken))
		return FALSE;
	if (dll) {
		BOOL wow = FALSE;
		IsWow64Process(pi->hProcess, &wow);
		if (!wow && !inject(pi->hProcess, dll) && dll == hookDll) {
			TerminateProcess(pi->hProcess, 1);
			CloseHandle(pi->hThread);
			CloseHandle(pi->hProcess);
			SetLastError(ERROR_ACCESS_DENIED);
			return FALSE;
		}
		if (!(flags & CREATE_SUSPENDED))
			ResumeThread(pi->hThread);
	}
	return TRUE;
}

static BOOL hook(LPCWSTR module, LPCSTR name, LPVOID detour, LPVOID *real) {
	return MH_CreateHookApi(module, name, detour, real) == MH_OK;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
	if (reason != DLL_PROCESS_ATTACH)
		return TRUE;
	DisableThreadLibraryCalls(inst);
	imports[0] = (void *)getaddrinfo, imports[1] = (void *)GetAdaptersAddresses, imports[2] = (void *)DnsQuery_W, imports[3] = (void *)ShellExecuteW, imports[4] = (void *)WlanQueryInterface;
	if (!GetModuleFileNameW(inst, self, MAX_PATH) || !GetModuleFileNameW(NULL, image, MAX_PATH))
		return FALSE;
	full = _wcsicmp(base(self), L"airlockhook.dll") == 0;
	lstrcpynW(helper, self, MAX_PATH);
	lstrcpyW((LPWSTR)base(helper), L"airlockw.exe");
	lstrcpynW(icmp, self, MAX_PATH);
	lstrcpyW((LPWSTR)base(icmp), L"airlockicmp.dll");
	lstrcpynW(hookDll, self, MAX_PATH);
	lstrcpyW((LPWSTR)base(hookDll), L"airlockhook.dll");
	if (!loadIdentity() || MH_Initialize() != MH_OK)
		return FALSE;
	if (claudeApp(image))
		RegSetKeyValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\DirectX\\UserGpuPreferences", image, REG_SZ, L"GpuPreference=1;", sizeof L"GpuPreference=1;");
	BOOL ok = hook(L"iphlpapi", "IcmpSendEcho", no_icmp, NULL) &&
		  hook(L"iphlpapi", "IcmpSendEcho2", no_icmp, NULL) &&
		  hook(L"iphlpapi", "IcmpSendEcho2Ex", no_icmp, NULL) &&
		  hook(L"iphlpapi", "Icmp6SendEcho2", no_icmp, NULL) &&
		  hook(L"iphlpapi", "GetAdaptersAddresses", my_GetAdaptersAddresses, (LPVOID *)&real_GetAdaptersAddresses) &&
		  hook(L"iphlpapi", "GetAdaptersInfo", my_GetAdaptersInfo, (LPVOID *)&real_GetAdaptersInfo) &&
		  hook(L"iphlpapi", "GetIpNetTable", my_GetIpNetTable, NULL) &&
		  hook(L"iphlpapi", "GetIpNetTable2", my_GetIpNetTable2, NULL) &&
		  hook(L"iphlpapi", "GetIfTable2", my_GetIfTable2, (LPVOID *)&real_GetIfTable2) &&
		  hook(L"iphlpapi", "GetIfTable2Ex", my_GetIfTable2Ex, (LPVOID *)&real_GetIfTable2Ex) &&
		  hook(L"iphlpapi", "GetIfEntry2", my_GetIfEntry2, (LPVOID *)&real_GetIfEntry2) &&
		  hook(L"iphlpapi", "GetIfEntry2Ex", my_GetIfEntry2Ex, (LPVOID *)&real_GetIfEntry2Ex) &&
		  hook(L"iphlpapi", "GetIfTable", my_GetIfTable, (LPVOID *)&real_GetIfTable) &&
		  hook(L"iphlpapi", "GetIfEntry", my_GetIfEntry, (LPVOID *)&real_GetIfEntry) &&
		  hook(L"iphlpapi", "SendARP", my_SendARP, NULL) &&
		  hook(L"iphlpapi", "ResolveIpNetEntry2", my_ResolveIpNetEntry2, NULL) &&
		  hook(L"wlanapi", "WlanGetNetworkBssList", my_WlanGetNetworkBssList, (LPVOID *)&real_WlanGetNetworkBssList) &&
		  hook(L"wlanapi", "WlanQueryInterface", my_WlanQueryInterface, (LPVOID *)&real_WlanQueryInterface) &&
		  hook(L"ntdll", "NtQueryValueKey", my_NtQueryValueKey, (LPVOID *)&real_NtQueryValueKey) &&
		  hook(L"ntdll", "NtEnumerateValueKey", my_NtEnumerateValueKey, (LPVOID *)&real_NtEnumerateValueKey) &&
		  hook(L"ntdll", "NtQueryVolumeInformationFile", my_NtQueryVolumeInformationFile, (LPVOID *)&real_NtQueryVolumeInformationFile) &&
		  hook(L"ntdll", "NtQueryInformationFile", my_NtQueryInformationFile, (LPVOID *)&real_NtQueryInformationFile) &&
		  hook(L"ntdll", "NtQuerySystemInformation", my_NtQuerySystemInformation, (LPVOID *)&real_NtQuerySystemInformation) &&
		  hook(L"kernel32", "GetTickCount64", my_GetTickCount64, (LPVOID *)&real_GetTickCount64) &&
		  hook(L"kernel32", "GetTickCount", my_GetTickCount, NULL) &&
		  hook(L"ntdll", "NtQueryDefaultLocale", my_NtQueryDefaultLocale, (LPVOID *)&real_NtQueryDefaultLocale) &&
		  hook(L"ntdll", "NtQueryInstallUILanguage", my_NtQueryInstallUILanguage, NULL) &&
		  hook(L"kernelbase", "GetSystemDefaultLCID", my_GetSystemDefaultLCID, NULL) &&
		  hook(L"kernelbase", "GetSystemDefaultLangID", my_GetSystemDefaultLangID, NULL) &&
		  hook(L"kernelbase", "GetSystemDefaultUILanguage", my_GetSystemDefaultLangID, NULL) &&
		  hook(L"kernelbase", "GetSystemDefaultLocaleName", my_GetSystemDefaultLocaleName, NULL) &&
		  hook(L"kernelbase", "DeviceIoControl", my_DeviceIoControl, (LPVOID *)&real_DeviceIoControl) &&
		  hook(L"advapi32", "LookupAccountSidW", my_LookupAccountSidW, (LPVOID *)&real_LookupAccountSidW) &&
		  hook(L"advapi32", "LsaLookupSids", my_LsaLookupSids, (LPVOID *)&real_LsaLookupSids) &&
		  hook(L"advapi32", "LsaLookupSids2", my_LsaLookupSids2, (LPVOID *)&real_LsaLookupSids2) &&
		  hook(L"kernelbase", "CreateProcessInternalW", my_CreateProcessInternalW, (LPVOID *)&real_CreateProcessInternalW) &&
		  hook(L"ws2_32", "connect", my_connect, (LPVOID *)&real_connect) &&
		  hook(L"ws2_32", "WSAConnect", my_WSAConnect, (LPVOID *)&real_WSAConnect) &&
		  hook(L"ws2_32", "WSAIoctl", my_WSAIoctl, (LPVOID *)&real_WSAIoctl) &&
		  hook(L"ws2_32", "getpeername", my_getpeername, (LPVOID *)&real_getpeername) &&
		  hook(L"ws2_32", "closesocket", my_closesocket, (LPVOID *)&real_closesocket) &&
		  hook(L"ws2_32", "getaddrinfo", my_getaddrinfo, (LPVOID *)&real_getaddrinfo) &&
		  hook(L"ws2_32", "GetAddrInfoW", my_GetAddrInfoW, (LPVOID *)&real_GetAddrInfoW) &&
		  hook(L"ws2_32", "GetAddrInfoExW", my_GetAddrInfoExW, (LPVOID *)&real_GetAddrInfoExW) &&
		  hook(L"ws2_32", "GetAddrInfoExA", my_GetAddrInfoExA, (LPVOID *)&real_GetAddrInfoExA) &&
		  hook(L"ws2_32", "gethostbyname", my_gethostbyname, (LPVOID *)&real_gethostbyname) &&
		  hook(L"dnsapi", "DnsQuery_W", my_DnsQuery_W, (LPVOID *)&real_DnsQuery_W) &&
		  hook(L"dnsapi", "DnsQuery_A", my_DnsQuery_A, (LPVOID *)&real_DnsQuery_A) &&
		  hook(L"dnsapi", "DnsQuery_UTF8", my_DnsQuery_UTF8, (LPVOID *)&real_DnsQuery_UTF8) &&
		  hook(L"dnsapi", "DnsQueryEx", my_DnsQueryEx, (LPVOID *)&real_DnsQueryEx);
	if (ok && full)
		ok = hook(L"shell32", "ShellExecuteW", my_ShellExecuteW, (LPVOID *)&real_ShellExecuteW) &&
		     hook(L"shell32", "ShellExecuteExW", my_ShellExecuteExW, (LPVOID *)&real_ShellExecuteExW) &&
		     hook(L"shell32", "Shell_NotifyIconW", no_tray, NULL);
	return ok && MH_EnableHook(MH_ALL_HOOKS) == MH_OK;
}