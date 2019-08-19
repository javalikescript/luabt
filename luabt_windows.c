#include "luamod.h"

#include <windows.h>
#include <io.h>

// Link to ws2_32.lib
#include <Winsock2.h>
#include <Ws2bth.h>
// Link to Bthprops.lib
#include <BluetoothAPIs.h>

#include "luabt_base.c"


static char * format_error(DWORD err) {
	DWORD ret = 0;
	static char errbuf[MAX_PATH+1] = {0};
	static char retbuf[MAX_PATH+1] = {0};
	ret = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, errbuf, MAX_PATH, NULL);
	if (ret >= 2) {
		/* discard CRLF characters */
		errbuf[ret-2] = 0;
	} else {
		strcpy(errbuf, "n/a");
	}
	snprintf(retbuf, MAX_PATH, "\"%s\" (%lu)", errbuf, err);
	return retbuf;
}

static char * last_error(void) {
	return format_error(GetLastError());
}

static char * last_wsa_error(void) {
	return format_error(WSAGetLastError());
}

static void ba2str(BTH_ADDR ba, char *addr, size_t len) {
	int i;
	unsigned char bytes[6];
	for (i = 0; i < 6; i++) {
		bytes[5-i] = (unsigned char) ((ba >> (i*8)) & 0xff);
	}
	sprintf_s(addr, len, "%02X:%02X:%02X:%02X:%02X:%02X", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
}

static int str2uuid(const char *uuid_str, GUID *uuid) {
	// Parse uuid128 standard format: 12345678-9012-3456-7890-123456789012
	int i;
	char buf[20] = { 0 };

	if ((strlen(uuid_str) == 4) || (strlen(uuid_str) == 8)) {
		uuid->Data1 = strtoul(uuid_str, NULL, 16);
		// -0000-1000-8000-00805F9B34FB
		uuid->Data2 = 0x0000;
		uuid->Data3 = 0x1000;
		uuid->Data4[0] = 0x80;
		uuid->Data4[1] = 0x00;
		uuid->Data4[2] = 0x00;
		uuid->Data4[3] = 0x80;
		uuid->Data4[4] = 0x5F;
		uuid->Data4[5] = 0x9B;
		uuid->Data4[6] = 0x34;
		uuid->Data4[7] = 0xFB;
		return 0;
	}

	if ((strlen(uuid_str) != 36) || (uuid_str[8] != '-') || (uuid_str[13] != '-') || (uuid_str[18] != '-') || (uuid_str[23] != '-' )) {
		return 1;
	}

	strncpy_s(buf, _countof(buf), uuid_str, 8);
	uuid->Data1 = strtoul(buf, NULL, 16);
	memset(buf, 0, sizeof(buf));

	strncpy_s(buf, _countof(buf), uuid_str + 9, 4);
	uuid->Data2 = (unsigned short) strtoul(buf, NULL, 16);
	memset(buf, 0, sizeof(buf));

	strncpy_s(buf, _countof(buf), uuid_str + 14, 4);
	uuid->Data3 = (unsigned short) strtoul(buf, NULL, 16);
	memset(buf, 0, sizeof(buf));

	strncpy_s(buf, _countof(buf), uuid_str + 19, 4);
	strncpy_s(buf+4, _countof(buf) - 4, uuid_str + 24, 12);

	for (i = 0; i < 8; i++) {
		char buf2[3] = { buf[2*i], buf[2*i+1], 0 };
		uuid->Data4[i] = (unsigned char)strtoul(buf2, NULL, 16);
	}
	return 0;
}

static int bt_startup(void) {
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 0);
	int errorCode;
	errorCode = WSAStartup(wVersionRequested, &wsaData);
	if (errorCode != 0) {
		trace("bt_startup failure, due to WSAStartup error code: %d\n", errorCode);
		return 0;
	}
	trace("bt_startup() success\n");
	return 1;
}

static int bt_cleanup(void) {
	WSACleanup();
	trace("bt_cleanup() success\n");
	return 1;
}

static int _check_socket_type(lua_State *l, int index) {
	static const char *TYPE_OPTIONS[] = { BT_SOCK_TYPE_KEY_DGRAM, BT_SOCK_TYPE_KEY_RAW, BT_SOCK_TYPE_KEY_RDM, BT_SOCK_TYPE_KEY_SEQPACKET, BT_SOCK_TYPE_KEY_STREAM, NULL };
	static const int TYPE_VALUES[] = { SOCK_DGRAM, SOCK_RAW, SOCK_RDM, SOCK_SEQPACKET, SOCK_STREAM };
	int type;
	if (lua_isinteger(l, index)) {
		type = luaL_checkinteger(l, index);
	} else {
		type = TYPE_VALUES[luaL_checkoption(l, index, BT_SOCK_TYPE_KEY_RAW, TYPE_OPTIONS)];
	}
	trace("_check_socket_type(#%d) => %d\n", index, type);
	return type;
}

static int _check_proto(lua_State *l, int index) {
	static const char *PROTO_OPTIONS[] = { BT_PROTO_KEY_HCI, BT_PROTO_KEY_L2CAP, BT_PROTO_KEY_RFCOMM, NULL };
	static const int PROTO_VALUES[] = { -1, BTHPROTO_L2CAP, BTHPROTO_RFCOMM };
	int proto;
	if (lua_isinteger(l, index)) {
		proto = luaL_checkinteger(l, index);
	} else {
		proto = PROTO_VALUES[luaL_checkoption(l, index, BT_PROTO_KEY_RFCOMM, PROTO_OPTIONS)];
	}
	trace("_check_proto(#%d) => %d\n", index, proto);
	return proto;
}

static int bt_socket(lua_State *l) {
	int sockfd = -1;
	int type = _check_socket_type(l, 1);
	int proto = _check_proto(l, 2);
	if (proto < 0) {
		RETURN_ERROR(l, "Unsupported protocol")
	}
	sockfd = socket(AF_BTH, type, proto);
	trace("bt_socket(%d, %d) => %d\n", type, proto, sockfd);
	if (sockfd == SOCKET_ERROR) {
		RETURN_ERROR(l, last_wsa_error())
	}
	lua_pushinteger(l, sockfd);
	return 1;
}

static int bt_bind(lua_State *l) {
	SOCKADDR_BTH sa = { 0 };
	int sa_len = sizeof(sa);
	int sockfd = luaL_checkinteger(l, 1);
	int proto = _check_proto(l, 2);
	const char *addrstr = luaL_checkstring(l, 3);
	int port = luaL_checkinteger(l, 4);
	//if (port == 0) {port = BT_PORT_ANY;}
	trace("bt_bind(%d, \"%s\", %d)\n", sockfd, addrstr, port);
	if (WSAStringToAddressA(addrstr, AF_BTH, NULL, (LPSOCKADDR)&sa, &sa_len) != NO_ERROR) {
		RETURN_ERROR(l, last_wsa_error())
	}
	sa.addressFamily = AF_BTH;
	/*
	 * When used with the bind function on client applications,
	 * the port member must be zero to enable an appropriate local endpoint to be assigned.
	 * When used with bind on server applications, the port member must be a valid port number or BT_PORT_ANY;
	 * ports automatically assigned using BT_PORT_ANY may be queried subsequently with a call to the getsockname function.
	 * The valid range for requesting a specific RFCOMM port is 1 through 30.
	 */
	sa.port = port;
	/*
	 * Service Class Identifier of the socket. When used with the bind function, serviceClassId is ignored.
	 * Also ignored if the port is specified. For the connect function,
	 * specifies the unique Bluetooth service class ID of the service to which it wants to connect.
	 * If the peer device has more than one port that corresponds to the service class identifier,
	 * the connect function attempts to connect to the first valid service; this mechanism can be used without prior SDP queries.
	 */
	//sa.serviceClassId;
	if (bind(sockfd, (LPSOCKADDR)&sa, sa_len) != NO_ERROR) {
		RETURN_ERROR(l, last_wsa_error())
	}
	RETURN_SUCCESS(l)
}

static int bt_connect(lua_State *l) {
	SOCKADDR_BTH sa = { 0 };
	int sa_len = sizeof(sa);
	int sockfd = luaL_checkinteger(l, 1);
	int proto = _check_proto(l, 2);
	const char *addrstr = luaL_checkstring(l, 3);
	int port = luaL_checkinteger(l, 4);
	trace("bt_connect(%d, \"%s\", %d)\n", sockfd, addrstr, port);
	if (WSAStringToAddressA(addrstr, AF_BTH, NULL, (LPSOCKADDR)&sa, &sa_len) != NO_ERROR) {
		RETURN_ERROR(l, last_wsa_error())
	}
	sa.addressFamily = AF_BTH;
	sa.port = port;
	if (connect(sockfd, (LPSOCKADDR)&sa, sa_len) != NO_ERROR) {
		RETURN_ERROR(l, last_wsa_error())
	}
	RETURN_SUCCESS(l)
}

static int bt_closesocket(lua_State *l) {
	int sockfd = luaL_checkinteger(l, 1);
	trace("bt_closesocket(%d)\n", sockfd);
	closesocket(sockfd);
	RETURN_SUCCESS(l)
}

static int bt_getDeviceInfo(lua_State *l) {
	HANDLE rhandle = NULL;
	BLUETOOTH_FIND_RADIO_PARAMS p = { sizeof(p) };
	HBLUETOOTH_RADIO_FIND fhandle = NULL;
	BLUETOOTH_DEVICE_INFO dinfo;
	SOCKADDR_BTH sa;
	int sa_len = sizeof(sa);
	DWORD ret;
	char buffer[40];
	const char *addrstr = luaL_checkstring(l, 1);

	ZeroMemory(&sa, sizeof(sa_len));
	if (WSAStringToAddressA(addrstr, AF_BTH, NULL, (LPSOCKADDR)&sa, &sa_len) != NO_ERROR) {
		RETURN_ERROR(l, last_wsa_error())
	}
	ZeroMemory(&dinfo, sizeof(BLUETOOTH_DEVICE_INFO));
	dinfo.dwSize = sizeof(BLUETOOTH_DEVICE_INFO);
	dinfo.Address.ullLong = sa.btAddr;

  trace("looking for first radio\n");
	fhandle = BluetoothFindFirstRadio(&p, &rhandle);
	if (fhandle == NULL) {
		RETURN_ERROR(l, last_error())
	}
	trace("using radio 0x%p\n", rhandle);

	// The Bluetooth device must have been previously identified through a successful device inquiry function call.
	ret = BluetoothGetDeviceInfo(rhandle, &dinfo);
	//trace("BluetoothGetDeviceInfo() => %s\n", last_wsa_error());
	//trace("BluetoothGetDeviceInfo() => %s\n", last_error());
	if (!BluetoothFindRadioClose(fhandle)) {
		RETURN_ERROR(l, last_error())
	}
	if (ret == ERROR_SUCCESS) {
		ZeroMemory(buffer, sizeof(buffer));
		WideCharToMultiByte(CP_UTF8, 0, dinfo.szName, wcslen(dinfo.szName), buffer, sizeof(buffer), NULL, NULL);
		trace("name: %s\n", buffer);
		trace(" Class: 0x%08x\n", dinfo.ulClassofDevice);
		trace(" Connected: %s\n", b2s(dinfo.fConnected));
		trace(" Authenticated: %s\n", b2s(dinfo.fAuthenticated));
		trace(" Remembered: %s\n", b2s(dinfo.fRemembered));
		trace(" LastSeen: %04d-%02d-%02dT%02d:%02d:%02d.%03d\n", dinfo.stLastSeen.wYear, dinfo.stLastSeen.wMonth, dinfo.stLastSeen.wDay,
			dinfo.stLastSeen.wHour, dinfo.stLastSeen.wMinute, dinfo.stLastSeen.wSecond, dinfo.stLastSeen.wMilliseconds);
		trace(" LastUsed: %04d-%02d-%02dT%02d:%02d:%02d.%03d\n", dinfo.stLastUsed.wYear, dinfo.stLastUsed.wMonth, dinfo.stLastUsed.wDay,
			dinfo.stLastUsed.wHour, dinfo.stLastUsed.wMinute, dinfo.stLastUsed.wSecond, dinfo.stLastUsed.wMilliseconds);
	} else {
		// if (ret == ERROR_NOT_FOUND) trace("device not found\n");
	  trace("Fail to get device info, due to BluetoothGetDeviceInfo() => %lx\n", ret);
		RETURN_ERROR(l, "Unable to get the device info")
	}
	RETURN_SUCCESS(l)
}

static int bt_discoverRadios(lua_State *l) {
	BLUETOOTH_FIND_RADIO_PARAMS m_bt_find_radio = {sizeof(BLUETOOTH_FIND_RADIO_PARAMS)};
	BLUETOOTH_RADIO_INFO m_bt_info = {sizeof(BLUETOOTH_RADIO_INFO)};
	HANDLE m_radio = NULL;
	HBLUETOOTH_RADIO_FIND m_bt = NULL;
	DWORD mbtinfo_ret;
	char buffer[40];

	ZeroMemory(&m_bt_info, sizeof(BLUETOOTH_RADIO_INFO));
	ZeroMemory(&m_bt_find_radio, sizeof(BLUETOOTH_FIND_RADIO_PARAMS));
	ZeroMemory(buffer, sizeof(buffer));

	m_bt_info.dwSize = sizeof(BLUETOOTH_RADIO_INFO);
	m_bt_find_radio.dwSize = sizeof(BLUETOOTH_FIND_RADIO_PARAMS);

	trace("Start discovering radios...\n");
	m_bt = BluetoothFindFirstRadio(&m_bt_find_radio, &m_radio);
	if (m_bt == NULL) {
		RETURN_ERROR(l, last_error())
	}
	do {
		mbtinfo_ret = BluetoothGetRadioInfo(m_radio, &m_bt_info);
		if (mbtinfo_ret != ERROR_SUCCESS) {
			RETURN_ERROR(l, last_error())
		}
		ZeroMemory(buffer, sizeof(buffer));
		WideCharToMultiByte(CP_UTF8, 0, m_bt_info.szName, wcslen(m_bt_info.szName), buffer, sizeof(buffer), NULL, NULL);
		trace("Instance Name: %s\n", buffer);
		trace(" Address: %02X:%02X:%02X:%02X:%02X:%02X\n", m_bt_info.address.rgBytes[5],
			m_bt_info.address.rgBytes[4], m_bt_info.address.rgBytes[3], m_bt_info.address.rgBytes[2],
			m_bt_info.address.rgBytes[1], m_bt_info.address.rgBytes[0]);
		trace(" Class: 0x%08x\n", m_bt_info.ulClassofDevice);
		trace(" Manufacturer: 0x%04x\n", m_bt_info.manufacturer);

	} while(BluetoothFindNextRadio(&m_bt_find_radio, &m_radio));

	if (!BluetoothFindRadioClose(m_bt)) {
		RETURN_ERROR(l, last_error())
	}
	RETURN_SUCCESS(l)
}

static int bt_discoverDevices(lua_State *l) {
	BLUETOOTH_DEVICE_INFO device_info;
	BLUETOOTH_DEVICE_SEARCH_PARAMS search_criteria;
	HBLUETOOTH_DEVICE_FIND found_device;
	BOOL next = TRUE;
	int duration = 8;
	int flush_cache = 1;
	int i = 1;
	char buffer[40];
	char addrstr[20];

	ZeroMemory(&device_info, sizeof(BLUETOOTH_DEVICE_INFO));
	ZeroMemory(&search_criteria, sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS));
	ZeroMemory(buffer, sizeof(buffer));

	device_info.dwSize = sizeof(BLUETOOTH_DEVICE_INFO);
	search_criteria.dwSize = sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS);
	search_criteria.fReturnAuthenticated = TRUE;
	search_criteria.fReturnRemembered = !flush_cache;
	search_criteria.fReturnConnected = TRUE;
	search_criteria.fReturnUnknown = TRUE;
	search_criteria.fIssueInquiry = TRUE;
	// A value that indicates the time out for the inquiry, expressed in increments of 1.28 seconds. 
	search_criteria.cTimeoutMultiplier = duration;
	search_criteria.hRadio = NULL;

	trace("Start discovering devices using timeout %d...\n", duration);
	found_device = BluetoothFindFirstDevice(&search_criteria, &device_info);
	if (found_device == NULL) {
		RETURN_ERROR(l, last_error())
	}
	// table to return all the devices
	lua_newtable(l);
	while(next) {
		ba2str(device_info.Address.ullLong, addrstr, _countof(addrstr));

		//trace("Name: %s\n", device_info.szName);
		//MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, device_info.szName, wcslen(device_info.szName), buffer, sizeof(buffer));
		ZeroMemory(buffer, sizeof(buffer));
		WideCharToMultiByte(CP_UTF8, 0, device_info.szName, wcslen(device_info.szName), buffer, sizeof(buffer), NULL, NULL);
		trace("Name: %s\n", buffer);
		trace(" Address: %s\n", addrstr);
		trace(" Class: 0x%08x\n", device_info.ulClassofDevice);
		trace(" Connected: %s\n", b2s(device_info.fConnected));
		trace(" Authenticated: %s\n", b2s(device_info.fAuthenticated));
		trace(" Remembered: %s\n", b2s(device_info.fRemembered));
		// table for this device
		lua_newtable(l);
		SET_TABLE_KEY_STRING(l, "name", buffer)
		SET_TABLE_KEY_STRING(l, "address", addrstr)
		SET_TABLE_KEY_INTEGER(l, "class", device_info.ulClassofDevice)
		lua_rawseti(l, -2, i++);

		next = BluetoothFindNextDevice(found_device, &device_info);
	}
	if (!BluetoothFindDeviceClose(found_device)) {
		RETURN_ERROR(l, last_error())
	}
	return 1;
}

static int bt_findService(lua_State *l) {
	//DWORD qs_len = sizeof(WSAQUERYSET);
	DWORD qs_len = 1000;
	WSAQUERYSET *qs = (WSAQUERYSET*) malloc(qs_len);
	DWORD flags = LUP_FLUSHCACHE | LUP_RETURN_ALL;
	//LUP_RETURN_NAME | LUP_CONTAINERS | LUP_RETURN_ADDR | LUP_FLUSHCACHE | LUP_RETURN_TYPE | LUP_RETURN_BLOB | LUP_RES_SERVICE
	HANDLE h;
	int status = 0;
	GUID uuid;
	int proto;
	int port;
	int i = 1;
	CSADDR_INFO *csinfo = NULL;
	//char addressBuf[20];
	const char *addr = luaL_checkstring(l, 1);
	//const char *uuidstr = luaL_checkstring(l, 2);
	const char *uuidstr = luaL_optstring(l, 2, "1002"); // default to public browse group

	trace("Start finding service on address \"%s\" with UUID \"%s\"\n", addr, uuidstr);

	//ZeroMemory(addressBuf, sizeof(addressBuf));
	ZeroMemory(&uuid, sizeof(GUID));
	ZeroMemory(qs, qs_len);

	str2uuid(uuidstr, &uuid);
	// RFCOMM_PROTOCOL_UUID SDP_PROTOCOL_UUID L2CAP_PROTOCOL_UUID

	qs->dwSize = sizeof(WSAQUERYSET);
	qs->dwNameSpace = NS_BTH;
	qs->dwNumberOfCsAddrs = 0;
	//qs->lpszContext = (LPSTR) addressBuf;
	qs->lpszContext = (LPSTR) addr;
	qs->lpServiceClassId = &uuid;

	status = WSALookupServiceBegin(qs, flags, &h);
	if (SOCKET_ERROR == status) {
		free(qs);
		RETURN_ERROR(l, last_wsa_error())
	}

	// table to return all the service records
	lua_newtable(l);

	trace("Next service\n");
	while (1) {
		status = WSALookupServiceNext(h, flags, &qs_len, qs);
		if (status != NO_ERROR) {
			int error = WSAGetLastError();
			if (error == WSA_E_NO_MORE) {
				trace("No more service\n");
				break;
			} else if (error == WSAEFAULT) {
				// The buffer was too small to contain a WSAQUERYSET set. 
				free(qs);
				qs = (WSAQUERYSET*) malloc(qs_len);
				continue;
			}
			free(qs);
			RETURN_ERROR(l, format_error(error))
		}
		//trace("Host: %s\n", addr);
		trace("Name: %s\n", qs->lpszServiceInstanceName);
		trace(" Comment: %s\n", qs->lpszComment);

		// table for this service record
		lua_newtable(l);
		SET_TABLE_KEY_STRING(l, "name", qs->lpszServiceInstanceName)
		if (strlen(qs->lpszComment) > 0) {
			SET_TABLE_KEY_STRING(l, "description", qs->lpszComment)
		}

		csinfo = qs->lpcsaBuffer;
		if (csinfo != NULL) {
			proto = csinfo->iProtocol;
			port = ((SOCKADDR_BTH*)csinfo->RemoteAddr.lpSockaddr)->port;
			trace(" Port: %d\n", port);
			if( proto == BTHPROTO_RFCOMM ) {
				trace(" Protocol: %s\n", "RFCOMM");
				SET_TABLE_KEY_STRING(l, "protocol", BT_PROTO_KEY_RFCOMM)
				SET_TABLE_KEY_INTEGER(l, "port", port)
			} else if( proto == BTHPROTO_L2CAP ) {
				trace(" Protocol: %s\n", "L2CAP");
				SET_TABLE_KEY_STRING(l, "protocol", BT_PROTO_KEY_L2CAP)
				SET_TABLE_KEY_INTEGER(l, "port", port)
			} else {
				trace(" Protocol: %s\n", "UNKNOWN");
			}
		}
		lua_rawseti(l, -2, i++);
		// raw service record
		//qs->lpBlob->pBlobData, qs->lpBlob->cbSize
	}
	WSALookupServiceEnd(h);
	free(qs);

	trace("Stop finding services\n");

	return 1;
}
