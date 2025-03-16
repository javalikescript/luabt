#include <errno.h>
#include <string.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/l2cap.h>
/*
#include <bluetooth/sco.h>
*/

#include "luabt_base.c"


int str2uuid(const char *uuid_str, uuid_t *uuid) {
    uint32_t uuid_int[4];
    char *endptr;

    if( strlen( uuid_str ) == 36 ) {
        // Parse uuid128 standard format: 12345678-9012-3456-7890-123456789012
        char buf[9] = { 0 };

        if( uuid_str[8] != '-' && uuid_str[13] != '-' &&
            uuid_str[18] != '-'  && uuid_str[23] != '-' ) {
            return 0;
        }
        // first 8-bytes
        strncpy(buf, uuid_str, 8);
        uuid_int[0] = htonl( strtoul( buf, &endptr, 16 ) );
        if( endptr != buf + 8 ) return 0;

        // second 8-bytes
        strncpy(buf, uuid_str+9, 4);
        strncpy(buf+4, uuid_str+14, 4);
        uuid_int[1] = htonl( strtoul( buf, &endptr, 16 ) );
        if( endptr != buf + 8 ) return 0;

        // third 8-bytes
        strncpy(buf, uuid_str+19, 4);
        strncpy(buf+4, uuid_str+24, 4);
        uuid_int[2] = htonl( strtoul( buf, &endptr, 16 ) );
        if( endptr != buf + 8 ) return 0;

        // fourth 8-bytes
        strncpy(buf, uuid_str+28, 8);
        uuid_int[3] = htonl( strtoul( buf, &endptr, 16 ) );
        if( endptr != buf + 8 ) return 0;

        if( uuid != NULL ) sdp_uuid128_create( uuid, uuid_int );
    } else if ( strlen( uuid_str ) == 8 ) {
        // 32-bit reserved UUID
        uint32_t i = strtoul( uuid_str, &endptr, 16 );
        if( endptr != uuid_str + 8 ) return 0;
        if( uuid != NULL ) sdp_uuid32_create( uuid, i );
    } else if( strlen( uuid_str ) == 4 ) {
        // 16-bit reserved UUID
        int i = strtol( uuid_str, &endptr, 16 );
        if( endptr != uuid_str + 4 ) return 0;
        if( uuid != NULL ) sdp_uuid16_create( uuid, i );
    } else {
        return 0;
    }
    return 1;
}


static int bt_startup(void) {
	trace("bt_startup() success\n");
	return 1;
}

static int bt_cleanup(void) {
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
	static const int PROTO_VALUES[] = { BTPROTO_HCI, BTPROTO_L2CAP, BTPROTO_RFCOMM };
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
	int type, proto;
	int sockfd = -1;
	type = _check_socket_type(l, 1);
	proto = _check_proto(l, 2);
	sockfd = socket(PF_BLUETOOTH, type, proto);
	trace("bt_socket(%d, %d) => %d\n", type, proto, sockfd);
	if (sockfd < 0) {
		trace("Fail to create socket type: %d, proto: %d\n", type, proto);
		RETURN_ERROR(l, strerror(errno));
	}
	lua_pushinteger(l, sockfd);
	return 1;
}

static int _check_sockaddr(lua_State *l, int index, int proto, struct sockaddr *sa) {
	memset(sa, 0, sizeof(struct sockaddr));
	sa->sa_family = AF_BLUETOOTH;
	switch (proto) {
	case BTPROTO_L2CAP:
		{
			struct sockaddr_l2* addr = (struct sockaddr_l2 *) sa;
			const char *addrstr = luaL_checkstring(l, index);
			//bacpy(&addr->l2_bdaddr, BDADDR_ANY);
			str2ba(addrstr, &addr->l2_bdaddr);
			// The l2_psm field specifies the L2CAP port number to use.
			// Since it is a multibyte unsigned integer, byte ordering is significant.
			// The htobs function is used here to convert numbers to Bluetooth byte order. 
			addr->l2_psm = luaL_checkinteger(l, index + 1);
			trace("_check_sockaddr(%d, \"%s\", %d)\n", proto, addrstr, addr->l2_psm);
			addr->l2_psm = htobs(addr->l2_psm);
			break;
		}
	case BTPROTO_RFCOMM:
		{
			struct sockaddr_rc* addr = (struct sockaddr_rc *) sa;
			const char *addrstr = luaL_checkstring(l, index);
			str2ba(addrstr, &addr->rc_bdaddr);
			addr->rc_channel = luaL_checkinteger(l, index + 1);
			trace("_check_sockaddr(%d, \"%s\", %d)\n", proto, addrstr, addr->rc_channel);
			break;
		}
	default:
		//return luaL_error(l, "Unsupported protocol");
		RETURN_ERROR(l, "Unsupported protocol");
	}
	return 0;
}

static int bt_bind(lua_State *l) {
	struct sockaddr sa;
	int sockfd = luaL_checkinteger(l, 1);
	int proto = _check_proto(l, 2);
	trace("bt_bind(%d, %d, ...)\n", sockfd, proto);
	int status = _check_sockaddr(l, 3, proto, &sa);
	if (status > 0) {
		return status;
	}
	if (bind(sockfd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		trace("Fail to bind socket\n");
		RETURN_ERROR(l, strerror(errno));
	}
	RETURN_SUCCESS(l);
}

static int bt_connect(lua_State *l) {
	struct sockaddr sa;
	int sockfd = luaL_checkinteger(l, 1);
	int proto = _check_proto(l, 2);
	trace("bt_connect(%d, %d, ...)\n", sockfd, proto);
	int status = _check_sockaddr(l, 3, proto, &sa);
	if (status > 0) {
		return status;
	}
	if (connect(sockfd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		trace("Fail to connect socket\n");
		RETURN_ERROR(l, strerror(errno));
	}
	RETURN_SUCCESS(l);
}

static int bt_closesocket(lua_State *l) {
	int sockfd = luaL_checkinteger(l, 1);
	trace("bt_closesocket(%d)\n", sockfd);
	close(sockfd);
	RETURN_SUCCESS(l);
}

static int bt_getDeviceInfo(lua_State *l) {
	RETURN_SUCCESS(l);
}

static int bt_discoverRadios(lua_State *l) {
	RETURN_SUCCESS(l);
}

static int bt_discoverDevices(lua_State *l) {
	inquiry_info *ii = NULL;
	int devId, sock, flags, len, i, dev_class;
	int max_rsp, num_rsp;
	char addr[19] = { 0 };
	char name[248] = { 0 };

	flags = IREQ_CACHE_FLUSH;
	len = 8;
	max_rsp = 255;
	devId = hci_get_route(NULL);
	if (devId < 0) {
		trace("No available Bluetooth device\n");
		RETURN_ERROR(l, strerror(errno));
	}
	trace("Discovering devices using route %d...\n", devId);
	// this function opens a socket connection to the microcontroller on the specified local Bluetooth adapter
	sock = hci_open_dev(devId);
	if (sock < 0) {
		trace("Fail to open Bluetooth device socket\n");
		RETURN_ERROR(l, strerror(errno));
	}
	ii = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));
	if (ii == NULL) {
		close(sock);
		RETURN_ERROR(l, "Fail to allocate inquiry info");
	}
	trace("Start discovering devices using timeout %d...\n", len);
	num_rsp = hci_inquiry(devId, len, max_rsp, NULL, &ii, flags);
	if ( num_rsp < 0 ) {
		free(ii);
		close(sock);
		trace("Fail to discover Bluetooth devices\n");
		RETURN_ERROR(l, strerror(errno));
	}
	// table to return all the devices
	lua_newtable(l);
	for (i = 0; i < num_rsp; i++) {
		dev_class = (ii+i)->dev_class[2] << 16 | (ii+i)->dev_class[1] << 8 | (ii+i)->dev_class[0];
		ba2str(&(ii+i)->bdaddr, addr);
		memset(name, 0, sizeof(name));
		if (hci_read_remote_name(sock, &(ii+i)->bdaddr, sizeof(name), name, 0) < 0) {
			strcpy(name, "[unknown]");
		}
		trace("name: %s\n", name);
		trace(" Address: %s\n", addr);
		trace(" Class: 0x%08x\n", dev_class);
		// table for this device
		lua_newtable(l);
		SET_TABLE_KEY_STRING(l, "name", name);
		SET_TABLE_KEY_STRING(l, "address", addr);
		SET_TABLE_KEY_INTEGER(l, "class", dev_class);
		lua_rawseti(l, -2, i + 1);
	}
	free(ii);
	close(sock);
	return 1;
}

static int bt_findService(lua_State *l) {
	int status, port, i;
	bdaddr_t target;
	uuid_t svc_uuid;
	sdp_session_t *session = 0;
	sdp_list_t *response_list, *search_list, *attrid_list;
	uint32_t range = 0x0000ffff;
	const char *addr = luaL_checkstring(l, 1);
	//const char *uuidstr = luaL_checkstring(l, 2);
	const char *uuidstr = luaL_optstring(l, 2, "1002"); // default to public browse group
    char buf[1024] = { 0 };
	trace("Start finding service on address \"%s\" with UUID \"%s\"\n", addr, uuidstr);

	str2ba(addr, &target);
	str2uuid(uuidstr, &svc_uuid);

	// connect to the SDP server running on the remote machine
	session = sdp_connect(BDADDR_ANY, &target, 0);

	search_list = sdp_list_append(0, &svc_uuid);
	attrid_list = sdp_list_append(0, &range);
	
	response_list = NULL;
	status = sdp_service_search_attr_req(session, search_list, SDP_ATTR_REQ_RANGE, attrid_list, &response_list);

	// table to return all the service records
	lua_newtable(l);

	if (status == 0) {
		sdp_list_t *proto_list;
		sdp_list_t *r = response_list;
		// go through each of the service records
		i = 1;
		for (; r; r = r->next) {
			// table for this service record
			lua_newtable(l);
			sdp_record_t *rec = (sdp_record_t*) r->data;
			if (!sdp_get_service_name(rec, buf, sizeof(buf))) {
				trace("Name: \"%s\"\n", buf);
				SET_TABLE_KEY_STRING(l, "name", buf);
			}
			if (!sdp_get_service_desc(rec, buf, sizeof(buf))) {
				trace(" Description: \"%s\"\n", buf);
				SET_TABLE_KEY_STRING(l, "description", buf);
			}
			// get a list of the protocol sequences
			if( sdp_get_access_protos(rec, &proto_list) == 0 ) {
				sdp_list_t *p = proto_list;
				// get the RFCOMM port number
				port = sdp_get_proto_port(proto_list, RFCOMM_UUID);
				if (port != 0) {
					SET_TABLE_KEY_STRING(l, "protocol", BT_PROTO_KEY_RFCOMM);
					SET_TABLE_KEY_INTEGER(l, "port", port);
				} else {
					port = sdp_get_proto_port(proto_list, L2CAP_UUID);
					if (port != 0) {
						SET_TABLE_KEY_STRING(l, "protocol", BT_PROTO_KEY_L2CAP);
						SET_TABLE_KEY_INTEGER(l, "port", port);
					}
				}
				// sdp_get_access_protos allocates data on the heap for the
				// protocol list, so we need to free the results...
				for (; p ; p = p->next) {
					sdp_list_free( (sdp_list_t*)p->data, 0 );
				}
				sdp_list_free(proto_list, 0);
			}
			sdp_record_free(rec);
			trace(" Port: %d\n", port);
			lua_rawseti(l, -2, i++);
		}
	}
	sdp_list_free(response_list, 0);
	sdp_list_free(search_list, 0);
	sdp_list_free(attrid_list, 0);
	sdp_close(session);

	return 1;
}
