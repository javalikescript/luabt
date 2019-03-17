
//#define JLS_LUA_MOD_TRACE 1
#include "luamod.h"

#ifdef WIN32
#include "luabt_windows.c"
#else
#include "luabt_linux.c"
#endif

static int bt_load(lua_State *l) {
  if (!bt_startup()) {
    RETURN_ERROR(l, "Fail to startup bt")
  }
	RETURN_SUCCESS(l)
}

static int bt_unload(lua_State *l) {
  if (!bt_cleanup()) {
    RETURN_ERROR(l, "Fail to cleanup bt")
  }
	RETURN_SUCCESS(l)
}

LUALIB_API int luaopen_bt(lua_State *l) {
  trace("luaopen_bt()\n");
  if (!bt_startup()) {
    lua_pushstring(l, "Unable to initialize library");
    lua_error(l);
    return 0;
  }
  luaL_Reg reg[] = {
    { "_bt_load", bt_load },
    { "__unload", bt_unload },
    { "socket", bt_socket },
    { "bind", bt_bind },
    { "connect", bt_connect },
    { "closesocket", bt_closesocket },
    { "getDeviceInfo", bt_getDeviceInfo },
    // Device - is the thing that is connected to via the Bluetooth connection.
    { "discoverDevices", bt_discoverDevices },
    // Radio - is the thing plugged in/attached to the local machine.
    { "discoverRadios", bt_discoverRadios },
    // SDP Service Discovery Protocol
    { "findService", bt_findService },
    { NULL, NULL }
  };
  lua_newtable(l);
  luaL_setfuncs(l, reg, 0);
  lua_pushliteral(l, "Lua Bluetooth");
  lua_setfield(l, -2, "_NAME");
  lua_pushliteral(l, "0.1");
  lua_setfield(l, -2, "_VERSION");
  trace("luaopen_bt() done\n");
  return 1;
}
