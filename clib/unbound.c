/*
 * clib/unbound.c - luakit libunbound wrapper
 *
 * Copyright: 2012 Guido Witmond <guido@witmond.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "clib/unbound.h"
#include "luah.h"

// We're a singleton, so ignore class and object headers for now.
// #include "common/luaobject.h"
// #include "common/luaclass.h"
#include "globalconf.h"

#include <unbound.h>
#include <arpa/inet.h>
#include <errno.h>      // for testing 
#include <stdio.h>      // for debugging

// Macros to eas Lua table generation
#define PUSHVAL(type, prop, value...)	      \
  lua_pushliteral (L, #prop);		      \
  lua_push##type (L, value);		      \
  lua_rawset(L, -3);                          \
  debug("PUSHED " #prop)

// From a C-struct named 'result'
#define PUSH(type, prop) PUSHVAL(type, prop, result->prop)


typedef struct {
  LUA_OBJECT_HEADER
} unbound_t;

// setup module signals
lua_class_t unbound_class;
LUA_CLASS_FUNCS(unbound, unbound_class);

// forward decls.
char* unbound_parse_a(const char *data, const int len);
void unbound_parse_tlsa(lua_State *L, const char *data, const int len);
void unbound_parse_ub_data(lua_State *L, struct ub_result *ub_result);

void unbound_parse_ub_result(lua_State *L, struct ub_result *result) {
  lua_newtable(L);
  PUSH(string,  qname);
  PUSH(integer, qtype);
  PUSH(integer, qclass);
  PUSH(string,  canonname);
  PUSH(boolean, nxdomain);
  PUSH(boolean, secure);
  PUSH(boolean, bogus);
  PUSH(string,  why_bogus);

  unbound_parse_ub_data(L, result);
}

// Parse the result->data[] into separate tables
void unbound_parse_ub_data(lua_State *L, struct ub_result *ub_result) {
  int i = 0;
  for (i=0; ub_result->data[i]; i++) {
    lua_pushinteger(L, i+1); // lua counts from base 1, C from base 0
    switch (ub_result->qtype) {
    case 1: // A
      lua_pushstring(L, unbound_parse_a(ub_result->data[i], ub_result->len[i]));
      break;
    case 52: // TLSA
      lua_newtable(L);
      unbound_parse_tlsa(L, ub_result->data[i], ub_result->len[i]);
      break;
    }
    lua_settable(L, -3);
  }
}

char* unbound_parse_a(const char *data, const int UNUSED(len)) {
  // assert(len == 4); // just to make sure..
  return inet_ntoa(*(struct in_addr*) data);
}

void unbound_parse_tlsa(lua_State *L, const char *data, const int len) {
  // assert(len >= 35); // 3 bytes descriptor and 32 bytes of sha1 is our minimum length.
  PUSHVAL(integer, usage,      data[0]);
  PUSHVAL(integer, selector,   data[1]);
  PUSHVAL(integer, match_type, data[2]);
  PUSHVAL(lstring, cert_ass,   data + 3, len -3);
}

static int unbound_resolve(lua_State *L) {
  
  struct ub_ctx* ctx;
  struct ub_result* result;
  int errcode;
  int stack = 0;
  
  // Check param (params start at index 2 as we have an class-abstraction of ourself at index 1
  const char *server_name = luaL_checkstring(L, 2);
  const int   rr_type     = luaL_checkint(L, 3);

  /* create context */
  ctx = ub_ctx_create();
  if(!ctx) {
    lua_pushnil(L);
    lua_pushstring(L, "error: could not create unbound context.");
    return 2;
  }


  // ub_ctx_debugout(ctx, stderr);
  // ub_ctx_debuglevel(ctx, 4);

  // install Unbound-package to use as validating resolver
  // ie. apt-get install unbound
  // or point to a validating resolver on your network
  ub_ctx_set_fwd(ctx, "127.0.0.1");

  // Add the DNSSEC root key to validate against.
  ub_ctx_add_ta(ctx, ". 86400 DNSKEY 257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=");

  debug("unbound resolving for: %s", server_name);
  debug("unbound resolving type: %d", rr_type);

  errcode = ub_resolve(ctx, (char*)server_name, 
		       rr_type, 
		       1, /* CLASS IN (internet) */ 
		       &result);
  if (errcode) {
    lua_pushnil(L);
    lua_pushstring(L, ub_strerror(errcode));
    stack += 2;
  } else {
    if (result->havedata) {
      debug("unbound had results for %s", result->qname);
      unbound_parse_ub_result(L, result);
      stack += 1;
    }
  }
  ub_resolve_free(result);
  ub_ctx_delete(ctx);
  
  return stack;
}

/************************************
 * Class setup boiler plate
 ************************************/

// #define check_unbound(L, idx) luaH_checkudata(L, idx, &(unbound_class))

static int luaH_unbound_new(lua_State * UNUSED(L))
{
  //luaH_class_new(L, &unbound_class);
    ///unbound_t *unbound = check_unbound(L, -1);
    // unbound->xxx = YYY;
    return 0;
}

void unbound_lib_setup(lua_State *L)
{
    static const struct luaL_reg unbound_lib[] =
    {
        LUA_CLASS_METHODS(unbound)
        { "__call", luaH_unbound_new },
	{ "resolve", unbound_resolve },
        { NULL, NULL }
    };

    // create signals array
    unbound_class.signals = signal_new();

    luaH_openlib(L, "unbound", unbound_lib, unbound_lib);
}



//#undef check_unbound

// vim: ft=c:et:sw=4:ts=8:sts=4:tw=80
