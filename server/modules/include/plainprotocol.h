#ifndef _MYSQL_PROTOCOL_H
#define _MYSQL_PROTOCOL_H
/*
 * This file is distributed as part of the MariaDB Corporation MaxScale.  It is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright MariaDB Corporation Ab 2013-2015
 */

/*
 * Revision History
 *
 * Date         Who                     Description
 * 24-03-2015   Markus Makela           Initial implementation

 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <service.h>
#include <router.h>
#include <poll.h>
#include <users.h>
#include <dbusers.h>
#include <version.h>
#include <housekeeper.h>

#define GW_MYSQL_VERSION "MaxScale " MAXSCALE_VERSION
#define GW_MYSQL_LOOP_TIMEOUT 300000000
#define GW_MYSQL_READ 0
#define GW_MYSQL_WRITE 1
#define MYSQL_HEADER_LEN 4L

#define GW_MYSQL_PROTOCOL_VERSION 10 // version is 10
#define GW_MYSQL_HANDSHAKE_FILLER 0x00
#define GW_MYSQL_SERVER_CAPABILITIES_BYTE1 0xff
#define GW_MYSQL_SERVER_CAPABILITIES_BYTE2 0xf7
#define GW_MYSQL_SERVER_LANGUAGE 0x08
#define GW_MYSQL_MAX_PACKET_LEN 0xffffffL;
#define GW_MYSQL_SCRAMBLE_SIZE 20
#define GW_SCRAMBLE_LENGTH_323 8

#ifndef MYSQL_SCRAMBLE_LEN
# define MYSQL_SCRAMBLE_LEN GW_MYSQL_SCRAMBLE_SIZE
#endif

#define GW_NOINTR_CALL(A)       do { errno = 0; A; } while (errno == EINTR)
#define SMALL_CHUNK 1024
#define MAX_CHUNK SMALL_CHUNK * 8 * 4
#define ToHex(Y) (Y>='0'&&Y<='9'?Y-'0':Y-'A'+10)
struct dcb;

/** Protocol packing macros. */
#define gw_mysql_set_byte2(__buffer, __int) do { \
  (__buffer)[0]= (uint8_t)((__int) & 0xFF); \
  (__buffer)[1]= (uint8_t)(((__int) >> 8) & 0xFF); } while (0)
#define gw_mysql_set_byte3(__buffer, __int) do { \
  (__buffer)[0]= (uint8_t)((__int) & 0xFF); \
  (__buffer)[1]= (uint8_t)(((__int) >> 8) & 0xFF); \
  (__buffer)[2]= (uint8_t)(((__int) >> 16) & 0xFF); } while (0)
#define gw_mysql_set_byte4(__buffer, __int) do { \
  (__buffer)[0]= (uint8_t)((__int) & 0xFF); \
  (__buffer)[1]= (uint8_t)(((__int) >> 8) & 0xFF); \
  (__buffer)[2]= (uint8_t)(((__int) >> 16) & 0xFF); \
  (__buffer)[3]= (uint8_t)(((__int) >> 24) & 0xFF); } while (0)

/** Protocol unpacking macros. */
#define gw_mysql_get_byte2(__buffer) \
  (uint16_t)((__buffer)[0] | \
            ((__buffer)[1] << 8))
#define gw_mysql_get_byte3(__buffer) \
  (uint32_t)((__buffer)[0] | \
            ((__buffer)[1] << 8) | \
            ((__buffer)[2] << 16))
#define gw_mysql_get_byte4(__buffer) \
  (uint32_t)((__buffer)[0] | \
            ((__buffer)[1] << 8) | \
            ((__buffer)[2] << 16) | \
            ((__buffer)[3] << 24))
#define gw_mysql_get_byte8(__buffer) \
  ((uint64_t)(__buffer)[0] | \
  ((uint64_t)(__buffer)[1] << 8) | \
  ((uint64_t)(__buffer)[2] << 16) | \
  ((uint64_t)(__buffer)[3] << 24) | \
  ((uint64_t)(__buffer)[4] << 32) | \
  ((uint64_t)(__buffer)[5] << 40) | \
  ((uint64_t)(__buffer)[6] << 48) | \
  ((uint64_t)(__buffer)[7] << 56))

/** MySQL protocol constants */
typedef enum
{
  GW_MYSQL_CAPABILITIES_NONE=                   0,
  GW_MYSQL_CAPABILITIES_LONG_PASSWORD=          (1 << 0),
  GW_MYSQL_CAPABILITIES_FOUND_ROWS=             (1 << 1),
  GW_MYSQL_CAPABILITIES_LONG_FLAG=              (1 << 2),
  GW_MYSQL_CAPABILITIES_CONNECT_WITH_DB=        (1 << 3),
  GW_MYSQL_CAPABILITIES_NO_SCHEMA=              (1 << 4),
  GW_MYSQL_CAPABILITIES_COMPRESS=               (1 << 5),
  GW_MYSQL_CAPABILITIES_ODBC=                   (1 << 6),
  GW_MYSQL_CAPABILITIES_LOCAL_FILES=            (1 << 7),
  GW_MYSQL_CAPABILITIES_IGNORE_SPACE=           (1 << 8),
  GW_MYSQL_CAPABILITIES_PROTOCOL_41=            (1 << 9),
  GW_MYSQL_CAPABILITIES_INTERACTIVE=            (1 << 10),
  GW_MYSQL_CAPABILITIES_SSL=                    (1 << 11),
  GW_MYSQL_CAPABILITIES_IGNORE_SIGPIPE=         (1 << 12),
  GW_MYSQL_CAPABILITIES_TRANSACTIONS=           (1 << 13),
  GW_MYSQL_CAPABILITIES_RESERVED=               (1 << 14),
  GW_MYSQL_CAPABILITIES_SECURE_CONNECTION=      (1 << 15),
  GW_MYSQL_CAPABILITIES_MULTI_STATEMENTS=       (1 << 16),
  GW_MYSQL_CAPABILITIES_MULTI_RESULTS=          (1 << 17),
  GW_MYSQL_CAPABILITIES_PS_MULTI_RESULTS=       (1 << 18),
  GW_MYSQL_CAPABILITIES_PLUGIN_AUTH=            (1 << 19),
  GW_MYSQL_CAPABILITIES_SSL_VERIFY_SERVER_CERT= (1 << 30),
  GW_MYSQL_CAPABILITIES_REMEMBER_OPTIONS=       (1 << 31),
  GW_MYSQL_CAPABILITIES_CLIENT= (GW_MYSQL_CAPABILITIES_LONG_PASSWORD |
                                GW_MYSQL_CAPABILITIES_FOUND_ROWS |
                                GW_MYSQL_CAPABILITIES_LONG_FLAG |
                                GW_MYSQL_CAPABILITIES_CONNECT_WITH_DB |
                                GW_MYSQL_CAPABILITIES_LOCAL_FILES |
                                GW_MYSQL_CAPABILITIES_PLUGIN_AUTH |
                                GW_MYSQL_CAPABILITIES_TRANSACTIONS |
                                GW_MYSQL_CAPABILITIES_PROTOCOL_41 |
                                GW_MYSQL_CAPABILITIES_MULTI_STATEMENTS |
                                GW_MYSQL_CAPABILITIES_MULTI_RESULTS |
                                GW_MYSQL_CAPABILITIES_PS_MULTI_RESULTS |
                                GW_MYSQL_CAPABILITIES_SECURE_CONNECTION),
  GW_MYSQL_CAPABILITIES_CLIENT_COMPRESS= (GW_MYSQL_CAPABILITIES_LONG_PASSWORD |
                                GW_MYSQL_CAPABILITIES_FOUND_ROWS |
                                GW_MYSQL_CAPABILITIES_LONG_FLAG |
                                GW_MYSQL_CAPABILITIES_CONNECT_WITH_DB |
                                GW_MYSQL_CAPABILITIES_LOCAL_FILES |
                                GW_MYSQL_CAPABILITIES_PLUGIN_AUTH |
                                GW_MYSQL_CAPABILITIES_TRANSACTIONS |
                                GW_MYSQL_CAPABILITIES_PROTOCOL_41 |
                                GW_MYSQL_CAPABILITIES_MULTI_STATEMENTS |
                                GW_MYSQL_CAPABILITIES_MULTI_RESULTS |
                                GW_MYSQL_CAPABILITIES_PS_MULTI_RESULTS |
                                GW_MYSQL_CAPABILITIES_COMPRESS
                                ),
} gw_mysql_capabilities_t;

/** Copy from enum in mariadb-5.5 mysql_com.h */
typedef enum mysql_server_cmd {
        MYSQL_COM_UNDEFINED = -1,
        MYSQL_COM_SLEEP = 0,
        MYSQL_COM_QUIT,
        MYSQL_COM_INIT_DB,
        MYSQL_COM_QUERY,
        MYSQL_COM_FIELD_LIST,
        MYSQL_COM_CREATE_DB, 
        MYSQL_COM_DROP_DB,
        MYSQL_COM_REFRESH, 
        MYSQL_COM_SHUTDOWN, 
        MYSQL_COM_STATISTICS,
        MYSQL_COM_PROCESS_INFO, 
        MYSQL_COM_CONNECT, 
        MYSQL_COM_PROCESS_KILL, 
        MYSQL_COM_DEBUG, 
        MYSQL_COM_PING,
        MYSQL_COM_TIME, 
        MYSQL_COM_DELAYED_INSERT, 
        MYSQL_COM_CHANGE_USER, 
        MYSQL_COM_BINLOG_DUMP,
        MYSQL_COM_TABLE_DUMP, 
        MYSQL_COM_CONNECT_OUT, 
        MYSQL_COM_REGISTER_SLAVE,
        MYSQL_COM_STMT_PREPARE, 
        MYSQL_COM_STMT_EXECUTE, 
        MYSQL_COM_STMT_SEND_LONG_DATA, 
        MYSQL_COM_STMT_CLOSE,
        MYSQL_COM_STMT_RESET, 
        MYSQL_COM_SET_OPTION, 
        MYSQL_COM_STMT_FETCH, 
        MYSQL_COM_DAEMON,
        MYSQL_COM_END /*< Must be the last */
} mysql_server_cmd_t;

/**
 * MySQL Protocol specific state data.
 * 
 * Protocol carries information from client side to backend side, such as 
 * MySQL session command information and history of earlier session commands.
 */
typedef struct {
#if defined(SS_DEBUG)
        skygw_chk_t     protocol_chk_top;
#endif
        int                 fd;                           /*< The socket descriptor */
        struct dcb          *owner_dcb;                   /*< The DCB of the socket
        * we are running on */
        SPINLOCK            protocol_lock;              
        uint8_t             scramble[MYSQL_SCRAMBLE_LEN]; /*< server scramble,
        * created or received */
        uint32_t            server_capabilities;          /*< server capabilities,
        * created or received */
        uint32_t            client_capabilities;          /*< client capabilities,
        * created or received */
        unsigned        long tid;                         /*< MySQL Thread ID, in
        * handshake */
        unsigned int    charset;                          /*< MySQL character set at connect time */
#if defined(SS_DEBUG)
        skygw_chk_t     protocol_chk_tail;
#endif
} PlainProtocol;



#define MYSQL_GET_COMMAND(payload)              (payload[4])
#define MYSQL_GET_PACKET_NO(payload)            (payload[3])
#define MYSQL_GET_PACKET_LEN(payload)           (gw_mysql_get_byte3(payload))
#define MYSQL_GET_ERRCODE(payload)              (gw_mysql_get_byte2(&payload[5]))
#define MYSQL_GET_STMTOK_NPARAM(payload)        (gw_mysql_get_byte2(&payload[9]))
#define MYSQL_GET_STMTOK_NATTR(payload)         (gw_mysql_get_byte2(&payload[11]))
#define MYSQL_IS_ERROR_PACKET(payload)          (MYSQL_GET_COMMAND(payload)==0xff)
#define MYSQL_IS_COM_QUIT(payload)              (MYSQL_GET_COMMAND(payload)==0x01)
#define MYSQL_IS_COM_INIT_DB(payload)              (MYSQL_GET_COMMAND(payload)==0x02)
#define MYSQL_IS_CHANGE_USER(payload)		(MYSQL_GET_COMMAND(payload)==0x11)
#define MYSQL_GET_NATTR(payload)                ((int)payload[4])

#endif /** _MYSQL_PROTOCOL_H */

PlainProtocol* mysql_protocol_init(DCB* dcb, int fd);
void           mysql_protocol_done (DCB* dcb);
PlainProtocol *gw_mysql_init(PlainProtocol *data);
int  gw_receive_backend_auth(PlainProtocol *protocol);
int  gw_decode_mysql_server_handshake(PlainProtocol *protocol, uint8_t *payload);
int  gw_read_backend_handshake(PlainProtocol *protocol);
int  gw_send_authentication_to_backend(
        char *dbname,
        char *user,
        uint8_t *passwd,
        PlainProtocol *protocol);

int        plain_do_connect_to_backend(char *host, int port, int* fd);