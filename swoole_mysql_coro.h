/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#ifndef SWOOLE_MYSQL_H_
#define SWOOLE_MYSQL_H_

#include "php_swoole.h"
#include "mysql.h"

BEGIN_EXTERN_C()
#ifdef SW_USE_MYSQLND
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_charset.h"
#endif

//typedef struct
//{
//    int packet_length;
//    int packet_number;
//    uint8_t protocol_version;
//    char *server_version;
//    int connection_id;
//    char auth_plugin_data[SW_MYSQL_NONCE_LENGTH + 1]; // nonce + '\0'
//    uint8_t l_auth_plugin_data;
//    char filler;
//    int capability_flags;
//    char character_set;
//    int16_t status_flags;
//    char reserved[10];
//    char *auth_plugin_name;
//    uint8_t l_auth_plugin_name;
//} mysql_handshake_request;
//
//typedef struct
//{
//    char *host;
//    char *user;
//    char *password;
//    char *database;
//    zend_bool strict_type;
//    zend_bool fetch_mode;
//
//    size_t host_len;
//    size_t user_len;
//    size_t password_len;
//    size_t database_len;
//
//    long port;
//    double timeout;
//    swTimer_node *timer;
//
//    int capability_flags;
//    int max_packet_size;
//    char character_set;
//    int packet_length;
//    char buf[512];
//#ifdef SW_USE_OPENSSL
//    char auth_plugin_data[SW_MYSQL_NONCE_LENGTH]; // save challenge data for RSA auth
//#endif
//
//    uint16_t error_code;
//    char *error_msg;
//    uint16_t error_length;
//} mysql_connector;
//
//typedef struct
//{
//    char *buffer;
//    char *name; /* Name of column */
//    char *org_name; /* Original column name, if an alias */
//    char *table; /* Table of column if column was a field */
//    char *org_table; /* Org table name, if table was an alias */
//    char *db; /* Database for table */
//    char *catalog; /* Catalog for table */
//    char *def; /* Default value (set by mysql_list_fields) */
//    ulong_t length; /* Width of column (create length) */
//    ulong_t max_length; /* Max width for selected set */
//    uint32_t name_length;
//    uint32_t org_name_length;
//    uint32_t table_length;
//    uint32_t org_table_length;
//    uint32_t db_length;
//    uint32_t catalog_length;
//    uint32_t def_length;
//    uint32_t flags; /* Div flags */
//    uint32_t decimals; /* Number of decimals in field */
//    uint32_t charsetnr; /* Character set */
//    enum sw_mysql_field_types type; /* Type of field. See mysql_com.h for types */
//    void *extension;
//} mysql_field;
//
//typedef union
//{
//    signed char stiny;
//    uchar utiny;
//    uchar mbool;
//    short ssmall;
//    unsigned short small;
//    int sint;
//    uint32_t uint;
//    long long sbigint;
//    unsigned long long ubigint;
//    float mfloat;
//    double mdouble;
//} mysql_row;
//
//typedef struct
//{
//    uint32_t id;
//    uint16_t field_count;
//    uint16_t param_count;
//    uint16_t warning_count;
//    uint16_t unreaded_param_count;
//    struct _mysql_client *client;
//    zval *object;
//    swString *buffer; /* save the mysql multi responses data */
//    zval *result; /* save the zval array result */
//} mysql_statement;
//
//typedef struct
//{
//    mysql_field *columns;
//    ulong_t num_column;
//    ulong_t index_column;
//    uint32_t num_row;
//    uint8_t response_type;
//    uint32_t packet_length :24;
//    uint32_t packet_number :8;
//    int32_t  error_code;
//    uint32_t warnings;
//    uint16_t status_code;
//    char status_msg[6];
//    char *server_msg;
//    uint16_t l_server_msg;
//    ulong_t affected_rows;
//    ulong_t insert_id;
//    zval *result_array;
//} mysql_response_t;
//
//typedef struct _mysql_client
//{
//#ifdef SW_COROUTINE
//    zend_bool defer;
//    zend_bool suspending;
//    mysql_io_status iowait;
//    zval *result;
//    long cid;
//#endif
//    uint8_t state;
//    uint32_t switch_check :1; /* check if server request auth switch */
//    uint8_t handshake;
//    uint8_t cmd; /* help with judging to do what in callback */
//    swString *buffer; /* save the mysql responses data */
//    swClient *cli;
//    zval *object;
//    zval *callback;
//    zval *onClose;
//    int fd;
//    uint32_t transaction :1;
//    uint32_t connected :1;
//
//    mysql_connector connector;
//    mysql_statement *statement;
//    swLinkedList *statement_list;
//
//    swTimer_node *timer;
//
//    zval _object;
//    zval _onClose;
//
//    off_t check_offset;
//    mysql_response_t response; /* single response */
//
//    // for stored procedure
//    zval* tmp_result;
//
//} mysql_client;

END_EXTERN_C()

#endif /* SWOOLE_MYSQL_H_ */
