/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
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

#include "php_swoole_cxx.h"

#include "swoole_coroutine.h"
#include "swoole_mysql_coro.h"
#include "socket.h"

// see mysqlnd 'L64' macro redefined
#undef L64

extern "C" {
#include "ext/hash/php_hash.h"
#include "ext/hash/php_hash_sha.h"
#include "ext/standard/php_math.h"
}

#include <unordered_map>

using namespace swoole;

namespace swoole
{
class mysql_statement;
class mysql_client
{
public:
    Socket *socket = nullptr;
    std::string host = SW_MYSQL_DEFAULT_HOST;
    uint16_t port = SW_MYSQL_DEFAULT_PORT;
    bool ssl = false;

    std::string user = "root";
    std::string password = "root";
    std::string database = "test";
    char charset = SW_MYSQL_DEFAULT_CHARSET;

    double connect_timeout = PHPCoroutine::socket_connect_timeout;
    double timeout = PHPCoroutine::socket_timeout;
    bool strict_type = false;

    uint16_t error_code = 0;
    std::string error_msg = "";

    enum sw_mysql_state state = SW_MYSQL_STATE_CLOSED;
    bool more_results_exist = false;
    mysql::result_info result;

    std::unordered_map<uint32_t, mysql_statement*> statements;

    inline void connection_error()
    {
        error_code = ECONNRESET;
        error_msg = strerror(ECONNRESET);
        // has been closed
    }

    inline void io_error()
    {
        error_code = socket->errCode;
        error_msg = socket->errMsg;
        close();
    }

    inline void proto_error(const char *data, const enum sw_mysql_packet_types expected_type)
    {
        mysql::server_packet packet(data);
        swWarn(
            "Unexpected mysql packet length=%u, number=%u, type=%u, expected_type=%u",
            packet.header.length, packet.header.number, (uint8_t) data[SW_MYSQL_PACKET_HEADER_SIZE], expected_type
        );
        error_code = EPROTO;
        error_msg = strerror(error_code);
        close();
    }

    inline void server_error(const char *data)
    {
        mysql::err_packet err_packet(data);
        error_code = err_packet.code;
        error_msg = cpp_string::format("SQLSTATE[%s] [%d] %s", err_packet.sql_state, err_packet.code, err_packet.msg.c_str());
    }

    inline bool get_fetch_mode()
    {
        return fetch_mode;
    }

    inline bool set_fetch_mode(bool v)
    {
        if (unlikely(socket && v))
        {
            error_code = EINVAL;
            error_msg = "can not use fetch mode after the connection is established";
            return false;
        }
        defer = v;
        return true;
    }

    inline bool get_defer()
    {
        return defer;
    }

    inline bool set_defer(bool v)
    {
        if (unlikely(fetch_mode && v))
        {
            error_code = EINVAL;
            error_msg = "can not use defer mode when fetch mode is on";
            return false;
        }
        defer = v;
        return true;
    }

    bool connect(std::string host, uint16_t port, bool ssl);

    inline bool connect()
    {
        return connect(host, port, ssl);
    }

    inline int get_fd()
    {
        return socket ? socket->get_fd() : -1;
    }

    inline bool check_liveness()
    {
        if (unlikely(!socket || !socket->check_liveness()))
        {
            close();
            connection_error();
            return false;
        }
        return true;
    }

    inline bool is_writeable()
    {
        return socket && !socket->has_bound(SW_EVENT_WRITE);
    }

    const char* recv_length(size_t needle);
    const char* recv_packet();

    inline const char* recv_none_error_packet()
    {
        const char *data = recv_packet();
        if (unlikely(data && mysql::server_packet::is_err(data)))
        {
            server_error(data);
            return nullptr;
        }
        return data;
    }

    inline const char* recv_eof_packet()
    {
        const char *data = recv_packet();
        if (unlikely(data && !mysql::server_packet::is_eof(data)))
        {
            proto_error(data, SW_MYSQL_PACKET_EOF);
            return nullptr;
        }
#ifdef SW_LOG_TRACE_OPEN
        mysql::eof_packet eof_packet(data);
#endif
        return data;
    }

    inline bool send_raw(const char *data, size_t length)
    {
        if (unlikely(!socket))
        {
            connection_error();
            return false;
        }
        if (unlikely(socket->send_all(data, length) != (ssize_t) length))
        {
            io_error();
            return false;
        }
        return true;
    }

    bool send_packet(mysql::client_packet *packet);
    bool send_command(enum sw_mysql_command command, const char* sql = nullptr, size_t length = 0);

    void query(zval *return_value, const char *statement, size_t statement_length, double timeout = 0);
    void recv_query_response(zval *return_value);
    bool recv_fields();
    void fetch(zval *return_value);
    void fetch_all(zval *return_value);
    void next_result(zval *return_value);
    bool recv(double timeout);
    bool begin();
    bool commit();
    bool rollback();

    mysql_statement* prepare(const char *statement, size_t statement_length, double timeout);
    mysql_statement* recv_prepare_response();

    void close();

    ~mysql_client()
    {
        close();
    }

private:
    bool fetch_mode = false;
    bool defer = false;

    bool handshake();
};

class mysql_statement
{
public:
    mysql_client *client;
    mysql::statement info;
    mysql::result_info result;

    uint16_t error_code = 0;
    std::string error_msg = "";

    mysql_statement(mysql_client *client);

    inline bool is_available()
    {
        if (unlikely(!client))
        {
            error_code = ECONNRESET;
            error_msg = "the statement must to be recompiled after the connection is broken";
            return false;
        }
        return true;
    }

    inline bool is_available_for_new_query()
    {
        if (unlikely(client->state != SW_MYSQL_STATE_IDLE))
        {
            error_code = EINPROGRESS;
            error_msg = "mysql client is busy now, please recv or fetch all unread data and try again";
            return false;
        }
        return true;
    }

    // [notify = false]: connection is closed
    inline void close(const bool notify = true)
    {
        if (client)
        {
            // if client point exists, socket is always available
            if (notify)
            {
                if (likely(client->is_writeable()))
                {
                    char id[4];
                    sw_mysql_int4store(id, info.id);
                    client->send_command(SW_MYSQL_COM_STMT_CLOSE, id, sizeof(id));
                }
                client->statements.erase(info.id);
            }
            client = nullptr;
            error_code = ECONNRESET;
            error_msg = strerror(ECONNRESET);
        }
    }

    ~mysql_statement()
    {
        close();
    }

    void execute(zval *return_value, zval *params);
    void recv_execute_response(zval *return_value);
    void fetch(zval *return_value);
    void fetch_all(zval *return_value);
};
}

static zend_class_entry swoole_mysql_coro_ce;
static zend_class_entry *swoole_mysql_coro_ce_ptr;
static zend_object_handlers swoole_mysql_coro_handlers;

static zend_class_entry swoole_mysql_coro_exception_ce;
static zend_class_entry *swoole_mysql_coro_exception_ce_ptr;
static zend_object_handlers swoole_mysql_coro_exception_handlers;

static zend_class_entry swoole_mysql_coro_statement_ce;
static zend_class_entry *swoole_mysql_coro_statement_ce_ptr;
static zend_object_handlers swoole_mysql_coro_statement_handlers;

typedef struct {
    mysql_client *mc;
    zend_object std;
} mysql_coro_t;

typedef struct {
    mysql_statement *statement;
    zend_object std;
} mysql_coro_statement_t;

static PHP_METHOD(swoole_mysql_coro, __construct);
static PHP_METHOD(swoole_mysql_coro, __destruct);
static PHP_METHOD(swoole_mysql_coro, connect);
static PHP_METHOD(swoole_mysql_coro, getDefer);
static PHP_METHOD(swoole_mysql_coro, setDefer);
static PHP_METHOD(swoole_mysql_coro, query);
static PHP_METHOD(swoole_mysql_coro, fetch);
static PHP_METHOD(swoole_mysql_coro, fetchAll);
static PHP_METHOD(swoole_mysql_coro, nextResult);
static PHP_METHOD(swoole_mysql_coro, prepare);
static PHP_METHOD(swoole_mysql_coro, recv);
static PHP_METHOD(swoole_mysql_coro, begin);
static PHP_METHOD(swoole_mysql_coro, commit);
static PHP_METHOD(swoole_mysql_coro, rollback);
#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql_coro, escape);
#endif
static PHP_METHOD(swoole_mysql_coro, close);

static PHP_METHOD(swoole_mysql_coro_statement, execute);
static PHP_METHOD(swoole_mysql_coro_statement, fetch);
static PHP_METHOD(swoole_mysql_coro_statement, fetchAll);
static PHP_METHOD(swoole_mysql_coro_statement, nextResult);

#define DATETIME_MAX_SIZE  20

typedef struct _mysql_big_data_info {
    // for used:
    ulong_t len;  // data length
    ulong_t remaining_size; // max remaining size that can be read
    uint32_t currrent_packet_remaining_size; // remaining size of current packet
    char *read_p; // where to start reading data
    // for result:
    uint32_t ext_header_len; // extra packet header length
    uint32_t ext_packet_len; // extra packet length (body only)
} mysql_big_data_info;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_connect, 0, 0, 0)
    ZEND_ARG_ARRAY_INFO(0, server_config, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_query, 0, 0, 1)
    ZEND_ARG_INFO(0, sql)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_prepare, 0, 0, 1)
    ZEND_ARG_INFO(0, query)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_setDefer, 0, 0, 0)
    ZEND_ARG_INFO(0, defer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_begin, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_commit, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_rollback, 0, 0, 0)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

#ifdef SW_USE_MYSQLND
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_escape, 0, 0, 1)
    ZEND_ARG_INFO(0, string)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_execute, 0, 0, 0)
    ZEND_ARG_INFO(0, params)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_fetch, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_fetchAll, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_coro_statement_nextResult, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_mysql_coro_methods[] =
{
    PHP_ME(swoole_mysql_coro, __construct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, getDefer, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, setDefer, arginfo_swoole_mysql_coro_setDefer, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, connect, arginfo_swoole_mysql_coro_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, query, arginfo_swoole_mysql_coro_query, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, fetch, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, fetchAll, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, nextResult, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, prepare, arginfo_swoole_mysql_coro_prepare, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, recv, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, begin, arginfo_swoole_mysql_coro_begin, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, commit, arginfo_swoole_mysql_coro_commit, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro, rollback, arginfo_swoole_mysql_coro_rollback, ZEND_ACC_PUBLIC)
#ifdef SW_USE_MYSQLND
    PHP_ME(swoole_mysql_coro, escape, arginfo_swoole_mysql_coro_escape, ZEND_ACC_PUBLIC)
#endif
    PHP_ME(swoole_mysql_coro, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry swoole_mysql_coro_statement_methods[] =
{
    PHP_ME(swoole_mysql_coro_statement, execute, arginfo_swoole_mysql_coro_statement_execute, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, fetch, arginfo_swoole_mysql_coro_statement_fetch, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, fetchAll, arginfo_swoole_mysql_coro_statement_fetchAll, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql_coro_statement, nextResult, arginfo_swoole_mysql_coro_statement_nextResult, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_sha256(const char *str, int len, unsigned char *digest)
{
    PHP_SHA256_CTX context;
    PHP_SHA256Init(&context);
    PHP_SHA256Update(&context, (unsigned char *) str, len);
    PHP_SHA256Final(digest, &context);
}

bool mysql_client::connect(std::string host, uint16_t port, bool ssl)
{
    if (socket && (host != this->host || port != this->port || ssl != this->ssl))
    {
        close();
    }
    if (!socket)
    {
        if (host.compare(0, 6, "unix:/", 0, 6) == 0)
        {
            host = host.substr(sizeof("unix:") - 1);
            host.erase(0, host.find_first_not_of('/') - 1);
            socket = new Socket(SW_SOCK_UNIX_STREAM);
        }
        else if (host.find(':') != std::string::npos)
        {
            socket = new Socket(SW_SOCK_TCP6);
        }
        else
        {
            socket = new Socket(SW_SOCK_TCP);
        }
        if (unlikely(socket->socket == nullptr))
        {
            swoole_php_fatal_error(E_WARNING, "new Socket() failed. Error: %s [%d]", strerror(errno), errno);
            error_code = errno;
            error_msg = strerror(errno);
            delete socket;
            socket = nullptr;
            return false;
        }
        socket->open_ssl = ssl;
        socket->set_timeout(connect_timeout, SW_TIMEOUT_CONNECT);
        if (!socket->connect(host, port))
        {
            io_error();
            return false;
        }
        this->host = host;
        this->port = port;
        this->ssl = ssl;
        if (!handshake())
        {
            close();
            return false;
        }
        state = SW_MYSQL_STATE_IDLE;
    }
    return true;
}

const char* mysql_client::recv_length(size_t needle)
{
    if (unlikely(!socket))
    {
        connection_error();
        return nullptr;
    }
    else
    {
        swString *buffer = socket->get_read_buffer();
        off_t offset = buffer->offset; // save offset instead of buffer point (due to realloc)
        size_t read_n = buffer->length - buffer->offset;

        while (read_n < needle)
        {
            ssize_t retval = socket->recv(buffer->str + buffer->length, buffer->size - buffer->length);
            if (unlikely(retval <= 0))
            {
                io_error();
                return nullptr;
            }
            read_n += retval;
            buffer->length += retval;
            if (unlikely(buffer->length == buffer->size))
            {
                if (unlikely(swString_extend_align(buffer, buffer->length + read_n) != SW_OK))
                {
                    error_code = ENOMEM;
                    error_msg = strerror(ENOMEM);
                    return nullptr;
                }
                else
                {
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "buffer extend to %zu", buffer->size);
                }
            }
        }
        buffer->offset += needle;
        return buffer->str + offset;
    }
}

const char* mysql_client::recv_packet()
{
    const char *p;
    uint32_t length;
    p = recv_length(SW_MYSQL_PACKET_HEADER_SIZE);
    if (unlikely(!p))
    {
        return nullptr;
    }
    length = mysql::server_packet::get_length(p);
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "recv packet length=%u, number=%u", length, mysql::server_packet::get_number(p));
    if (unlikely(!recv_length(length)))
    {
        return nullptr;
    }
    return p;
}

//const char* mysql_client::recv_text_data()
//{
//    const char *p;
//    uint32_t packet_length;
//    uint64_t length;
//    bool nul;
//    p = recv_length(SW_MYSQL_PACKET_HEADER_SIZE);
//    packet_length = mysql::server_packet::get_length(p);
//    p = recv_length(packet_length);
//    p += mysql::read_lcb(p, &length, &nul);
//
//}

bool mysql_client::send_packet(mysql::client_packet *packet)
{
    const char *data = packet->get_data();
    uint32_t length = SW_MYSQL_PACKET_HEADER_SIZE + packet->get_length();
    if (likely(send_raw(data, length)))
    {
        return true;
    }
    io_error();
    return false;
}

bool mysql_client::send_command(enum sw_mysql_command command, const char* sql, size_t length)
{
    if (likely(SW_MYSQL_PACKET_HEADER_SIZE + 1 + length <= SwooleG.pagesize))
    {
        mysql::command_packet command_packet(command, sql, length);
        return send_raw(command_packet.get_data(), command_packet.get_data_length());
    }
    else
    {
        size_t send_s = MIN(length, SW_MYSQL_MAX_PACKET_BODY_SIZE - 1), send_n = send_s, number = 0;
        mysql::command_packet command_packet(command);
        command_packet.set_header(1 + send_s, number++);
        if (unlikely(
            !send_raw(command_packet.get_data(), SW_MYSQL_PACKET_HEADER_SIZE + 1)) ||
            !send_raw(sql, send_s)
        )
        {
            return false;
        }
        while (send_n < length)
        {
            send_s = MIN(length - send_n, SW_MYSQL_MAX_PACKET_BODY_SIZE);
            command_packet.set_header(send_s, number++);
            if (unlikely(
                !send_raw(command_packet.get_data(), SW_MYSQL_PACKET_HEADER_SIZE)) ||
                !send_raw(sql + send_n, send_s)
            )
            {
                return false;
            }
            send_n += send_s;
        }
        return true;
    }
}

bool mysql_client::handshake()
{
    const char *data;
    // recv greeting pakcet
    if (unlikely(!(data = recv_none_error_packet())))
    {
        return false;
    }
    mysql::greeting_packet greeting_packet(data);
    // generate login packet
    do {
        mysql::login_packet login_packet(&greeting_packet, user, password, database, charset);
        if (unlikely(!send_packet(&login_packet)))
        {
            return false;
        }
    } while (0);
    // recv auth switch request packet, 4 possible packet types
    switch (mysql::server_packet::parse_type(data = recv_packet()))
    {
    case SW_MYSQL_PACKET_AUTH_SWITCH_REQUEST:
    {
        mysql::auth_switch_request_packet request(data);
        mysql::auth_switch_response_packet response(&request, password);
        if (unlikely(!send_packet(&response)))
        {
            return false;
        }
        break;
    }
    case SW_MYSQL_PACKET_AUTH_SIGNATURE_REQUEST:
    {
        mysql::auth_signature_request_packet request(data);
        if (unlikely(!request.is_vaild()))
        {
            goto _proto_error;
        }
        if (likely(!request.is_full_auth_required()))
        {
            break;
        }
        // no cache, need full auth with rsa key (openssl required)
#ifdef SW_MYSQL_RSA_SUPPORT
        // tell the server we are prepared
        do {
            mysql::auth_signature_prepared_packet prepared(request.header.number);
            if (unlikely(!send_packet(&prepared)))
            {
                return false;
            }
        } while (0);
        // recv rsa key and encode the password
        do {
            if (unlikely(!(data = recv_none_error_packet())))
            {
                return false;
            }
            mysql::raw_data_packet raw_data_packet(data);
            mysql::auth_signature_response_packet response(&raw_data_packet, password, greeting_packet.auth_plugin_data);
            if (unlikely(!send_packet(&response)))
            {
                return false;
            }
        } while (0);
        break;
#else
        error_code = EPROTONOSUPPORT;
        error_msg = SW_MYSQL_NO_RSA_ERROR;
        return false;
#endif
    }
    case SW_MYSQL_PACKET_OK:
        return true;
    case SW_MYSQL_PACKET_ERR:
        server_error(data);
        return false;
    case SW_MYSQL_PACKET_NULL:
        // io_error
        return false;
    default:
        _proto_error:
        proto_error(data, SW_MYSQL_PACKET_AUTH_SWITCH_REQUEST);
        return false;
    }
    // maybe ok packet or err packet
    if (unlikely(!(data = recv_none_error_packet())))
    {
        return false;
    }
#ifdef SW_LOG_TRACE_OPEN
    mysql::ok_packet ok_packet(data);
#endif
    return true;
}

void mysql_client::query(zval *return_value, const char *statement, size_t statement_length, double timeout)
{
    if (unlikely(!check_liveness()))
    {
        RETURN_FALSE;
    }
    if (unlikely(!send_command(SW_MYSQL_COM_QUERY, statement, statement_length)))
    {
        RETURN_FALSE;
    }
    state = SW_MYSQL_STATE_QUERY;
    if (defer)
    {
        RETURN_TRUE;
    }
    recv_query_response(return_value);
};

bool mysql_client::recv_fields()
{
    const char *data;
    if (unlikely(!(data = recv_none_error_packet())))
    {
        return false;
    }
    if (mysql::server_packet::is_ok(data))
    {
        mysql::ok_packet ok_packet(data);
        result.ok = ok_packet;
        state = ok_packet.server_status.more_results_exists() ? SW_MYSQL_STATE_MORE_RESULTS : SW_MYSQL_STATE_IDLE;
        return true;
    }
    mysql::lcb_packet lcb_packet(data);
    if (unlikely(lcb_packet.length == 0))
    {
        // is it possible?
        proto_error(data, SW_MYSQL_PACKET_FIELD);
        return false;
    }
    // loop fields
    result.alloc_fields(lcb_packet.length);
    for (uint32_t i = 0; i < lcb_packet.length; i++)
    {
        if (unlikely(!(data = recv_packet())))
        {
            return false;
        }
        result.set_field(i, data);
    }
    // expect eof
    if (unlikely(!(data = recv_eof_packet())))
    {
        return false;
    }
    state = SW_MYSQL_STATE_QUERY_FETCH;
    return true;
}

void mysql_client::recv_query_response(zval *return_value)
{
    if (unlikely(!recv_fields()))
    {
        RETURN_FALSE;
    }
    // ok packet
    if (state == SW_MYSQL_STATE_IDLE || get_fetch_mode())
    {
        RETURN_TRUE;
    }
    fetch_all(return_value);
}

void mysql_client::fetch(zval *return_value)
{
    if (unlikely(state != SW_MYSQL_STATE_QUERY_FETCH))
    {
        RETURN_NULL();
    }
    const char *data;
    if (unlikely(!(data = recv_packet())))
    {
        RETURN_FALSE;
    }
    if (mysql::server_packet::is_eof(data))
    {
        mysql::eof_packet eof_packet(data);
        state = eof_packet.server_status.more_results_exists() ? SW_MYSQL_STATE_MORE_RESULTS : SW_MYSQL_STATE_IDLE;
        RETURN_NULL();
    }
    do {
        const char *p = data + SW_MYSQL_PACKET_HEADER_SIZE;
        // const char *p_eof = p + mysql::server_packet::get_length(data);
        array_init_size(return_value, result.get_fields_length());
        for (uint32_t i = 0; i < result.get_fields_length(); i++)
        {
            mysql::field_packet *field = result.get_field(i);
            mysql::row_data_text row_data_text(&p);
            // handle big data
//            do {
//                // packet eof addr - row_data_text.body (reaminning size)
//                size_t write_s = p_eof - row_data_text.body;
//                // big data more than single packet
//                if (unlikely(row_data_text.length > write_s))
//                {
//                    zend_string *zstring = zend_string_alloc(row_data_text.length, 0);
//                    size_t write_n = write_s;
//                    memcpy(zstring->val, p, write_s);
//                    do {
//                        if (unlikely(!(data = recv_packet())))
//                        {
//                            zend_string_release(zstring);
//                            RETURN_FALSE;
//                        }
//                        p = data + SW_MYSQL_PACKET_HEADER_SIZE;
//                        p_eof = p + mysql::server_packet::get_length(data);
//                        write_s = MIN(row_data_text.length - write_n, p_eof - p);
//                        memcpy(zstring->val + write_n, p, write_s);
//                        write_n += write_s;
//                    } while (write_n < row_data_text.length);
//                    SW_ASSERT(write_n == row_data_text.length);
//                    ZSTR_VAL(zstring)[write_n] = '\0';
//                    // add zend string
//                    do {
//                        zval zdata;
//                        ZVAL_STR(&zdata, zstring);
//                        add_assoc_zval_ex(&zrow, field->name, field->name_length, &zdata);
//                    } while (0);
//                    p += write_s; // for the next
//                    continue;
//                }
//            } while (0);
            if (row_data_text.nul || field->type == SW_MYSQL_TYPE_NULL)
            {
                add_assoc_null_ex(return_value, field->name, field->name_length);
            }
            else if (!strict_type)
            {
                _add_string:
                add_assoc_stringl_ex(return_value, field->name, field->name_length, row_data_text.body, row_data_text.length);
            }
            else
            {
                switch (field->type)
                {
                /* String */
                case SW_MYSQL_TYPE_TINY_BLOB:
                case SW_MYSQL_TYPE_MEDIUM_BLOB:
                case SW_MYSQL_TYPE_LONG_BLOB:
                case SW_MYSQL_TYPE_BLOB:
                case SW_MYSQL_TYPE_DECIMAL:
                case SW_MYSQL_TYPE_NEWDECIMAL:
                case SW_MYSQL_TYPE_BIT:
                case SW_MYSQL_TYPE_STRING:
                case SW_MYSQL_TYPE_VAR_STRING:
                case SW_MYSQL_TYPE_VARCHAR:
                case SW_MYSQL_TYPE_NEWDATE:
                /* Date Time */
                case SW_MYSQL_TYPE_TIME:
                case SW_MYSQL_TYPE_YEAR:
                case SW_MYSQL_TYPE_TIMESTAMP:
                case SW_MYSQL_TYPE_DATETIME:
                case SW_MYSQL_TYPE_DATE:
                case SW_MYSQL_TYPE_JSON:
                    goto _add_string;
                }
                char tmp[32];
                char *error;
                if (unlikely(row_data_text.length > sizeof(tmp)-1))
                {
                    goto _add_string;
                }
                memcpy(tmp, row_data_text.body, row_data_text.length);
                tmp[row_data_text.length] = '\0';
                switch (field->type)
                {
                /* Integer */
                case SW_MYSQL_TYPE_TINY:
                case SW_MYSQL_TYPE_SHORT:
                case SW_MYSQL_TYPE_INT24:
                case SW_MYSQL_TYPE_LONG:
                    if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
                    {
                        ulong_t uint = strtoul(tmp, &error, 10);
                        if (unlikely(*error != '\0'))
                        {
                            goto _add_string;
                        }
                        add_assoc_long_ex(return_value, field->name, field->name_length, uint);
                    }
                    else
                    {
                        long sint = strtol(tmp, &error, 10);
                        if (unlikely(*error != '\0'))
                        {
                            goto _add_string;
                        }
                        add_assoc_long_ex(return_value, field->name, field->name_length, sint);
                    }
                    break;
                case SW_MYSQL_TYPE_LONGLONG:
                    if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
                    {
                        unsigned long long ubigint = strtoull(tmp, &error, 10);
                        if (unlikely(*error != '\0' || ubigint > ZEND_LONG_MAX))
                        {
                            goto _add_string;
                        }
                        add_assoc_long_ex(return_value, field->name, field->name_length, ubigint);
                    }
                    else
                    {
                        long long sbigint = strtoll(tmp, &error, 10);
                        if (unlikely(*error != '\0'))
                        {
                            goto _add_string;
                        }
                        add_assoc_long_ex(return_value, field->name, field->name_length, sbigint);
                    }
                    break;
                case SW_MYSQL_TYPE_FLOAT:
                case SW_MYSQL_TYPE_DOUBLE:
                {
                    double mdouble = strtod(tmp, &error);
                    if (unlikely(*error != '\0'))
                    {
                        goto _add_string;
                    }
                    add_assoc_double_ex(return_value, field->name, field->name_length, mdouble);
                    break;
                }
                default:
                {
                    swWarn("unknown type[%d] for field [%.*s].", field->type, field->name_length, field->name);
                    goto _add_string;
                }
                }
            }
        }
    } while (0);
}

void mysql_client::fetch_all(zval *return_value)
{
    if (likely(state == SW_MYSQL_STATE_QUERY_FETCH))
    {
        zval zrow;
        array_init(return_value);
        while (true)
        {
            fetch(&zrow);
            if (unlikely(ZVAL_IS_NULL(&zrow)))
            {
                // eof
                return;
            }
            if (unlikely(Z_TYPE_P(&zrow) == IS_FALSE))
            {
                // error
                zval_ptr_dtor(return_value);
                RETURN_FALSE;
            }
            (void) add_next_index_zval(return_value, &zrow);
        }
    }
    RETURN_NULL();
}

void mysql_client::next_result(zval *return_value)
{
    if (likely(state == SW_MYSQL_STATE_MORE_RESULTS))
    {
        recv_query_response(return_value);
        return;
    }
    if (state == SW_MYSQL_STATE_QUERY_FETCH)
    {
        fetch_all(return_value);
        if (ZVAL_IS_NULL(return_value))
        {
            next_result(return_value);
            return;
        }
        else if (Z_TYPE_P(return_value) == IS_FALSE)
        {
            return;
        }
        else
        {
            zval_ptr_dtor(return_value);
        }
    }
    RETURN_NULL();
}

mysql_statement* mysql_client::prepare(const char *statement, size_t statement_length, double timeout)
{
    if (unlikely(!check_liveness()))
    {
        return nullptr;
    }
    if (unlikely(!send_command(SW_MYSQL_COM_STMT_PREPARE, statement, statement_length)))
    {
        return nullptr;
    }
    state = SW_MYSQL_STATE_PREPARE;
    if (defer)
    {
        return (mysql_statement *) -1;
    }
    return recv_prepare_response();
}

mysql_statement* mysql_client::recv_prepare_response()
{
    if (likely(state == SW_MYSQL_STATE_PREPARE))
    {
        state = SW_MYSQL_STATE_IDLE; // or will be replaced by constructor
        mysql_statement* statement = new mysql_statement(this);
        if (unlikely(!statement->is_available()))
        {
            delete statement;
            return nullptr;
        }
        statements[statement->info.id] = statement;
        return statement;
    }
    return nullptr;
}

void mysql_client::close()
{
    Socket *socket = this->socket;
    if (socket)
    {
        // make statements non-available
        while (!statements.empty())
        {
            auto i = statements.begin();
            i->second->close(false);
            statements.erase(i);
        }
        if (likely(!socket->has_bound()))
        {
            send_command(SW_MYSQL_COM_QUIT);
            this->socket = nullptr;
        }
        if (likely(socket->close()))
        {
            // FIXME: merge master // delete socket;
        }
    }
    state = SW_MYSQL_STATE_CLOSED;
}

mysql_statement::mysql_statement(mysql_client *client)
{
    const char *data;
    if (unlikely(!(data = client->recv_none_error_packet())))
    {
        return;
    }
    info = mysql::statement(data);
    if (likely(info.param_count != 0))
    {
        for (uint16_t i = info.param_count; i--;)
        {
            if (unlikely(!(data = client->recv_packet())))
            {
                return;
            }
    #ifdef SW_LOG_TRACE_OPEN
            mysql::param_packet param_packet(data);
    #endif
        }
        if (unlikely(!(data = client->recv_eof_packet())))
        {
            return;
        }
    }
    if (info.field_count != 0)
    {
        result.alloc_fields(info.field_count);
        for (uint16_t i = 0; i < info.field_count; i++)
        {
            if (unlikely(!(data = client->recv_packet())))
            {
                return;
            }
            result.set_field(i, data);
        }
        if (unlikely(!(data = client->recv_eof_packet())))
        {
            return;
        }
    }
    this->client = client;
}

void mysql_statement::execute(zval *return_value, zval *params)
{
    if (unlikely(!is_available()))
    {
        RETURN_FALSE;
    }
    long lval;
    char buf[10];
    zval *value;
    uint32_t param_count = params ? php_swoole_array_length(params) : 0;

    if (param_count != info.param_count)
    {
        error_code = EINVAL;
        error_msg = cpp_string::format("statement#%u expects %u parameter, %u given.", info.id, info.param_count, param_count);
        RETURN_FALSE;
    }

    swString *buffer = SwooleTG.buffer_stack;
    char *p = buffer->str;

    memset(p, 0, 5);
    // command
    buffer->str[4] = SW_MYSQL_COM_STMT_EXECUTE;
    buffer->length = 5;
    p += 5;

    // stmt.id
    sw_mysql_int4store(p, info.id);
    p += 4;
    // flags = CURSOR_TYPE_NO_CURSOR
    sw_mysql_int1store(p, 0);
    p += 1;
    // iteration_count
    sw_mysql_int4store(p, 1);
    p += 4;
    buffer->length += 9;

    if (param_count != 0)
    {
        // null bitmap
        size_t null_start_offset = p - buffer->str;
        unsigned int map_size = (param_count + 7) / 8;
        memset(p, 0, map_size);
        p += map_size;
        buffer->length += map_size;

        // rebind
        sw_mysql_int1store(p, 1);
        p += 1;
        buffer->length += 1;

        size_t type_start_offset = p - buffer->str;
        p += param_count * 2;
        buffer->length += param_count * 2;

        zend_ulong index = 0;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(params), value)
        {
            if (ZVAL_IS_NULL(value))
            {
                *((buffer->str + null_start_offset) + (index / 8)) |= (1UL << (index % 8));
                sw_mysql_int2store((buffer->str + type_start_offset) + (index * 2), SW_MYSQL_TYPE_NULL);
            }
            else
            {
                sw_mysql_int2store((buffer->str + type_start_offset) + (index * 2), SW_MYSQL_TYPE_VAR_STRING);
                zend::string str_value(value);

                if (str_value.len() > 0xffff)
                {
                    buf[0] = (char) SW_MYSQL_TYPE_VAR_STRING;
                    if (swString_append_ptr(buffer, buf, 1) < 0)
                    {
                        RETURN_FALSE;
                    }
                }
                else if (str_value.len() > 250)
                {
                    buf[0] = (char) SW_MYSQL_TYPE_BLOB;
                    if (swString_append_ptr(buffer, buf, 1) < 0)
                    {
                        RETURN_FALSE;
                    }
                }
                lval = mysql::write_lcb(buf, str_value.len());
                if (swString_append_ptr(buffer, buf, lval) < 0)
                {
                    RETURN_FALSE;
                }
                if (swString_append_ptr(buffer, str_value.val(), str_value.len()) < 0)
                {
                    RETURN_FALSE;
                }
            }
            index++;
        }
        ZEND_HASH_FOREACH_END();
    }
    mysql::client_packet::set_header(buffer->str, buffer->length - SW_MYSQL_PACKET_HEADER_SIZE, 0);
    if (unlikely(!client->send_raw(buffer->str, buffer->length)))
    {
        RETURN_FALSE;
    }
    client->state = SW_MYSQL_STATE_EXECUTE;
    if (client->get_defer())
    {
        RETURN_TRUE;
    }
    recv_execute_response(return_value);
}

void mysql_statement::recv_execute_response(zval *return_value)
{
    const char *data;
    if (unlikely(!(data = client->recv_none_error_packet())))
    {
        RETURN_FALSE;
    }
    if (mysql::server_packet::is_ok(data))
    {
        mysql::ok_packet ok_packet(data);
        result.ok = ok_packet;
        client->state = ok_packet.server_status.more_results_exists() ? SW_MYSQL_STATE_MORE_RESULTS : SW_MYSQL_STATE_IDLE;
        RETURN_TRUE;
    }
#ifdef SW_LOG_TRACE_OPEN
    else
    {
        mysql::lcb_packet lcb_packet(data);
        SW_ASSERT(lcb_packet.length == result.get_fields_length());
    }
#endif
    // skip fileds info (because we have already known it when we prepared statement)
    for (size_t i = 0; i < result.get_fields_length(); i++)
    {
        if (unlikely(!(data = client->recv_packet())))
        {
            RETURN_FALSE;
        }
#ifdef SW_LOG_TRACE_OPEN
        mysql::field_packet field_packet(data);
#endif
    }
    // expect eof
    if (unlikely(!(data = client->recv_eof_packet())))
    {
        RETURN_FALSE;
    }
    client->state = SW_MYSQL_STATE_EXECUTE_FETCH;
    if (client->get_fetch_mode())
    {
        RETURN_TRUE;
    }
    fetch_all(return_value);
}

void mysql_statement::fetch(zval *return_value)
{
    if (unlikely(!is_available()))
    {
        RETURN_FALSE;
    }
    if (unlikely(client->state != SW_MYSQL_STATE_EXECUTE_FETCH))
    {
        RETURN_NULL();
    }
    const char *data;
    if (unlikely(!(data = client->recv_packet())))
    {
        RETURN_FALSE;
    }
    if (mysql::server_packet::is_eof(data))
    {
        mysql::eof_packet eof_packet(data);
        client->state = eof_packet.server_status.more_results_exists() ? SW_MYSQL_STATE_MORE_RESULTS : SW_MYSQL_STATE_IDLE;
        RETURN_NULL();
    }
    do {
        mysql::row_u row;
        const char *p = data + SW_MYSQL_PACKET_HEADER_SIZE, *null_bitmap = p;
        size_t null_count = ((result.get_fields_length() + 9) / 8) + 1;

        swTraceLog(SW_TRACE_MYSQL_CLIENT, "null_count=%u", null_count);
        p += null_count;

        array_init_size(return_value, result.get_fields_length());
        for (uint32_t i = 0; i < result.get_fields_length(); i++)
        {
            mysql::field_packet *field = result.get_field(i);

            /* to check Null-Bitmap @see https://dev.mysql.com/doc/internals/en/null-bitmap.html */
            if (((null_bitmap + 1)[((i + 2) / 8)] & (0x01 << ((i + 2) % 8))) != 0)
            {
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s is null", field->name_length, field->name);
                add_assoc_null_ex(return_value, field->name, field->name_length);
                continue;
            }

            swTraceLog(SW_TRACE_MYSQL_CLIENT, "field#%d: name=%.*s, type=%d, size=%lu", i, field->name_length, field->name, field->type, field->length);

            switch (field->type)
            {
            /* Date Time */
            case SW_MYSQL_TYPE_TIMESTAMP:
            case SW_MYSQL_TYPE_DATETIME:
            {
                mysql::datetime datetime(&p);
                add_assoc_stringl_ex(return_value, field->name, field->name_length, datetime.str(), datetime.len());
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%s", field->name_length, field->name, datetime.str());
                break;
            }
            case SW_MYSQL_TYPE_TIME:
            {
                mysql::time time(&p);
                add_assoc_stringl_ex(return_value, field->name, field->name_length, time.str(), time.len());
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%s", field->name_length, field->name, time.str());
                break;
            }
            case SW_MYSQL_TYPE_YEAR:
            {
                mysql::year year(&p);
                add_assoc_stringl_ex(return_value, field->name, field->name_length, year.str(), year.len());
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%s", field->name_length, field->name, year.str());
                break;
            }
            case SW_MYSQL_TYPE_DATE:
            {
                mysql::date date(&p);
                add_assoc_stringl_ex(return_value, field->name, field->name_length, date.str(), date.len());
                swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%s", field->name_length, field->name, date.str());
                break;
            }
            case SW_MYSQL_TYPE_NULL:
                add_assoc_null_ex(return_value, field->name, field->name_length);
                break;
            /* String */
            case SW_MYSQL_TYPE_TINY_BLOB:
            case SW_MYSQL_TYPE_MEDIUM_BLOB:
            case SW_MYSQL_TYPE_LONG_BLOB:
            case SW_MYSQL_TYPE_BLOB:
            case SW_MYSQL_TYPE_DECIMAL:
            case SW_MYSQL_TYPE_NEWDECIMAL:
            case SW_MYSQL_TYPE_BIT:
            case SW_MYSQL_TYPE_JSON:
            case SW_MYSQL_TYPE_STRING:
            case SW_MYSQL_TYPE_VAR_STRING:
            case SW_MYSQL_TYPE_VARCHAR:
            case SW_MYSQL_TYPE_NEWDATE:
            {
                _add_string:
                mysql::row_data_text row_data_text(&p);
//                tmp_len = mysql_length_coded_binary(&buf[read_n], &len, &nul, packet_length - read_n);
//                if (tmp_len == -1)
//                {
//                    swWarn("mysql response parse error: bad lcb, tmp_len=%d", tmp_len);
//                    read_n = -SW_MYSQL_ERR_BAD_LCB;
//                    goto _error;
//                }
//                read_n += tmp_len;
//                // WARNING: data may be longer than single packet (0x00fffff => 16M)
//                if (unlikely(len > packet_length - read_n))
//                {
//                    zend_string *zstring;
//                    mysql_big_data_info mbdi = { len, n_buf - read_n, packet_length - (uint32_t) read_n, buf + read_n, 0, 0 };
//                    if ((zstring = mysql_decode_big_data(&mbdi)))
//                    {
//                        zval _zdata, *zdata = &_zdata;
//                        ZVAL_STR(zdata, zstring);
//                        add_assoc_zval_ex(return_value, field->name, field->name_length, zdata);
//                        read_n += mbdi.ext_header_len;
//                        packet_length += mbdi.ext_header_len + mbdi.ext_packet_len;
//                    }
//                    else
//                    {
//                        read_n = SW_AGAIN;
//                        goto _error;
//                    }
//                }
//                else
                {
                    add_assoc_stringl_ex(return_value, field->name, field->name_length, row_data_text.body, row_data_text.length);
                }
                break;
            }
            /* Integer */
            case SW_MYSQL_TYPE_TINY:
                if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
                {
                    row.utiny = *(uint8_t *) p;
                    add_assoc_long_ex(return_value, field->name, field->name_length, row.utiny);
                    p += sizeof(row.utiny);
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%u", field->name_length, field->name, row.utiny);
                }
                else
                {
                    row.stiny = *(int8_t *) p;
                    add_assoc_long_ex(return_value, field->name, field->name_length, row.stiny);
                    p += sizeof(row.stiny);
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%d", field->name_length, field->name, row.stiny);
                }
                break;

            case SW_MYSQL_TYPE_SHORT:
                if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
                {
                    row.small = *(uint16_t *) p;
                    add_assoc_long_ex(return_value, field->name, field->name_length, row.small);
                    p += sizeof(row.small);
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%u", field->name_length, field->name, row.small);
                }
                else
                {
                    row.ssmall = *(int16_t *) p;
                    add_assoc_long_ex(return_value, field->name, field->name_length, row.ssmall);
                    p += sizeof(row.ssmall);
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%d", field->name_length, field->name, row.ssmall);
                }
                break;

            case SW_MYSQL_TYPE_INT24:
            case SW_MYSQL_TYPE_LONG:
                if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
                {
                    row.uint = *(uint32_t *) p;
                    add_assoc_long_ex(return_value, field->name, field->name_length, row.uint);
                    p += sizeof(row.uint);
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%u", field->name_length, field->name, row.uint);
                }
                else
                {
                    row.sint = *(int32_t *) p;
                    add_assoc_long_ex(return_value, field->name, field->name_length, row.sint);
                    p += sizeof(row.sint);
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%d", field->name_length, field->name, row.sint);
                }
                break;

            case SW_MYSQL_TYPE_LONGLONG:
                if (field->flags & SW_MYSQL_UNSIGNED_FLAG)
                {
                    row.ubigint = *(uint64_t *) p;
                    add_assoc_ulong_safe_ex(return_value, field->name, field->name_length, row.ubigint);
                    p += sizeof(row.ubigint);
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%llu", field->name_length, field->name, row.ubigint);
                }
                else
                {
                    row.sbigint = *(int64_t *) p;
                    add_assoc_long_ex(return_value, field->name, field->name_length, row.sbigint);
                    p += sizeof(row.sbigint);
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%lld", field->name_length, field->name, row.sbigint);
                }
                break;
            case SW_MYSQL_TYPE_FLOAT:
                {
                    row.mfloat = *(float *) p;
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%.7f", field->name_length, field->name, row.mfloat);
                    row.mdouble = _php_math_round(row.mfloat, 5, PHP_ROUND_HALF_DOWN);
                    add_assoc_double_ex(return_value, field->name, field->name_length, row.mdouble);
                    p += sizeof(row.mfloat);
                }
                break;
            case SW_MYSQL_TYPE_DOUBLE:
                {
                    row.mdouble = *(double *) p;
                    swTraceLog(SW_TRACE_MYSQL_CLIENT, "%.*s=%.16f", field->name_length, field->name, row.mdouble);
                    add_assoc_double_ex(return_value, field->name, field->name_length, row.mdouble);
                    p += sizeof(row.mdouble);
                }
                break;
            default:
                swWarn("unknown type[%d] for field [%.*s].", field->type, field->name_length, field->name);
                goto _add_string;
            }
        }
    } while (0);
}

void mysql_statement::fetch_all(zval *return_value)
{
    if (likely(client->state == SW_MYSQL_STATE_EXECUTE_FETCH))
    {
        zval zrow;
        array_init(return_value);
        while (true)
        {
            fetch(&zrow);
            if (unlikely(ZVAL_IS_NULL(&zrow)))
            {
                // eof
                return;
            }
            if (unlikely(Z_TYPE_P(&zrow) == IS_FALSE))
            {
                // error
                zval_ptr_dtor(return_value);
                RETURN_FALSE;
            }
            (void) add_next_index_zval(return_value, &zrow);
        }
    }
    RETURN_NULL();
}

static sw_inline mysql_coro_t* swoole_mysql_coro_fetch_object(zend_object *obj)
{
    return (mysql_coro_t *) ((char *) obj - swoole_mysql_coro_handlers.offset);
}

static sw_inline mysql_client* swoole_get_mysql_client(zval *zobject)
{
    return swoole_mysql_coro_fetch_object(Z_OBJ_P(zobject))->mc;
}

static void swoole_mysql_coro_free_object(zend_object *object)
{
    mysql_coro_t *mc_t = swoole_mysql_coro_fetch_object(object);
    delete mc_t->mc;
    zend_object_std_dtor(&mc_t->std);
}

static zend_object *swoole_mysql_coro_create_object(zend_class_entry *ce)
{
    mysql_coro_t *mc_t = (mysql_coro_t *) ecalloc(1, sizeof(mysql_coro_t) + zend_object_properties_size(ce));
    zend_object_std_init(&mc_t->std, ce);
    object_properties_init(&mc_t->std, ce);
    mc_t->std.handlers = &swoole_mysql_coro_handlers;
    mc_t->mc = new mysql_client();
    return &mc_t->std;
}

static sw_inline mysql_coro_statement_t* swoole_mysql_coro_statement_fetch_object(zend_object *obj)
{
    return (mysql_coro_statement_t *) ((char *) obj - swoole_mysql_coro_statement_handlers.offset);
}

static sw_inline mysql_statement* swoole_get_mysql_statement(zval *zobject)
{
    return swoole_mysql_coro_statement_fetch_object(Z_OBJ_P(zobject))->statement;
}

static void swoole_mysql_coro_statement_free_object(zend_object *object)
{
    mysql_coro_statement_t *mstmt_t = swoole_mysql_coro_statement_fetch_object(object);
    if (likely(mstmt_t->statement))
    {
        delete mstmt_t->statement;
    }
    zend_object_std_dtor(&mstmt_t->std);
}

static sw_inline zend_object *swoole_mysql_coro_statement_create_object(zend_class_entry *ce, mysql_statement *statement)
{
    mysql_coro_statement_t *mstmt_t = (mysql_coro_statement_t *) ecalloc(1, sizeof(mysql_coro_statement_t) + zend_object_properties_size(ce));
    zend_object_std_init(&mstmt_t->std, ce);
    object_properties_init(&mstmt_t->std, ce);
    mstmt_t->std.handlers = &swoole_mysql_coro_statement_handlers;
    if (UNEXPECTED(!statement))
    {
        swoole_php_fatal_error(E_ERROR, "you must create mysql statement object by prepare method");
        return nullptr;
    }
    else
    {
        SW_ASSERT(statement != (mysql_statement * ) -1); // for defer mode
        zval zobject;
        ZVAL_OBJ(&zobject, &mstmt_t->std);
        zend_update_property_long(ce, &zobject, ZEND_STRL("id"), statement->info.id);
        mstmt_t->statement = statement;
    }
    return &mstmt_t->std;
}

static sw_inline zend_object *swoole_mysql_coro_statement_create_object(mysql_statement *statement)
{
    return swoole_mysql_coro_statement_create_object(swoole_mysql_coro_statement_ce_ptr, statement);
}

static zend_object *swoole_mysql_coro_statement_create_object(zend_class_entry *ce)
{
    return swoole_mysql_coro_statement_create_object(ce, nullptr);
}

static sw_inline void swoole_mysql_coro_sync_error_properties(zval *zobject, int error_code, const char *error_msg)
{
    SW_ASSERT(Z_OBJCE_P(zobject) == swoole_mysql_coro_ce_ptr || Z_OBJCE_P(zobject) == swoole_mysql_coro_statement_ce_ptr);
    zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("errno"), error_code);
    zend_update_property_string(Z_OBJCE_P(zobject), zobject, ZEND_STRL("error"), error_msg);
}

static sw_inline void swoole_mysql_coro_sync_result_properties(zval *zobject, zend_long affect_rows, zend_long last_insert_id)
{
    SW_ASSERT(Z_OBJCE_P(zobject) == swoole_mysql_coro_ce_ptr || Z_OBJCE_P(zobject) == swoole_mysql_coro_statement_ce_ptr);
    zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("affected_rows"), affect_rows);
    zend_update_property_long(Z_OBJCE_P(zobject), zobject, ZEND_STRL("insert_id"), last_insert_id);
}

void swoole_mysql_coro_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_mysql_coro, "Swoole\\Coroutine\\MySQL", NULL, "Co\\MySQL", swoole_mysql_coro_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_mysql_coro, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_mysql_coro, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_mysql_coro, zend_class_unset_property_deny);
    SWOOLE_SET_CLASS_CUSTOM_OBJECT(swoole_mysql_coro, swoole_mysql_coro_create_object, swoole_mysql_coro_free_object, mysql_coro_t, std);

    SWOOLE_INIT_CLASS_ENTRY(swoole_mysql_coro_statement, "Swoole\\Coroutine\\MySQL\\Statement", NULL, "Co\\MySQL\\Statement", swoole_mysql_coro_statement_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_mysql_coro_statement, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_mysql_coro_statement, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_mysql_coro_statement, zend_class_unset_property_deny);
    SWOOLE_SET_CLASS_CUSTOM_OBJECT(swoole_mysql_coro_statement, swoole_mysql_coro_statement_create_object, swoole_mysql_coro_statement_free_object, mysql_coro_statement_t, std);

    SWOOLE_INIT_CLASS_ENTRY_EX(swoole_mysql_coro_exception, "Swoole\\Coroutine\\MySQL\\Exception", NULL, "Co\\MySQL\\Exception", NULL, swoole_exception);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_mysql_coro_exception, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_mysql_coro_exception, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_mysql_coro_exception, zend_class_unset_property_deny);

    zend_declare_property_null(swoole_mysql_coro_ce_ptr, ZEND_STRL("serverInfo"), ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce_ptr, ZEND_STRL("sock"), -1, ZEND_ACC_PUBLIC);
    zend_declare_property_bool(swoole_mysql_coro_ce_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce_ptr, ZEND_STRL("connect_errno"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_mysql_coro_ce_ptr, ZEND_STRL("connect_error"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce_ptr, ZEND_STRL("affected_rows"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce_ptr, ZEND_STRL("insert_id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_mysql_coro_ce_ptr, ZEND_STRL("error"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_ce_ptr, ZEND_STRL("errno"), 0, ZEND_ACC_PUBLIC);

    zend_declare_property_long(swoole_mysql_coro_statement_ce_ptr, ZEND_STRL("id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_statement_ce_ptr, ZEND_STRL("affected_rows"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_statement_ce_ptr, ZEND_STRL("insert_id"), 0, ZEND_ACC_PUBLIC);
    zend_declare_property_string(swoole_mysql_coro_statement_ce_ptr, ZEND_STRL("error"), "", ZEND_ACC_PUBLIC);
    zend_declare_property_long(swoole_mysql_coro_statement_ce_ptr, ZEND_STRL("errno"), 0, ZEND_ACC_PUBLIC);
}

static PHP_METHOD(swoole_mysql_coro, __construct) { }
static PHP_METHOD(swoole_mysql_coro, __destruct) { }

static PHP_METHOD(swoole_mysql_coro, connect)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    zval *zserver_info = nullptr;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY_EX(zserver_info, 1, 0)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (zserver_info)
    {
        HashTable *ht = Z_ARRVAL_P(zserver_info);
        zval *ztmp;

        if (php_swoole_array_get_value(ht, "host", ztmp))
        {
            mc->host = std::string(zend::string(ztmp).val());
        }
        else
        {
            zend_throw_exception(swoole_mysql_coro_exception_ce_ptr, "HOST parameter is required.", 11);
            RETURN_FALSE;
        }
        if (php_swoole_array_get_value(ht, "port", ztmp))
        {
            mc->port = zval_get_long(ztmp);
        }
        if (php_swoole_array_get_value(ht, "user", ztmp))
        {
            mc->user = std::string(zend::string(ztmp).val());
        }
        else
        {
            zend_throw_exception(swoole_mysql_coro_exception_ce_ptr, "USER parameter is required.", 11);
            RETURN_FALSE;
        }
        if (php_swoole_array_get_value(ht, "password", ztmp))
        {
            mc->password = std::string(zend::string(ztmp).val());
        }
        else
        {
            zend_throw_exception(swoole_mysql_coro_exception_ce_ptr, "PASSWORD parameter is required.", 11);
            RETURN_FALSE;
        }
        if (php_swoole_array_get_value(ht, "database", ztmp))
        {
            mc->database = std::string(zend::string(ztmp).val());
        }
        else
        {
            zend_throw_exception(swoole_mysql_coro_exception_ce_ptr, "DATABASE parameter is required.", 11);
            RETURN_FALSE;
        }
        if (php_swoole_array_get_value(ht, "timeout", ztmp))
        {
            mc->connect_timeout = zval_get_double(ztmp);
        }
        if (php_swoole_array_get_value(ht, "charset", ztmp))
        {
            zend::string zstr_charset(ztmp);
            char charset = mysql::get_charset(zstr_charset.val());
            if (charset < 0)
            {
                zend_throw_exception_ex(swoole_mysql_coro_exception_ce_ptr, 11, "Unknown charset [%s].", zstr_charset.val());
                RETURN_FALSE;
            }
            mc->charset = charset;
        }
        if (php_swoole_array_get_value(ht, "strict_type", ztmp))
        {
            mc->strict_type = zval_is_true(ztmp);
        }
        if (php_swoole_array_get_value(ht, "fetch_mode", ztmp))
        {
            if (UNEXPECTED(!mc->set_fetch_mode(zval_is_true(ztmp))))
            {
                swoole_php_fatal_error(E_WARNING, "%s", mc->error_msg.c_str());
            }
        }
    }
    if (!mc->connect())
    {
        zend_update_property_long(swoole_mysql_coro_ce_ptr, getThis(), ZEND_STRL("connect_errno"), mc->error_code);
        zend_update_property_string(swoole_mysql_coro_ce_ptr, getThis(), ZEND_STRL("connect_error"), mc->error_msg.c_str());
        RETURN_FALSE;
    }
    if (zserver_info && php_swoole_array_length(zserver_info) > 0)
    {
        php_array_merge(
            Z_ARRVAL_P(sw_zend_read_property_array(swoole_mysql_coro_ce_ptr, getThis(), ZEND_STRL("serverInfo"), 0)),
            Z_ARRVAL_P(zserver_info)
        );
    }
    zend_update_property_long(swoole_mysql_coro_ce_ptr, getThis(), ZEND_STRL("sock"), mc->get_fd());
    zend_update_property_bool(swoole_mysql_coro_ce_ptr, getThis(), ZEND_STRL("connected"), 1);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql_coro, getDefer)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    RETURN_BOOL(mc->get_defer());
}

static PHP_METHOD(swoole_mysql_coro, setDefer)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    zend_bool defer = 1;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_BOOL(defer)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    bool ret = mc->set_defer(defer);
    if (UNEXPECTED(!ret))
    {
        swoole_php_fatal_error(E_WARNING, "%s", mc->error_msg.c_str());
    }
    RETURN_BOOL(ret);
}

static PHP_METHOD(swoole_mysql_coro, query)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    char *sql;
    size_t sql_length;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(sql, sql_length)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    mc->query(return_value, sql, sql_length, timeout);
}

static PHP_METHOD(swoole_mysql_coro, fetch)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    mc->fetch(return_value);
}

static PHP_METHOD(swoole_mysql_coro, fetchAll)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    mc->fetch_all(return_value);
}

static PHP_METHOD(swoole_mysql_coro, nextResult)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    mc->next_result(return_value);
}

static PHP_METHOD(swoole_mysql_coro, prepare)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    char *statement;
    size_t statement_length;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(statement, statement_length)
        Z_PARAM_OPTIONAL
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    mysql_statement *statement_object = mc->prepare(statement, statement_length, timeout);
    if (UNEXPECTED(!statement_object))
    {
        RETURN_FALSE;
    }
    if (mc->state == SW_MYSQL_STATE_PREPARE)
    {
        RETURN_TRUE;
    }
    RETURN_OBJ(swoole_mysql_coro_statement_create_object(statement_object));
}

static PHP_METHOD(swoole_mysql_coro, recv)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    switch(mc->state)
    {
    case SW_MYSQL_STATE_QUERY:
        mc->recv_query_response(return_value);
        return;
    case SW_MYSQL_STATE_PREPARE:
    {
        mysql_statement *statement_object = mc->recv_prepare_response();
        if (UNEXPECTED(!statement_object))
        {
            RETURN_FALSE;
        }
        RETURN_OBJ(swoole_mysql_coro_statement_create_object(statement_object));
        break; // for ide
    }
    default:
        swoole_mysql_coro_sync_error_properties(getThis(), ENOMSG, "no message to receive");
        RETURN_FALSE;
    }
}

static void swoole_mysql_coro_query_transcation(INTERNAL_FUNCTION_PARAMETERS, const char* command, size_t command_length)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    if (UNEXPECTED(mc->get_defer()))
    {
        swoole_php_fatal_error(E_WARNING, "you should not query transaction when defer mode is on, if you want, please use `query` instead.");
    }
    mc->query(return_value, command, command_length);
}

static PHP_METHOD(swoole_mysql_coro, begin)
{
    swoole_mysql_coro_query_transcation(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("BEGIN"));
}

static PHP_METHOD(swoole_mysql_coro, commit)
{
    swoole_mysql_coro_query_transcation(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("COMMIT"));
}

static PHP_METHOD(swoole_mysql_coro, rollback)
{
    swoole_mysql_coro_query_transcation(INTERNAL_FUNCTION_PARAM_PASSTHRU, ZEND_STRL("ROLLBACK"));
}

#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql_coro, escape)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    char *str;
    size_t str_length;
    zend_long flags = 0;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(str, str_length)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    char *newstr = (char *) safe_emalloc(2, str_length + 1, 1);
    if (!newstr)
    {
        swoole_php_fatal_error(E_ERROR, "emalloc(%ld) failed.", str_length + 1);
        RETURN_FALSE;
    }
    const MYSQLND_CHARSET* cset = mysqlnd_find_charset_nr(mc->charset);
    if (!cset)
    {
        swoole_php_fatal_error(E_ERROR, "unknown mysql charset[%d].", mc->charset);
        RETURN_FALSE;
    }
    zend_ulong newstr_len = mysqlnd_cset_escape_slashes(cset, newstr, str, str_length);
    if (newstr_len == (zend_ulong) ~0)
    {
        swoole_php_fatal_error(E_ERROR, "mysqlnd_cset_escape_slashes() failed.");
        RETURN_FALSE;
    }
    RETVAL_STRINGL(newstr, newstr_len);
    efree(newstr);
    return;
}
#endif

static PHP_METHOD(swoole_mysql_coro, close)
{
    mysql_client *mc = swoole_get_mysql_client(getThis());
    mc->close();
    zend_update_property_bool(swoole_mysql_coro_ce_ptr, getThis(), ZEND_STRL("connected"), 0);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql_coro_statement, execute)
{
    mysql_statement *statement = swoole_get_mysql_statement(getThis());
    zval *params = nullptr;
    double timeout = 0;

    ZEND_PARSE_PARAMETERS_START(0, 2)
        Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY(params)
        Z_PARAM_DOUBLE(timeout)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    statement->execute(return_value, params);
    switch(Z_TYPE_P(return_value))
    {
    case IS_TRUE:
    {
        mysql::ok_packet *ok_packet = &statement->result.ok;
        swoole_mysql_coro_sync_result_properties(getThis(), ok_packet->affected_rows, ok_packet->last_insert_id);
        break;
    }
    case IS_FALSE:
        swoole_mysql_coro_sync_error_properties(getThis(), statement->error_code, statement->error_msg.c_str());
        break;
    }
}

static PHP_METHOD(swoole_mysql_coro_statement, fetch)
{
    mysql_statement *statement = swoole_get_mysql_statement(getThis());
}

static PHP_METHOD(swoole_mysql_coro_statement, fetchAll)
{
}

static PHP_METHOD(swoole_mysql_coro_statement, nextResult)
{
}
