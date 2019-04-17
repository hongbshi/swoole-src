/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http:// www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "mysql.h"

using namespace swoole::mysql;

static uint32_t sha1_password_with_nonce(char* buf, const char* nonce, const char* password)
{
    char hash_0[20] = {0};
    swoole_sha1(password, strlen(password), (uchar *) hash_0);

    char hash_1[20] = {0};
    swoole_sha1(hash_0, sizeof (hash_0), (uchar *) hash_1);

    char str[40];
    memcpy(str, nonce, 20);
    memcpy(str + 20, hash_1, 20);

    char hash_2[20];
    swoole_sha1(str, sizeof (str), (uchar *) hash_2);

    char hash_3[20];

    int *a = (int *) hash_2;
    int *b = (int *) hash_0;
    int *c = (int *) hash_3;

    int i;
    for (i = 0; i < 5; i++)
    {
        c[i] = a[i] ^ b[i];
    }
    memcpy(buf, hash_3, 20);
    return 20;
}

static uint32_t sha256_password_with_nonce(char* buf, const char* nonce, const char* password)
{
    // XOR(SHA256(password), SHA256(SHA256(SHA256(password)), nonce))
    char hashed[32], double_hashed[32];
    swoole_sha256(password, strlen(password), (unsigned char *) hashed);
    swoole_sha256(hashed, 32, (unsigned char *) double_hashed);
    char combined[32 + SW_MYSQL_NONCE_LENGTH]; //double-hashed + nonce
    memcpy(combined, double_hashed, 32);
    memcpy(combined + 32, nonce, SW_MYSQL_NONCE_LENGTH);
    char xor_bytes[32];
    swoole_sha256(combined, 32 + SW_MYSQL_NONCE_LENGTH, (unsigned char *) xor_bytes);
    int i;
    for (i = 0; i < 32; i++)
    {
        hashed[i] ^= xor_bytes[i];
    }
    memcpy(buf, hashed, 32);
    return 32;
}

/** @return: password length */
static sw_inline uint32_t mysql_auth_encrypt_dispatch(char *buf, const std::string auth_plugin_name, const char* nonce, const char *password)
{
    if (auth_plugin_name.length() == 0 || auth_plugin_name == "mysql_native_password")
    {
        // mysql_native_password is default
        return sha1_password_with_nonce(buf, nonce, password);
    }
    else if (auth_plugin_name == "caching_sha2_password")
    {
        return sha256_password_with_nonce(buf, nonce, password);
    }
    else
    {
        swWarn("Unknown auth plugin: %s", auth_plugin_name.c_str());
        return 0;
    }
}

eof_packet::eof_packet(const char *data) : server_packet(data)
{
    swMysqlPacketDump(header.length, header.number, data, "EOF_Packet");
    // EOF_Packet = Packet header (4 bytes) + 0xFE + warning(2byte) + status(2byte)
    data += SW_MYSQL_PACKET_HEADER_SIZE;
    // int<1>   header  [fe] EOF header
    data += 1;
    // int<2>   warnings    number of warnings
    warning_count = sw_mysql_uint2korr2korr(data);
    data += 2;
    // int<2>   status_flags    Status Flags
    server_status = sw_mysql_uint2korr2korr(data);
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "EOF_Packet, warnings=%u, status_code=%u", warning_count, server_status);
}

ok_packet::ok_packet(const char *data) : server_packet(data)
{
    swMysqlPacketDump(header.length, header.number, data, "OK_Packet");
    bool nul;
    data += SW_MYSQL_PACKET_HEADER_SIZE;
    // int<1>   header  [00] or [fe] the OK packet header
    data += 1;
    // int<lenenc>  affected_rows   affected rows
    data += read_lcb(data, &affected_rows, &nul);
    // int<lenenc>  last_insert_id  last insert id
    data += read_lcb(data, &last_insert_id, &nul);
    // int<2>   status_flags    status Flags
    server_status = sw_mysql_uint2korr2korr(data);
    data += 2;
    // int<2>   warnings    number of warnings
    warning_count = sw_mysql_uint2korr2korr(data);
    // p += 2;
    swTraceLog(
        SW_TRACE_MYSQL_CLIENT, "OK_Packet, affected_rows=%" PRIu64 ", insert_id=%" PRIu64 ", status_flags=0x%08x, warnings=%u",
        affected_rows, last_insert_id, server_status, warning_count
    );
}

err_packet::err_packet(const char *data) : server_packet(data)
{
    swMysqlPacketDump(header.length, header.number, data, "ERR_Packet");
    // ERR Packet = Packet header (4 bytes) + ERR Payload
    data += SW_MYSQL_PACKET_HEADER_SIZE;
    // int<1>   header  [ff] header of the ERR packet
    data += 1;
    // int<2>   error_code  error-code
    code = sw_mysql_uint2korr2korr(data);
    data += 2;
    // string[1]    sql_state_marker    # marker of the SQL State
    data += 1;
    // string[5]    sql_state   SQL State
    memcpy(sql_state, data, 5);
    sql_state[5] = '\0';
    data += 5;
    // string<EOF>  error_message   human readable error message
    msg = std::string(data, header.length - 9);
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "ERR_Packet, error_code=%u, sql_state=%s, status_msg=[%s]", code, sql_state, msg.c_str());
};

greeting_packet::greeting_packet(const char *data) : server_packet(data)
{
    swMysqlPacketDump(header.length, header.number, data, "Protocol::HandshakeGreeting");
    /**
    1              [0a] protocol version
    string[NUL]    server version
    4              connection id
    string[8]      auth-plugin-data-part-1
    1              [00] filler
    2              capability flags (lower 2 bytes)
      if more data in the packet:
    1              character set
    2              status flags
    2              capability flags (upper 2 bytes)
      if capabilities & CLIENT_PLUGIN_AUTH {
    1              length of auth-plugin-data
      } else {
    1              [00]
      }
    string[10]     reserved (all [00])
      if capabilities & CLIENT_SECURE_CONNECTION {
    string[$len]   auth-plugin-data-part-2 ($len=MAX(13, length of auth-plugin-data - 8))
      if capabilities & CLIENT_PLUGIN_AUTH {
    string[NUL]    auth-plugin name
      }
    */
    const char *p = data + SW_MYSQL_PACKET_HEADER_SIZE;
    // 1              [0a] protocol version
    protocol_version = *p;
    p++;
    // x              server version
    server_version = std::string(p);
    p += server_version.length() + 1;
    // 4              connection id
    connection_id = *((int *) p);
    p += 4;
    // string[8]      auth-plugin-data-part-1
    memcpy(auth_plugin_data, p, 8);
    p += 8;
    // 1              [00] filler
    filler = *p;
    p += 1;
    // 2              capability flags (lower 2 bytes)
    memcpy(((char *) (&capability_flags)), p, 2);
    p += 2;

    if (p < data + header.length)
    {
        // 1              character set
        charset = *p;
        p += 1;
        // 2              status flags
        memcpy(&status_flags, p, 2);
        p += 2;
        // 2              capability flags (upper 2 bytes)
        memcpy(((char *) (&capability_flags) + 2), p, 2);
        p += 2;
        // 1              auth plugin data length
        auth_plugin_data_length = (uint8_t) *p;
        p += 1;
        // x              reserved
        memcpy(&reserved, p, sizeof(reserved));
        p += sizeof(reserved);
        if (capability_flags & SW_MYSQL_CLIENT_SECURE_CONNECTION)
        {
            uint8_t len = MAX(13, auth_plugin_data_length - 8);
            memcpy(auth_plugin_data + 8, p, len);
            p += len;
        }
        if (capability_flags & SW_MYSQL_CLIENT_PLUGIN_AUTH)
        {
            auth_plugin_name = std::string(p, strlen(p));
            swTraceLog(SW_TRACE_MYSQL_CLIENT, "use %s auth plugin", auth_plugin_name.c_str());
        }
    }
    swTraceLog(
        SW_TRACE_MYSQL_CLIENT, "Server protocol=%d, version=%s, connection_id=%d, capabilites=0x%08x, status=%u, auth_plugin_name=%s, auth_plugin_data=L%u[%s]",
        protocol_version, server_version.c_str(), connection_id, capability_flags, status_flags, auth_plugin_name.c_str(), auth_plugin_data_length, auth_plugin_data
    );
};

login_packet::login_packet(
    greeting_packet *greeting_packet,
    const std::string user,
    const std::string password,
    std::string database,
    char charset
)
{
    char *p = data.body;
    uint32_t tint;
    // capability flags, CLIENT_PROTOCOL_41 always set
    tint = SW_MYSQL_CLIENT_LONG_PASSWORD |
            SW_MYSQL_CLIENT_PROTOCOL_41 |
            SW_MYSQL_CLIENT_SECURE_CONNECTION |
            SW_MYSQL_CLIENT_CONNECT_WITH_DB |
            SW_MYSQL_CLIENT_PLUGIN_AUTH |
            SW_MYSQL_CLIENT_MULTI_RESULTS;
    memcpy(p, &tint, sizeof(tint));
    p += sizeof(tint);
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "Client capabilites=0x%08x", tint);
    // max-packet size
    tint = 300;
    memcpy(p, &tint, sizeof(tint));
    p += sizeof(tint);
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "Client max packet=%u", tint);
    // use the server character_set when the character_set is not set.
    *p = charset ? charset : greeting_packet->charset;
    p += 1;
    // string[23]     reserved (all [0])
    p += 23;
    // string[NUL]    username
    strcpy(p, user.c_str());
    p += (user.length() + 1);
    // string[NUL]    password
    if (password.length() > 0)
    {
        *p = mysql_auth_encrypt_dispatch(
            p + 1,
            greeting_packet->auth_plugin_name,
            greeting_packet->auth_plugin_data,
            password.c_str()
        );
    }
    else
    {
        *p = 0;
    }
    swTraceLog(
        SW_TRACE_MYSQL_CLIENT, "Client charset=%u, user=%s, password=%s, hased=L%d[%.*s], database=%s, auth_plugin_name=%s",
        charset, user.c_str(), password.c_str(), (int) *p, (int) *p, p + 1, database.c_str(), greeting_packet->auth_plugin_name.c_str()
    );
    p += (((uint32_t) *p) + 1);
    // string[NUL]    database
    strcpy(p, database.c_str());
    p += (database.length() + 1);
    // string[NUL]    auth plugin name
    strcpy(p, greeting_packet->auth_plugin_name.c_str());
    p += (greeting_packet->auth_plugin_name.length() + 1);
    // packet header
    set_header(p - data.body, greeting_packet->header.number + 1);
    swMysqlPacketDump(get_length(), get_number(), get_data(), "Protocol::HandshakeLogin");
}

auth_switch_request_packet::auth_switch_request_packet(const char *data) : server_packet(data)
{
    swMysqlPacketDump(header.length, header.number, data, "Protocol::AuthSwitchRequest");
    // 4 header
    data += SW_MYSQL_PACKET_HEADER_SIZE;
    // 1 type
    data += 1;
    // string[NUL] auth_method_name
    auth_method_name = std::string(data);
    data += (auth_method_name.length() + 1);
    // string[NUL] auth_method_data
    strcpy(auth_method_data, data);
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "auth switch plugin name=%s", auth_method_name.c_str());
}

auth_switch_response_packet::auth_switch_response_packet(auth_switch_request_packet *req, const std::string password)
{
    // if auth switch is triggered, password can't be empty
    // create auth switch response packet
    set_header(
        mysql_auth_encrypt_dispatch(
            data.body,
            req->auth_method_name,
            req->auth_method_data,
            password.c_str()
        ),
        req->header.number + 1
    );
    swMysqlPacketDump(get_length(), get_number(), get_data(), "Protocol::AuthSignatureResponse");
}

//  Caching sha2 authentication. Public key request and send encrypted password
// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthSwitchResponse
auth_signature_response_packet::auth_signature_response_packet(
    raw_data_packet *raw_data_pakcet,
    const std::string password,
    const char *auth_plugin_data
)
{
#ifndef SW_MYSQL_RSA_SUPPORT
    {
        swWarn(SW_MYSQL_NO_RSA_ERROR);
#else
    if (0)
    {
        _error:
#endif
        data.body[0] = SW_MYSQL_AUTH_SIGNATURE_ERROR;
        set_header(1, raw_data_pakcet->header.number + 1);
        return;
    }
#ifdef SW_MYSQL_RSA_SUPPORT
    const char *tmp = raw_data_pakcet->body;
    uint32_t rsa_public_key_length = raw_data_pakcet->header.length;
    while (tmp[0] != 0x2d)
    {
        tmp++; // ltrim
        rsa_public_key_length--;
    }
    char rsa_public_key[rsa_public_key_length + 1]; //rsa + '\0'
    memcpy((char *)rsa_public_key, tmp, rsa_public_key_length);
    rsa_public_key[rsa_public_key_length] = '\0';
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "rsa_public_key_length=%d;\nrsa_public_key=[%.*s]", rsa_public_key_length, rsa_public_key_length, rsa_public_key);

    size_t password_bytes_length = password.length() + 1;
    unsigned char password_bytes[password_bytes_length];
    // copy NUL terminator to password to stack
    strcpy((char *) password_bytes, password.c_str());
    // XOR the password bytes with the challenge
    for (size_t i = 0; i < password_bytes_length; i++) // include '\0' byte
    {
        password_bytes[i] ^= auth_plugin_data[i % SW_MYSQL_NONCE_LENGTH];
    }

    // prepare RSA public key
    BIO *bio = NULL;
    RSA *public_rsa = NULL;
    if (unlikely((bio = BIO_new_mem_buf((void *)rsa_public_key, -1)) == NULL))
    {
        swWarn("BIO_new_mem_buf publicKey error!");
        goto _error;
    }
    // PEM_read_bio_RSA_PUBKEY
    ERR_clear_error();
    if (unlikely((public_rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL)) == NULL))
    {
        char err_buf[512];
        ERR_load_crypto_strings();
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        swWarn("[PEM_read_bio_RSA_PUBKEY ERROR]: %s", err_buf);
        goto _error;
    }
    BIO_free_all(bio);
    // encrypt with RSA public key
    int rsa_len = RSA_size(public_rsa);
    unsigned char encrypt_msg[rsa_len];
    // RSA_public_encrypt
    ERR_clear_error();
    size_t flen = rsa_len - 42;
    flen = password_bytes_length > flen ? flen : password_bytes_length;
    swTraceLog(SW_TRACE_MYSQL_CLIENT, "rsa_len=%d", rsa_len);
    if (unlikely(RSA_public_encrypt(flen, (const unsigned char *) password_bytes, (unsigned char *) encrypt_msg, public_rsa, RSA_PKCS1_OAEP_PADDING) < 0))
    {
        char err_buf[512];
        ERR_load_crypto_strings();
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        swWarn("[RSA_public_encrypt ERROR]: %s", err_buf);
        goto _error;
    }
    RSA_free(public_rsa);
    memcpy(data.body, (char *)encrypt_msg, rsa_len); // copy rsa to buf
    set_header(rsa_len, raw_data_pakcet->header.number + 1);
    swMysqlPacketDump(get_length(), get_number(), get_data(), "Protocol::AuthSignatureResponse");
#endif
}

void field_packet::parse(const char *data)
{
    server_packet::parse(data);
    bool nul = false;
    char *p = body = new char[header.length];
    memcpy(body, data + SW_MYSQL_PACKET_HEADER_SIZE, header.length);
    // catalog
    p += read_lcb(p, &catalog_length, &nul);
    catalog = p;
    p += catalog_length;
    // database
    p += read_lcb(p, &database_length, &nul);
    database = p;
    p += database_length;
    // table
    p += read_lcb(p, &table_length, &nul);
    table = p;
    p += table_length;
    // origin table
    p += read_lcb(p, &org_table_length, &nul);
    org_table = p;
    p += org_table_length;
    // name
    p += read_lcb(p, &name_length, &nul);
    name = p;
    p += name_length;
    // origin table
    p += read_lcb(p, &org_name_length, &nul);
    org_name = p;
    p += org_name_length;
    // filler
    p += 1;
    // charset
    charset = sw_mysql_uint2korr2korr(p);
    p += 2;
    // binary length
    length = sw_mysql_uint2korr4korr(p);
    p += 4;
    // field type
    type = (uint8_t) *p;
    p += 1;
    // flags
    flags = sw_mysql_uint2korr2korr(p);
    p += 2;
    /* decimals */
    decimals = *p;
    p += 1;
    /* filler */
    p += 2;
    /* default - a priori facultatif */
    if (p < body + header.length)
    {
        p += read_lcb(p, &def_length, &nul);
        def = p;
        p += def_length;
    }
    swMysqlPacketDump(header.length, header.number, data, (*name == '?' ? "Protocol::Param": "Protocol::Field"));
    swTraceLog(
        SW_TRACE_MYSQL_CLIENT,
        "catalog=%.*s, database=%.*s, table=%.*s, org_table=%.*s, name=%.*s, org_name=%.*s,"
        "charset=%u, binary_length=%" PRIu64 ", type=%u, flags=0x%08x, decimals=%u, def=[%.*s]",
        catalog_length, catalog, database_length, database,
        table_length, table, org_table_length, org_table,
        name_length, name, org_name_length, org_name,
        charset, length, type, flags, decimals, def_length, def
    );
}
