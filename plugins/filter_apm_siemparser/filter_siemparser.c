#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>
#include <string.h>
#include <io.h>
#include <stdlib.h>
#include "filter_siemparser.h"
#define PLUGIN_NAME "filter:apm_siemparser"

// Define global siemSock socket
int siemSock = 0;

static int connect_socket(int port)
{
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
    {
        flb_error("[%s] Invalid address/ Address not supported", PLUGIN_NAME);
        return -1;
    }
    if ((siemSock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        flb_error("[%s] Socket creation error on port %d",PLUGIN_NAME, port);
        return -1;
    }
    if (connect(siemSock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        flb_error("[%s] Connection Failed on port %d", PLUGIN_NAME, port);
        return -1;
    }
    else
    {
        flb_info("[%s] Connected to port %d", PLUGIN_NAME, port);
    }
    return siemSock;
}

static int configure(struct siemparser_ctx *ctx, struct flb_filter_instance *f_ins)
{
    struct flb_kv *kv = NULL;
    struct mk_list *head = NULL;
    ctx->lookup_key_check = NOT_AVAILABLE;
    ctx->port_key_check = NOT_AVAILABLE;
    mk_list_foreach(head, &f_ins->properties)
    {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (!strcasecmp(kv->key, LOOKUPKEY))
        {
            ctx->lookup_key_check = AVAILABLE;
            ctx->Agent_key = flb_strndup(kv->val, flb_sds_len(kv->val));
            ctx->Agent_key_len = flb_sds_len(kv->val);
        }

        if (!strcasecmp(kv->key, PORTKEY))
        {
            ctx->port_key_check = AVAILABLE;
            ctx->port = flb_strndup(kv->val, flb_sds_len(kv->val));
            ctx->port_key_len = flb_sds_len(kv->val);
        }
    }
    if (ctx->lookup_key_check == NOT_AVAILABLE)
    {
        flb_error("[%s] lookup key not found", PLUGIN_NAME);
        return -1;
    }
    if (ctx->port_key_check == NOT_AVAILABLE)
    {
        flb_error("[%s] port key not found", PLUGIN_NAME);
        return -1;
    }
    if (connect_socket(atoi(ctx->port)) < 0)
    {
        return 0;
    }
    return 0;
}

static int cb_modifier_init_apm_siem(struct flb_filter_instance *f_ins,
                            struct flb_config *config,
                            void *data)
{
    struct siemparser_ctx *ctx = NULL;
    ctx = flb_malloc(sizeof(struct siemparser_ctx));
    if (!ctx)
    {
        flb_errno();
        return -1;
    }
    if (configure(ctx, f_ins) < 0)
    {
        flb_free(ctx);
        ctx = NULL;
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int get_agent_info(char *agent, int port, msgpack_packer *packer)
{
    int valread = 0, retry = 0;
    char buffer[1024] = {0};
    char *entry;
    if (send(siemSock, agent, strlen(agent), 0) == -1)
    {
        flb_error("[%s] Error in sending the agent %s", PLUGIN_NAME, agent);
        goto retry;
    }
    valread = recv(siemSock, buffer, 1024, 0);
    if (valread == 0 || valread == -1)
    {
        retry:
        do
        {
            flb_info("[%s] Trying to reconnect the socket: retry %d/%d", PLUGIN_NAME, retry, RETRIES) ;
            if (connect_socket(port) < 0)
            {
                flb_info("[%s] Unable to reconnect the socket", PLUGIN_NAME);
                if (retry++ > RETRIES) {
                    return unable_to_connect;
                }
                continue;
            }
            if (send(siemSock, agent, strlen(agent), 0) == -1)
            {
                flb_error("[%s] Error in sending the agent %s: retry %d/%d", PLUGIN_NAME, agent,  retry, RETRIES);
                if (retry++ > RETRIES) {
                    return unable_to_connect;
                }
                continue;
            }
            valread = recv(siemSock, buffer, 1024, 0);
        } while (valread == 0);
    }

    entry = strtok(buffer, "}");
    while (entry != NULL)
    {
        msgpack_pack_str(packer, strlen(entry));
        msgpack_pack_str_body(packer, entry, strlen(entry));
        entry = strtok(NULL, "}");
    }
    return data_collected;
}


static int cb_modifier_filter(const void* data, size_t bytes,
    const char* tag, int tag_len,
    void** out_buf, size_t* out_size,
    struct flb_filter_instance* f_ins,
    void* context,
    struct flb_config* config)
{
    struct siemparser_ctx* ctx = context;
    //flb_info("ppm %d",ctx->Agent_key->len);
    size_t off = 0;
    int siem_parser_status = agent_not_available;
    int map_num = 0;
    struct flb_time tm;
    msgpack_sbuffer sbuffer;
    msgpack_packer packer;
    msgpack_unpacked unpacked;
    msgpack_object* obj, * old_record_key, * old_record_value;
    msgpack_object_kv* kv;
    msgpack_sbuffer_init(&sbuffer);
    msgpack_packer_init(&packer, &sbuffer, msgpack_sbuffer_write);
    msgpack_unpacked_init(&unpacked);

    while (msgpack_unpack_next(&unpacked, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS)
    {

        if (unpacked.data.type != MSGPACK_OBJECT_ARRAY)
        {
            continue;
        }
        flb_time_pop_from_msgpack(&tm, &unpacked, &obj);

        if (obj->type == MSGPACK_OBJECT_MAP)
        {
            map_num = obj->via.map.size;
        }
        else
        {
            continue;
        }
        msgpack_pack_array(&packer, 2);
        flb_time_append_to_msgpack(&tm, &packer, 0);

        kv = obj->via.map.ptr;
        int i = 0;
        int EventID = 0;
        char* Sid = NULL;
        double  time = 0;
        char* targetAccountDomainName = NULL;
        char* accountName = NULL;
        char* accountDomain = NULL;
        char* targetAccountName = NULL;
        char* SendingMessage = NULL;
        int newEntries = 0;
        bool eventToProcess = false;
        for (i = 0; i < map_num; i++)
        {
            old_record_key = &(kv + i)->key;
            old_record_value = &(kv + i)->val;
            if (old_record_key->type == MSGPACK_OBJECT_STR && !strncasecmp(old_record_key->via.str.ptr, "EventID", 7))
            {
                if (old_record_value->via.i64 == 4624 || old_record_value->via.i64 == 4625) {
                    newEntries = 4;
                    msgpack_pack_map(&packer, map_num + newEntries);
                    EventID = old_record_value->via.i64;
                    eventToProcess = true;
                    flb_info("EventID value %d", EventID);

                }
                if (old_record_value->via.i64 == 1033 || old_record_value->via.i64 == 1034) {
                    newEntries = 3;
                    msgpack_pack_map(&packer, map_num + newEntries);
                    EventID = old_record_value->via.i64;
                    eventToProcess = true;
                    flb_info("EventID value %d", EventID);

                }
                if (old_record_value->via.i64 == 4720) {
                    newEntries = 3;
                    msgpack_pack_map(&packer, map_num + newEntries);
                    EventID = old_record_value->via.i64;
                    eventToProcess = true;
                    flb_info("EventID value %d", EventID);
                }
                if (old_record_value->via.i64 == 4726) {
                    newEntries = 2;
                    msgpack_pack_map(&packer, map_num + newEntries);
                    EventID = old_record_value->via.i64;
                    eventToProcess = true;
                    flb_info("EventID value %d", EventID);

                }
                if (old_record_value->via.i64 == 4616) {
                    newEntries = 4;
                    msgpack_pack_map(&packer, map_num + newEntries);
                    EventID = old_record_value->via.i64;
                    eventToProcess = true;
                    flb_info("EventID value %d", EventID);

                }
                if (old_record_value->via.i64 == 104) {
                    newEntries = 2;
                    msgpack_pack_map(&packer, map_num + newEntries);
                    EventID = old_record_value->via.i64;
                    eventToProcess = true;
                    flb_info("EventID value %d", EventID);

                }

            }
            if (old_record_key->type == MSGPACK_OBJECT_STR && !strncasecmp(old_record_key->via.str.ptr, "Sid", 3))
            {
                Sid = flb_strndup(old_record_value->via.str.ptr, old_record_value->via.str.size);
                flb_info("sid value %s", Sid);
            }
            if (old_record_key->type == MSGPACK_OBJECT_STR && !strncmp(old_record_key->via.str.ptr, "targetAccountDomainName", 23))
            {
                targetAccountDomainName = flb_strndup(old_record_value->via.str.ptr, old_record_value->via.str.size);
                flb_info("targetAccountDomainName %s", targetAccountDomainName);
            }
            if (old_record_key->type == MSGPACK_OBJECT_STR && !strncasecmp(old_record_key->via.str.ptr, "accountName", 11)) {
                accountName = flb_strndup(old_record_value->via.str.ptr, old_record_value->via.str.size);
                flb_info("accountName %s", accountName);
            }
            if (old_record_key->type == MSGPACK_OBJECT_STR && !strncasecmp(old_record_key->via.str.ptr, "accountDomain", 13))
            {
                accountDomain = flb_strndup(old_record_value->via.str.ptr, old_record_value->via.str.size);
                flb_info("accountDomain %s", accountDomain);
            }
            if (old_record_key->type == MSGPACK_OBJECT_STR && !strncasecmp(old_record_key->via.str.ptr, "targetAccountName", 17)) {
                targetAccountName = flb_strndup(old_record_value->via.str.ptr, old_record_value->via.str.size);
                flb_info("targetAccountName %s", targetAccountName);
            }
        }
        for (i = 0; i < map_num; i++) {
            msgpack_pack_object(&packer, (kv + i)->key);
            msgpack_pack_object(&packer, (kv + i)->val);
        }

        if (eventToProcess == false) {
            continue;
        }
        if (EventID == 4624 || EventID == 4625) {
            flb_info("%d^%s^%s", EventID, accountName, accountDomain);
            sprintf(SendingMessage, "%d^%s^%s", EventID, accountName, accountDomain);
        }
        if (EventID == 4720) {
            flb_info("%d^%s^%s", EventID, targetAccountName, targetAccountDomainName);
            sprintf(SendingMessage, "%d^%s^%s", EventID, targetAccountName, targetAccountDomainName);
        }
        if (EventID == 1033 || EventID == 1034) {
            flb_info("%d^%s", EventID, Sid);
            sprintf(SendingMessage, "%d^%s", EventID, Sid);
        }

        //SendingMessage = "4624^An account was successfully logged on.\\r\\n\\r\\nSubject:\\r\\n\\tSecurity ID : \\t\\tS - 1 - 5 - 18\\r\\n\\tAccount Name : \\t\\tXOR - BAN - 274$\\r\\n\\tAccount Domain : \\t\\tWORKGROUP\\r\\n\\tLogon ID : \\t\\t0x3e7\\r\\n\\r\\nLogon Information : \\r\\n\\tLogon Type : \\t\\t2\\r\\n\\tRestricted Admin Mode : \\t - \\r\\n\\tVirtual Account : \\t\\t % %1843\\r\\n\\tElevated Token : \\t\\t % %1842\\r\\n\\r\\nImpersonation Level : \\t\\t % %1833\\r\\n\\r\\nNew Logon : \\r\\n\\tSecurity ID : \\t\\tS - 1 - 5 - 21 - 2547325851 - 3128153700 - 699163993 - 1003\\r\\n\\tAccount Name : \\t\\tsrivathsa.mugalodi\\r\\n\\tAccount Domain : \\t\\tXOR - BAN - 274\\r\\n\\tLogon ID : \\t\\t0x1062789\\r\\n\\tLinked Logon ID : \\t\\t0x10627b6\\r\\n\\tNetwork Account Name : \\t - \\r\\n\\tNetwork Account Domain : \\t - \\r\\n\\tLogon GUID : \\t\\t{ 00000000 - 0000 - 0000 - 0000 - 000000000000 }\\r\\n\\r\\nProcess Information : \\r\\n\\tProcess ID : \\t\\t0x868\\r\\n\\tProcess Name : \\t\\tC:\\Windows\\System32\\svchost.exe\\r\\n\\r\\nNetwork Information : \\r\\n\\tWorkstation Name : \\tXOR - BAN - 274\\r\\n\\tSource Network Address : \\t127.0.0.1\\r\\n\\tSource Port : \\t\\t0\\r\\n\\r\\nDetailed Authentication Information : \\r\\n\\tLogon Process : \\t\\tUser32 \\r\\n\\tAuthentication Package : \\tNegotiate\\r\\n\\tTransited Services : \\t - \\r\\n\\tPackage Name(NTLM only) :\\t - \\r\\n\\tKey Length : \\t\\t0\\r\\n\\r\\nThis event is generated when a logon session is created.It is generated on the computer that was accessed.\\r\\n\\r\\nThe subject fields indicate the account on the local system which requested the logon.This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\\r\\n\\r\\nThe logon type field indicates the kind of logon that occurred.The most common types are 2 (interactive) and 3 (network).\\r\\n\\r\\nThe New Logon fields indicate the account for whom the new logon was created, i.e.the account that was logged on.\\r\\n\\r\\nThe network fields indicate where a remote logon request originated.Workstation name is not always availableand may be left blank in some cases.\\r\\n\\r\\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\\r\\n\\r\\nThe authentication information fields provide detailed information about this specific logon request.\\r\\n\\t - Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\\r\\n\\t - Transited services indicate which intermediate services have participated in this logon request.\\r\\n\\t - Package name indicates which sub - protocol was used among the NTLM protocols.\\r\\n\\t - Key length indicates the length of the generated session key.This will be 0 if no session key was requested.\\r\\n\\n^ S - 1 - 5 - 21 - 3144977761 - 145940102 - 240959454 - 1239 ^ 9:30 ^ 17 : 00 ^ 1646655800440";
        //sprintf(SendingMessage, "%d^%s^%s^%s^%s^%f", EventID, message, Sid, OfficeLogOutTime, OfficeLogInTime, time);
        char* endln = "\n";
        strncat(SendingMessage, endln, strlen(endln));
        flb_info("[%s] Sending siem message: %s", PLUGIN_NAME, SendingMessage);

        siem_parser_status = get_agent_info(SendingMessage, atoi(ctx->port), &packer);
        if (siem_parser_status == unable_to_connect)
        {
            msgpack_sbuffer_destroy(&sbuffer);
            return FLB_FILTER_NOTOUCH;
        }
        msgpack_unpacked_destroy(&unpacked);
        *out_buf = sbuffer.data;
        *out_size = sbuffer.size;
        return FLB_FILTER_MODIFIED;
    }
}
static int cb_modifier_exit(void *data, struct flb_config *config)
{
    struct siemparser_ctx *ctx = data;
    close(siemSock);
    if (ctx != NULL)
    {
        flb_free(ctx->Agent_key);
        ctx->Agent_key = NULL;
        flb_free(ctx->port);
        ctx->port = NULL;
        flb_free(ctx);
        ctx = NULL;
    }
    return 0;
}
struct flb_filter_plugin filter_apm_siemparser_plugin = {
    .name = "apm_siemparser",
    .description = "Adds siem metric Information",
    .cb_init = cb_modifier_init_apm_siem,
    .cb_filter = cb_modifier_filter,
    .cb_exit = cb_modifier_exit,
    .flags = 0};
