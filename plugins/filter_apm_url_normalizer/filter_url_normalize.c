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
#include "filter_url_normalize.h"
#define PLUGIN_NAME "filter:apm_url_normalizer"

// Define global socketFD socket
int socketFD = 0;
int retryConnectCounter = 0;

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
    if ((socketFD = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        flb_error("[%s] Socket creation error on port %d",PLUGIN_NAME, port);
        return -1;
    }
    if (connect(socketFD, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        flb_error("[%s] Connection Failed on port %d", PLUGIN_NAME, port);
        return -1;
    }
    else
    {
        flb_info("[%s] Connected to port %d", PLUGIN_NAME, port);
    }
    return socketFD;
}

static int configure(struct urlnormalizer_ctx *ctx, struct flb_filter_instance *f_ins)
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
            ctx->lookup_key = flb_strndup(kv->val, flb_sds_len(kv->val));
            ctx->lookup_key_len = flb_sds_len(kv->val);
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

static int cb_modifier_init_apm_url_norm(struct flb_filter_instance *f_ins,
                            struct flb_config *config,
                            void *data)
{
    struct urlnormalizer_ctx *ctx = NULL;
    ctx = flb_malloc(sizeof(struct urlnormalizer_ctx));
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

static int get_norm_url(char *path, int port, msgpack_packer *packer)
{
    int size_recv = 0, retry = 0, total_size = 0;
    int new_buffer_len_max = strlen(path) + (SOCKET_BUF_SIZE * 2);
    flb_sds_t new_buffer = flb_sds_create_size(new_buffer_len_max);
    if (!new_buffer) {
        return data_collection_failed;
    }
    flb_sds_t tmp;
    char buffer[SOCKET_BUF_SIZE];
    char *entry;
    int sockSendStatus = 1;
sockSend:
    if ((sockSendStatus = send(socketFD, path, strlen(path), 0)) == -1)
    {
        flb_error("[%s] Error in sending the agent %s", PLUGIN_NAME, path);
        goto retry;
    }
    while (1)
    {
        memset(buffer, 0, SOCKET_BUF_SIZE);
        size_recv = recv(socketFD, buffer, SOCKET_BUF_SIZE, 0);
        if (size_recv < 0)
        {
            retry:
                while (1)
                {
                    flb_info("[%s] Trying to reconnect the socket: retry %d/%d", PLUGIN_NAME, retry, RETRIES) ;
                    if (connect_socket(port) < 0)
                    {
                        flb_info("[%s] Unable to reconnect the socket", PLUGIN_NAME);
                        if (retry++ > RETRIES) {
                            flb_sds_destroy(new_buffer);
                            return unable_to_connect;
                        }
                        continue;
                    }
                    retry = 0;
                    if (sockSendStatus == -1)
                    {
                        goto sockSend;
                    }
                    break;
                }
        }
        else
        {
            if (size_recv == 5) 
            {
                bool to_discard = (strcmp(buffer, END_OF_MESSAGE) == 0);
                if (to_discard)
                {
                    flb_debug("~eom~ sent by the socket: %d",size_recv);
                    break;
                }
            }
           
            flb_debug("Socket data being received in chunks: %d",size_recv);
            if (total_size + size_recv <= new_buffer_len_max)
            {
                tmp = flb_sds_cat(new_buffer, buffer, size_recv);
                if (!tmp) {
                    flb_sds_destroy(new_buffer);
                    return data_collection_failed;
                }
                new_buffer = tmp;
                total_size += size_recv;
            }
            else
            {
                flb_error("Buffer Overflow occurred = %s ", buffer);
                break;
            }
            
            if (size_recv < SOCKET_BUF_SIZE)
            {
                break;
            }
        }
    }

    int desiredSplit = NEW_ENTRIES * 2;
    entry = strtok(new_buffer, "}");
    while (entry != NULL)
    {
        if (desiredSplit == 0 )
        {
            break;
        }
        msgpack_pack_str(packer, strlen(entry));
        msgpack_pack_str_body(packer, entry, strlen(entry));
        entry = strtok(NULL, "}");
        desiredSplit = desiredSplit - 1;
    }
    flb_sds_destroy(new_buffer);
    return data_collected;
}

static int cb_modifier_filter_apm_url_norm(const void *data, size_t bytes,
                              const char *tag, int tag_len,
                              void **out_buf, size_t *out_size,
                              struct flb_filter_instance *f_ins,
                              void *context,
                              struct flb_config *config)
{
    struct urlnormalizer_ctx *ctx = context;
    //flb_info("ppm %d",ctx->lookup_key->len);
    size_t off = 0;
    int collection_status = url_path_not_available;
    int map_num = 0;
    struct flb_time tm;
    msgpack_sbuffer sbuffer;
    msgpack_packer packer;
    msgpack_unpacked unpacked;
    msgpack_object *obj, *old_record_key, *old_record_value;
    msgpack_object_kv *kv;
    msgpack_sbuffer_init(&sbuffer);
    msgpack_packer_init(&packer, &sbuffer, msgpack_sbuffer_write);
    msgpack_unpacked_init(&unpacked);
    size_t urlpath_len = 0;
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
        msgpack_pack_map(&packer, map_num + NEW_ENTRIES);
        kv = obj->via.map.ptr;
        int i = 0;
        for (i = 0; i < map_num; i++)
        {
            old_record_key = &(kv + i)->key;
            old_record_value = &(kv + i)->val;
            if (old_record_key->type == MSGPACK_OBJECT_STR && !strncasecmp(old_record_key->via.str.ptr, ctx->lookup_key, ctx->lookup_key_len) && old_record_value->via.str.size != 0)
            {
                char *urlpath = flb_strndup(old_record_value->via.str.ptr, old_record_value->via.str.size);
                urlpath_len =  old_record_value->via.str.size;
                char *endln = "\n" ;
                char *formattedPath = (char *)flb_malloc(old_record_value->via.str.size + 4);
                strcpy(formattedPath, urlpath);
                strncat(formattedPath, endln, strlen(endln));
                flb_trace("[%s] Sending url path for normalization: %s", PLUGIN_NAME, urlpath);
                //populates record map with agent information
                collection_status = get_norm_url(formattedPath, atoi(ctx->port), &packer);
                if (collection_status != data_collected)
                {
                    if (collection_status == unable_to_connect) 
                    {
                        flb_error("[%s] Unable to establish connection with the socket server: Log retry %d/%d", PLUGIN_NAME, retryConnectCounter, GLOBALRETRIES);
                        retryConnectCounter++;
                    }
                    msgpack_pack_str(&packer, NORMALIZED_PATH_LEN);
                    msgpack_pack_str_body(&packer, NORMALIZED_PATH, NORMALIZED_PATH_LEN);
                    msgpack_pack_str(&packer, urlpath_len);
                    msgpack_pack_str_body(&packer, urlpath, urlpath_len);
                }
                flb_free(formattedPath);
                flb_free(urlpath);
            }
            msgpack_pack_object(&packer, (kv + i)->key);
            msgpack_pack_object(&packer, (kv + i)->val);
        }
    }
    // flb_error(collection_status);
    msgpack_unpacked_destroy(&unpacked);
    if (collection_status == url_path_not_available)
    {
        flb_error("[%s] Lookup key %s not found in the log record", PLUGIN_NAME, ctx->lookup_key);
        msgpack_sbuffer_destroy(&sbuffer);
        return FLB_FILTER_NOTOUCH;
    }
    *out_buf = sbuffer.data;
    *out_size = sbuffer.size;
    return FLB_FILTER_MODIFIED;
}
static int cb_modifier_exit_apm_url_norm(void *data, struct flb_config *config)
{
    struct urlnormalizer_ctx *ctx = data;
    close(socketFD);
    if (ctx != NULL)
    {
        flb_free(ctx->lookup_key);
        ctx->lookup_key = NULL;
        flb_free(ctx->port);
        ctx->port = NULL;
        flb_free(ctx);
        ctx = NULL;
    }
    return 0;
}
struct flb_filter_plugin filter_apm_url_normalizer_plugin = {
    .name = "apm_url_normalizer",
    .description = "Adds Normalized URL Information",
    .cb_init = cb_modifier_init_apm_url_norm,
    .cb_filter = cb_modifier_filter_apm_url_norm,
    .cb_exit = cb_modifier_exit_apm_url_norm,
    .flags = 0};
