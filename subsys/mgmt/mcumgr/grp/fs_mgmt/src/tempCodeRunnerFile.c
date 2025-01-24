#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zcbor_common.h>
#include <zcbor_decode.h>
#include <zcbor_encode.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/net/buf.h>
#include <zephyr/mgmt/mcumgr/mgmt/mgmt.h>
#include <zephyr/mgmt/mcumgr/smp/smp.h>
#include <zephyr/mgmt/mcumgr/smp/smp_client.h>
#include <zephyr/mgmt/mcumgr/transport/smp.h>
#include <zephyr/mgmt/mcumgr/grp/fs_mgmt/fs_mgmt.h>
#include <zephyr/mgmt/mcumgr/grp/fs_mgmt/fs_mgmt_client.h>

#include <mgmt/mcumgr/util/zcbor_bulk.h>
#include <mgmt/mcumgr/transport/smp_internal.h>

#define FILE_MGMT_DATA_SHA_LEN 32
#define MCUMGR_UPLOAD_INIT_HEADER_BUF_SIZE 128

static K_SEM_DEFINE(mcumgr_fs_client_grp_sem, 0, 1);
static K_MUTEX_DEFINE(mcumgr_fs_client_grp_mutex);

/* Pointer for active Client */
static struct img_mgmt_client *active_client;

static struct mcumgr_file_upload *file_upload_buf;

static size_t upload_message_header_size(struct fs_mgmt_file_data *upload_state)
{
    bool ok;
    size_t cbor_length;
    int map_count;
    zcbor_state_t zse[CONFIG_MCUMGR_SMP_CBOR_MAX_DECODING_LEVELS + 2];
    uint8_t temp_buf[MCUMGR_UPLOAD_INIT_HEADER_BUF_SIZE];
    uint8_t temp_data;

    zcbor_new_encode_state(zse, ARRAY_SIZE(zse), temp_buf, MCUMGR_UPLOAD_INIT_HEADER_BUF_SIZE, 0);

    if (upload_state->hash_initialized) {
        map_count = 6; 
    } else {
        map_count = 4; 
    }

    ok = zcbor_map_start_encode(zse, map_count) &&
         zcbor_tstr_put_lit(zse, "name") &&
         zcbor_tstr_put_term(zse, upload_state->filename) &&
         zcbor_tstr_put_lit(zse, "data") &&
         zcbor_bstr_encode_ptr(zse, &temp_data, 1) &&
         zcbor_tstr_put_lit(zse, "off") &&
         zcbor_size_put(zse, upload_state->offset);

    if (ok && upload_state->hash_initialized) {
        ok = zcbor_tstr_put_lit(zse, "sha") &&
             zcbor_bstr_encode_ptr(zse, upload_state->sha256, FILE_MGMT_DATA_SHA_LEN);
    }

    if (ok) {
        ok = zcbor_map_end_encode(zse, map_count);
    }

    if (!ok) {
        LOG_ERR("Failed to encode file upload packet header");
        return 0;
    }

    cbor_length = zse->payload - temp_buf;

    return cbor_length + (CONFIG_MCUMGR_GRP_FILE_UPLOAD_DATA_ALIGNMENT_SIZE - 1);
}


void fs_mgmt_client_init(struct fs_mgmt_client *client, 
                         struct smp_client_object *smp_client)
{
    client->smp_client = smp_client;
    client->status = MGMT_ERR_EOK;
}

int fs_mgmt_client_upload_init(struct fs_mgmt_client *client, size_t file_size,
                                uint32_t file_num, const char *file_hash)
{
    int rc;

    k_mutex_lock(&mcumgr_fs_client_grp_mutex, K_FOREVER);

    client->file_data.file_size = file_size;
    client->file_data.offset = 0;
    client->file_data.file_num = file_num;

    if (file_hash) {
        memcpy(client->file_data.sha256, file_hash, 32);
        client->file_data.hash_initialized = true;
    } else {
        client->file_data.hash_initialized = false;
    }

    client->file_data.upload_header_size = upload_message_header_size(&client->file_data);
    if (client->file_data.upload_header_size > 0) {
        rc = MGMT_ERR_EOK; 
    } else {
        rc = MGMT_ERR_ENOMEM;
    }
    k_mutex_unlock(&mcumgr_fs_client_grp_mutex);
    return rc;
}


int file_mgmt_client_upload(struct fs_mgmt_client *client, const char *filename, 
                            const uint8_t *data, size_t length, 
                            struct mcumgr_file_upload *res_buf)
{
    struct net_buf *nb;
    const uint8_t *write_ptr;
    int rc;
    uint32_t map_count;
    bool ok;
    size_t write_length, max_data_length, offset_before_send, request_length, wrote_length;
    zcbor_state_t zse[CONFIG_MCUMGR_SMP_CBOR_MAX_DECODING_LEVELS + 2];

    k_mutex_lock(&mcumgr_fs_client_grp_mutex, K_FOREVER);
    active_client = client;
    file_upload_buf = res_buf;

    request_length = length;
    wrote_length = 0;

    max_data_length = CONFIG_MCUMGR_TRANSPORT_NETBUF_SIZE - 
                      (active_client->upload.upload_header_size + MGMT_HDR_SIZE + 2U + 2U);

    if (max_data_length % CONFIG_MCUMGR_GRP_FILE_UPLOAD_DATA_ALIGNMENT_SIZE) {
        max_data_length -= (max_data_length % CONFIG_MCUMGR_GRP_FILE_UPLOAD_DATA_ALIGNMENT_SIZE);
    }

    while (request_length != wrote_length) {
        write_ptr = data + wrote_length;
        write_length = request_length - wrote_length;
        if (write_length > max_data_length) {
            write_length = max_data_length;
        }

        nb = smp_client_buf_allocation(active_client->smp_client, MGMT_GROUP_ID_FS, 
                                       FS_MGMT_ID_FILE, MGMT_OP_WRITE, 
                                       SMP_MCUMGR_VERSION_1);
        if (!nb) {
            file_upload_buf->status = MGMT_ERR_ENOMEM;
            goto end;
        }

        zcbor_new_encode_state(zse, ARRAY_SIZE(zse), nb->data + nb->len, net_buf_tailroom(nb), 0);

        if (wrote_length == 0) {
            map_count = 5;
        } else {
            map_count = 4;
        }

        ok = zcbor_map_start_encode(zse, map_count) &&
             zcbor_tstr_put_lit(zse, "name") && zcbor_tstr_put_lit(zse, filename) &&
             zcbor_tstr_put_lit(zse, "data") &&
             zcbor_bstr_encode_ptr(zse, write_ptr, write_length) &&
             zcbor_tstr_put_lit(zse, "off") &&
             zcbor_size_put(zse, wrote_length);

        if (ok && wrote_length == 0) {
            ok = zcbor_tstr_put_lit(zse, "len") &&
                 zcbor_size_put(zse, length);
        }

        if (ok) {
            ok = zcbor_map_end_encode(zse, map_count);
        }

        if (!ok) {
            LOG_ERR("Failed to encode File Upload packet");
            smp_packet_free(nb);
            file_upload_buf->status = MGMT_ERR_ENOMEM;
            goto end;
        }

        offset_before_send = wrote_length;
        nb->len = zse->payload - nb->data;
        k_sem_reset(&mcumgr_fs_client_grp_sem);

        file_upload_buf->status = MGMT_ERR_EINVAL;
        file_upload_buf->file_upload_offset = SIZE_MAX;

        rc = smp_client_send_cmd(active_client->smp_client, nb, file_upload_res_fn, 
                                 &mcumgr_fs_client_grp_sem, 
                                 CONFIG_MCUMGR_GRP_FILE_FLASH_OPERATION_TIMEOUT);
        if (rc) {
            LOG_ERR("Failed to send SMP Upload packet, err: %d", rc);
            smp_packet_free(nb);
            file_upload_buf->status = rc;
            goto end;
        }

        k_sem_take(&mcumgr_fs_client_grp_sem, K_FOREVER);
        if (file_upload_buf->status) {
            LOG_ERR("Upload Fail: %d", file_upload_buf->status);
            goto end;
        }

        if (offset_before_send + write_length < wrote_length) {
            LOG_ERR("Unexpected offset returned");
            goto end;
        }

        wrote_length += write_length;
    }

end:
    rc = file_upload_buf->status;
    active_client = NULL;
    file_upload_buf = NULL;
    k_mutex_unlock(&mcumgr_fs_client_grp_mutex);

    return rc;
}


