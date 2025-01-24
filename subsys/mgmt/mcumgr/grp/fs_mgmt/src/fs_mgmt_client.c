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
static struct fs_mgmt_client *active_client;

static struct mcumgr_file_upload *file_upload_buf;

static int file_upload_res_fn(struct net_buf *nb, void *user_data)
{
	zcbor_state_t zsd[CONFIG_MCUMGR_SMP_CBOR_MAX_DECODING_LEVELS + 2];
	size_t decoded;
	int rc;
	int32_t res_rc = MGMT_ERR_EOK;

	struct zcbor_map_decode_key_val upload_res_decode[] = {
		ZCBOR_MAP_DECODE_KEY_DECODER("off", zcbor_size_decode,
					     &file_upload_buf->file_upload_offset),
		ZCBOR_MAP_DECODE_KEY_DECODER("rc", zcbor_int32_decode, &res_rc)};

	if (!nb) {
		file_upload_buf->status = MGMT_ERR_ETIMEOUT;
		goto end;
	}

	zcbor_new_decode_state(zsd, ARRAY_SIZE(zsd), nb->data, nb->len, 1, NULL, 0);

	rc = zcbor_map_decode_bulk(zsd, upload_res_decode, ARRAY_SIZE(upload_res_decode), &decoded);
	if (rc || file_upload_buf->file_upload_offset == SIZE_MAX) {
		file_upload_buf->status = MGMT_ERR_EINVAL;
		goto end;
	}
	file_upload_buf->status = res_rc;

	active_client->upload.offset = file_upload_buf->file_upload_offset;
end:
	/* Set status for Upload request handler */
	rc = file_upload_buf->status;
	k_sem_give(user_data);
	return rc;
}

static size_t file_upload_message_header_size(struct fs_gr_upload *upload_state)
{
    bool ok;
    size_t cbor_length;
    int map_count;
    zcbor_state_t zse[CONFIG_MCUMGR_SMP_CBOR_MAX_DECODING_LEVELS + 2];
    uint8_t temp_buf[MCUMGR_UPLOAD_INIT_HEADER_BUF_SIZE];
    uint8_t temp_data;

    zcbor_new_encode_state(zse, ARRAY_SIZE(zse), temp_buf, MCUMGR_UPLOAD_INIT_HEADER_BUF_SIZE, 0);

    if (upload_state->hash_initialized) {
        map_count = 7; 
    } else {
        map_count = 5; 
    }

    ok = zcbor_map_start_encode(zse, map_count) &&
         zcbor_tstr_put_lit(zse, "name") &&
         zcbor_tstr_put_lit(zse, upload_state->filename) &&
         zcbor_tstr_put_lit(zse, "data") &&
         zcbor_bstr_encode_ptr(zse, &temp_data, 1) &&
         zcbor_tstr_put_lit(zse, "off") &&
         zcbor_size_put(zse, upload_state->offset) &&
         zcbor_tstr_put_lit(zse, "len") &&  
         zcbor_size_put(zse, upload_state->file_size);

    if (ok) {
        ok = zcbor_map_end_encode(zse, map_count);
    }

    if (!ok) {
        printk("Failed to encode file upload packet header");
        return 0;
    }

    cbor_length = zse->payload - temp_buf;

    size_t alignment_size = 4; 
    return cbor_length + (alignment_size - 1);
}


void fs_mgmt_client_init(struct fs_mgmt_client *client, 
                         struct smp_client_object *smp_client)
{
    client->smp_client = smp_client;
    client->status = MGMT_ERR_EOK;
}

int fs_mgmt_client_upload_init(struct fs_mgmt_client *client, size_t file_size,
                                uint32_t file_num, const char *filename ,const char *file_hash)
{
    int rc;

    k_mutex_lock(&mcumgr_fs_client_grp_mutex, K_FOREVER);

    client->upload.file_size = file_size;
    client->upload.offset = 0;
    client->upload.file_num = file_num;
    client->upload.filename = filename;

    if (file_hash) {
        memcpy(client->upload.sha256, file_hash, 32);
        client->upload.hash_initialized = true;
    } else {
        client->upload.hash_initialized = false;
    }

    client->upload.upload_header_size = file_upload_message_header_size(&client->upload);
    if (client->upload.upload_header_size > 0) {
        rc = MGMT_ERR_EOK; 
    } else {
        rc = MGMT_ERR_ENOMEM;
    }
    k_mutex_unlock(&mcumgr_fs_client_grp_mutex);
    return rc;
}


int fs_mgmt_client_upload(struct fs_mgmt_client *client, const char *filename, 
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

    if (max_data_length % 4) {
        max_data_length -= (max_data_length % 4);
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
            printk("Failed to encode File Upload packet");
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
                                 15);
        if (rc) {
            printk("Failed to send SMP Upload packet, err: %d", rc);
            smp_packet_free(nb);
            file_upload_buf->status = rc;
            goto end;
        }

        k_sem_take(&mcumgr_fs_client_grp_sem, K_FOREVER);
        if (file_upload_buf->status) {
            printk("Upload Fail: %d", file_upload_buf->status);
            goto end;
        }

        if (offset_before_send + write_length < active_client->upload.offset) {
            printk("Unexpected offset returned");
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


