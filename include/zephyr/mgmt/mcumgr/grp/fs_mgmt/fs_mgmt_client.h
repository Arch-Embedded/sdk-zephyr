#ifndef H_FS_MGMT_CLIENT_
#define H_FS_MGMT_CLIENT_

#include <inttypes.h>
#include <zephyr/mgmt/mcumgr/grp/fs_mgmt/fs_mgmt.h>
#include <zephyr/mgmt/mcumgr/smp/smp_client.h>


struct mcumgr_file_upload {
    enum mcumgr_err_t status;
    size_t file_upload_offset;
};

struct fs_gr_upload {
    uint32_t file_num;       
    size_t file_size;       
    size_t offset;  
    size_t upload_header_size;         
    uint8_t sha256[32];      
    bool hash_initialized;  
    const char *filename; 
};

struct fs_mgmt_client {
    struct smp_client_object *smp_client;  
	struct fs_gr_upload upload;           
	int status;              
};

//int file_upload_res_fn(struct net_buf *nb, void *user_data);

void fs_mgmt_client_init(struct fs_mgmt_client *client,
                         struct smp_client_object *smp_client);


int fs_mgmt_client_upload_init(struct fs_mgmt_client *client,
                               size_t file_size,
                               uint32_t file_num,
                               const char *filename,
                               const char *file_hash);


int fs_mgmt_client_upload(struct fs_mgmt_client *client,
                            const char *filename,
                            const uint8_t *data,
                            size_t length,
                            struct mcumgr_file_upload *res_buf);

#endif /* H_FS_MGMT_CLIENT_ */
