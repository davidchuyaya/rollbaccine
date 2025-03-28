#include <crypto/aead.h>
#include <crypto/skcipher.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#define ROLLBACCINE_ENCRYPTION_GRANULARITY PAGE_SIZE
#define ROLLBACCINE_SECTORS_PER_ENCRYPTION (ROLLBACCINE_ENCRYPTION_GRANULARITY / SECTOR_SIZE)
#define ROLLBACCINE_MAX_BROADCAST_QUEUE_SIZE 1000000
#define SECTORS_PER_PAGE (PAGE_SIZE / SECTOR_SIZE)
#define AES_GCM_IV_SIZE 12
#define AES_GCM_AUTH_SIZE 16
#define AES_GCM_INTEGRITY_SIZE (AES_GCM_IV_SIZE + AES_GCM_AUTH_SIZE)
#define AES_GCM_INTEGRITY_PER_PAGE (PAGE_SIZE / AES_GCM_INTEGRITY_SIZE)
#define KEY_SIZE 16
#define SHA256_SIZE 32
#define DM_MSG_PREFIX "merkle"

#define MEMORY_TRACKING

struct merkle_device {
    struct dm_dev *dev;
    struct bio_set bs;

    uint64_t integrity_cache_num_pages;
    sector_t num_sectors;
    int tree_height; // Number of layers in merkle tree, including the layer in memory

    struct crypto_aead *tfm;
    char* checksums; // Layer "0" of the merkle tree
    struct mutex merkle_tree_lock;
    struct rb_root *merkle_tree_layers;  // Note: [0] = NULL always, since that layer is represented by checksums
    int *pages_per_merkle_tree_layer; // Note: [0] = 0 always, since that layer is in memory & its size shouldn't be factored in

    // Metrics
    int num_pending_checksum_ops;
    int max_pending_checksum_list_size;
};

struct pending_checksum_list {
    int layer;
    int parent_page_num;
    struct list_head ops;
    struct rb_node tree_node;
};

struct pending_checksum_op {
    int parent_page_num;
    int parent_page_offset;
    int checksum_offset; // Start reading the bio_data's checksum from this offset
    struct bio_data *bio_data;
    struct list_head list;
};

struct bio_data {
    struct merkle_device *device;
    struct bio *bio_src;
    struct bio *deep_clone;
    struct bio *shallow_clone;
    atomic_t ref_counter;  // The number of clones AND number of pending_checksum_ops with references to this bio. Once it hits 0, the bio can be freed
    bool is_write;
    sector_t start_sector;
    sector_t end_sector;
    int layer; // Layer in the merkle tree. Layer = tree_height if this is a data read/write
    struct pending_checksum_list *pending_checksum_list; // Any pending checksum operatons for this bio, in case it contains hashes that are to be verified/changed

    struct mutex checksum_lock; // Either this bio or its parent (containing the hash) completes last. The last one to complete should update the checksum fields under a lock, then verify and end_io
    unsigned char *expected_checksum_and_iv; // If this is a read and the parent completed first, this will be populated
    unsigned char *checksum_and_iv;
};

enum EncDecType { ROLLBACCINE_ENCRYPT, ROLLBACCINE_DECRYPT };

int __init dm_merkle_init(void);
void dm_merkle_exit(void);

int calc_tree_height(uint64_t integrity_cache_num_pages, sector_t num_sectors) {
    int smallest_layer_pages, i;
    int height = 0;
    int total_integrity_pages = num_sectors * ROLLBACCINE_SECTORS_PER_ENCRYPTION * AES_GCM_INTEGRITY_SIZE / AES_GCM_INTEGRITY_PER_PAGE;

    do {
        smallest_layer_pages = total_integrity_pages;
        for (i = 0; i < height; i++) {
            // Calculate the size of the smallest Merkle tree hash layer
            // Round layer size up so we have enough space
            smallest_layer_pages = (smallest_layer_pages + AES_GCM_INTEGRITY_PER_PAGE - 1) / AES_GCM_INTEGRITY_PER_PAGE;
        }

        height++;
    } while (smallest_layer_pages > integrity_cache_num_pages);

    printk(KERN_INFO "num_sectors: %d, total integrity pages: %d, integrity cache num pages: %llu, height: %d", num_sectors, total_integrity_pages, integrity_cache_num_pages, height);

    return height;
}

void write_hash_end_io(struct bio *bio) {
    struct bio_data *bio_data = bio->bi_private;
    struct merkle_device *device = bio_data->device;
    struct pending_checksum_list *pending_checksum_list = bio_data->pending_checksum_list;

    // TODO: Any locking in end_io must be a task
    mutex_lock(&device->merkle_tree_lock);
    if (list_empty(&pending_checksum_list->ops)) {
        // Remove from pending ops tree
        rb_erase(&pending_checksum_list->tree_node, &device->merkle_tree_layers[pending_checksum_list->layer]);
    }
    else {
        // If there are still pending operations for this page, we need to reissue the read
        bio_reset(bio, device->dev->bdev, REQ_OP_READ);
        bio->bi_end_io = read_hash_end_io;
        submit_bio_noacct(bio);
    }
    mutex_unlock(&device->merkle_tree_lock);
}

void read_hash_end_io(struct bio *bio) {
    struct bio_data *bio_data = bio->bi_private;
    struct merkle_device *device = bio_data->device;
    struct pending_checksum_list *pending_checksum_list = bio_data->pending_checksum_list;
    struct pending_checksum_op *pending_checksum_op, *next_pending_checksum_op;
    struct bio_data *pending_bio_data;
    bool encrypt_error;
    bool dirtied = false;
    struct page *page = bio_page(bio);
    void *page_addr = kmap(page);

    // Execute any pending checksum operations
    mutex_lock(&device->merkle_tree_lock);
    list_for_each_entry_safe(pending_checksum_op, next_pending_checksum_op, &pending_checksum_list->ops, list) {
        pending_bio_data = pending_checksum_op->bio_data;
        if (pending_bio_data->is_write) {
            // Write to the parent (the page read)
            memcpy(pending_bio_data->checksum_and_iv + pending_checksum_op->checksum_offset, page_addr + pending_checksum_op->parent_page_offset, AES_GCM_INTEGRITY_SIZE);
            dirtied = true;

            try_free_bio(pending_bio_data);

            list_del(&pending_checksum_op->list);
            kfree(pending_checksum_op);
        }
        else {
            // TODO: Read from the page
        }
    }
    if (!dirtied) {
        // Remove from pending ops tree
        // Note: We don't remove if the page is dirtied, because we want to prevent the next read from happening until the dirtied page makes it to disk, so the pending ops structures should remain
        rb_erase(&pending_checksum_list->tree_node, &device->merkle_tree_layers[pending_checksum_list->layer]);
    }
    mutex_unlock(&device->merkle_tree_lock);

    kunmap(page);

    // Add to this page's parent's pending ops, then write this bio to disk
    if (dirtied) {
        // Encrypt
        bio_data->checksum_and_iv = enc_or_dec_bio(bio_data, ROLLBACCINE_ENCRYPT, &encrypt_error);
        if (encrypt_error) {
            printk_ratelimited(KERN_ERR "Error encrypting hash %llu", bio_data->start_sector);
            return;
        }
        // Queue this write to the parent and fetch the parents
        fetch_parent_hashes(device, bio_data);
        
        bio_reset(bio, device->dev->bdev, REQ_OP_WRITE);
        bio->bi_end_io = write_hash_end_io;
        submit_bio_noacct(bio);
    }
    else {
        // Decrement ref count
        try_free_bio(bio_data);
    }
}

struct bio_data *create_parent_bio(struct merkle_device *device, struct pending_checksum_list *pending_checksum_list) {
    struct bio_data *bio_data;
    struct page *page;
    struct bio *bio = bio_alloc_bioset(device->dev->bdev, 1, REQ_OP_READ, GFP_NOIO, &device->bs);
    bio->bi_iter.bi_sector = pending_checksum_list->parent_page_num * SECTORS_PER_PAGE;

    page = alloc_page(GFP_KERNEL);
    if (!page) {
        printk(KERN_ERR "Could not allocate page");
        return NULL;
    }
    _bio_add_page(bio, page, PAGE_SIZE, 0);
    bio->bi_end_io = read_hash_end_io;

    bio_data = alloc_bio_data(device);
    bio_data->device = device;
    bio_data->bio_src = bio;
    bio_data->deep_clone = bio; // Set deep_clone (since that's what encrypt modifies), but don't need to actually clone it
    bio_data->start_sector = bio->bi_iter.bi_sector;
    bio_data->end_sector = bio_data->start_sector + SECTORS_PER_PAGE;
    bio_data->layer = pending_checksum_list->layer;
    bio_data->pending_checksum_list = pending_checksum_list;
    atomic_set(&bio_data->ref_counter, 1);
    bio->bi_private = bio_data;

    return bio_data;
}

struct bio_data *add_pending_checksum_op(struct merkle_device *device, int layer, struct pending_checksum_op *pending_checksum_op) {
    struct rb_node **other_tree_node_location = &(device->merkle_tree_layers[layer].rb_node);
    struct rb_node *other_tree_node = NULL;
    struct pending_checksum_list *other_pending_checksum_list;

    // See if we conflict with any outstanding operations
    while (*other_tree_node_location != NULL) {
        other_pending_checksum_list = container_of(*other_tree_node_location, struct pending_checksum_list, tree_node);
        other_tree_node = *other_tree_node_location;

        if (pending_checksum_op->parent_page_num < other_pending_checksum_list->parent_page_num)
            other_tree_node_location = &other_tree_node->rb_left;
        else if (pending_checksum_op->parent_page_num > other_pending_checksum_list->parent_page_num)
            other_tree_node_location = &other_tree_node->rb_right;
        else {
            // Exists pending list, insert
            list_add_tail(&pending_checksum_op->list, &other_pending_checksum_list->ops);
            return NULL;
        }
    }

    // No conflicts, init a new pending_checksum_list for this parent page, add this pending op to that list
    other_pending_checksum_list = kmalloc(sizeof(struct pending_checksum_list), GFP_KERNEL);
    other_pending_checksum_list->layer = layer;
    other_pending_checksum_list->parent_page_num = pending_checksum_op->parent_page_num;
    INIT_LIST_HEAD(&other_pending_checksum_list->ops);
    list_add_tail(&pending_checksum_op->list, &other_pending_checksum_list->ops);

    // Insert into rb tree with other_tree_node as the parent at root
    rb_link_node(&other_pending_checksum_list->tree_node, other_tree_node, other_tree_node_location);
    rb_insert_color(&other_pending_checksum_list->tree_node, &device->merkle_tree_layers[layer]);

    return create_parent_bio(device, other_pending_checksum_list);
}

void recursive_fetch_parent_hashes(struct merkle_device *device, struct bio_data *bio_data, struct bio_data **parent_bio_datas, int *num_parent_bios) {
    struct bio *bio = bio_data->bio_src;
    struct bio_data **parent_bio_datas;
    struct bio_data *parent_bio_data;
    struct pending_checksum_op *pending_checksum_op;
    int num_merkle_tree_pages, curr_sector, curr_page, num_pages, i, checksum_offset;

    if (bio_data->layer == 1) {
        // TODO: Verify
        return;
    }

    // Calculate the number of pages in the Merkle tree layers above this one
    for (i = 0; i < bio_data->layer; i++) {
        num_merkle_tree_pages += device->pages_per_merkle_tree_layer[i];
    }

    while (bio->bi_iter.bi_size) {
        curr_sector = bio->bi_iter.bi_sector;
        curr_page = curr_sector / SECTORS_PER_PAGE - num_merkle_tree_pages;

        pending_checksum_op = kmalloc(sizeof(struct pending_checksum_op), GFP_KERNEL);
        pending_checksum_op->parent_page_num = curr_page / AES_GCM_INTEGRITY_PER_PAGE;
        pending_checksum_op->parent_page_offset = curr_page % AES_GCM_INTEGRITY_PER_PAGE;
        pending_checksum_op->checksum_offset = checksum_offset;
        pending_checksum_op->bio_data = bio_data;
        atomic_inc(&bio_data->ref_counter);
        
        // Add to pending ops, check if the parent's parent also needs to be fetched
        parent_bio_data = add_pending_checksum_op(device, bio_data->layer - 1, pending_checksum_op);
        if (parent_bio_data != NULL) {
            parent_bio_datas[*num_parent_bios] = parent_bio_data;
            *num_parent_bios++;

            if (!bio_data->is_write) {
                recursive_fetch_parent_hashes(device, parent_bio_data, parent_bio_datas, num_parent_bios);
            }
        }

        bio_advance_iter(bio, &bio->bi_iter, ROLLBACCINE_ENCRYPTION_GRANULARITY);
        checksum_offset += AES_GCM_INTEGRITY_SIZE;
    }

    // Reset bio to start after iterating
    bio->bi_iter.bi_sector = bio_data->start_sector;
    bio->bi_iter.bi_size = (bio_data->end_sector - bio_data->start_sector) * SECTOR_SIZE;
    bio->bi_iter.bi_idx = 0;
}

// Layer is 0 indexed. Layer = tree_height for data read/writes
void fetch_parent_hashes(struct merkle_device *device, struct bio_data *bio_data) {
    int num_pages = bio_sectors(bio_data->bio_src) / SECTORS_PER_PAGE;
    struct bio_data **parent_bio_datas;
    int num_parent_bios = 0;
    int i;

    // TODO: Fast path if layer = 1
    if (bio_data->layer == 1) {

    }

    parent_bio_datas = kmalloc(num_pages * (bio_data->layer - 1) * sizeof(struct bio_data *), GFP_KERNEL);

    mutex_lock(&device->merkle_tree_lock);
    recursive_fetch_parent_hashes(device, bio_data, parent_bio_datas, &num_parent_bios);
    mutex_unlock(&device->merkle_tree_lock);

    // Read all parent bios. Note that we shouldn't read unless the previous write has completed.
    // All parent_bio_datas must have made it to disk, since if the previous write hasn't, then it would exist in the pending_checksums list and this parent bio_data wouldn't have been created
    for (i = 0; i < num_parent_bios; i++) {
        submit_bio_noacct(parent_bio_datas[i]->bio_src);
    }

    kfree(parent_bio_datas);
}

void free_pages_end_io(struct bio *bio) {
    struct bio_data *bio_data = bio->bi_private;
    struct bio_vec bvec;
    struct bvec_iter iter;

    // Free each page. Reset bio to start first, in case it's pointing to the end
    bio->bi_iter.bi_sector = bio_data->start_sector;
    bio->bi_iter.bi_size = (bio_data->end_sector - bio_data->start_sector) * SECTOR_SIZE;
    bio->bi_iter.bi_idx = 0;
    bio_for_each_segment(bvec, bio, iter) {
        __free_page(bvec.bv_page);
    }

    if (bio_data->expected_checksum_and_iv != NULL) {
        kfree(bio_data->expected_checksum_and_iv);
    }
    if (bio_data->checksum_and_iv != NULL) {
        kfree(bio_data->checksum_and_iv);
    }
    kfree(bio_data);

    bio_put(bio);
}

void try_free_bio(struct bio_data *bio_data) {
    if (atomic_dec_and_test(&bio_data->ref_counter)) {
        // printk(KERN_INFO "Freeing clone, write index: %d", deep_clone_bio_data->write_index);
        bio_put(bio_data->shallow_clone);
        free_pages_end_io(bio_data->deep_clone);
    }
}

void ack_bio_to_user_without_executing(struct bio *bio) {
    bio->bi_status = BLK_STS_OK;
    bio_endio(bio);
}

void write_disk_end_io(struct bio *shallow_clone) {
    struct bio_data *bio_data = shallow_clone->bi_private;

    ack_bio_to_user_without_executing(bio_data->bio_src);
    try_free_bio(bio_data);
}

struct bio *shallow_bio_clone(struct merkle_device *device, struct bio *bio_src) {
    struct bio *clone;
    clone = bio_alloc_clone(bio_src->bi_bdev, bio_src, GFP_NOIO, &device->bs);
    if (!clone) {
        printk(KERN_INFO "Could not create clone");
        return NULL;
    }

    clone->bi_iter.bi_sector = bio_src->bi_iter.bi_sector;
    return clone;
}

static int merkle_map(struct dm_target *ti, struct bio *bio) {
    struct merkle_device *device = ti->private;
    struct bio_data *bio_data;
    bool encrypt_error;

    bio_set_dev(bio, device->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    bio_data = kmalloc(sizeof(struct bio_data), GFP_KERNEL);
    bio_data->device = device;
    bio_data->bio_src = bio;
    bio_data->start_sector = bio->bi_iter.bi_sector;
    bio_data->end_sector = bio->bi_iter.bi_sector + bio_sectors(bio);
    bio_data->is_write = bio_data_dir(bio) == WRITE;
    bio_data->layer = device->tree_height;

    switch (bio_data_dir(bio)) {
        case WRITE:
            // Deep clone for encryption, otherwise we may overwrite buffers from the user and can cause a crash
            bio_data->deep_clone = deep_bio_clone(device, bio);
            if (!bio_data->deep_clone) {
                printk(KERN_ERR "Could not create deep clone");
                return DM_MAPIO_REMAPPED;
            }

            // Encrypt
            bio_data->checksum_and_iv = enc_or_dec_bio(bio_data, ROLLBACCINE_ENCRYPT, &encrypt_error);
            if (encrypt_error) {
                printk_ratelimited(KERN_ERR "Error encrypting bio %llu", bio_data->start_sector);
                return DM_MAPIO_REMAPPED;
            }

            // Create the disk clone. Necessary because we change the bi_end_io function, so we can't submit the original.
            bio_data->shallow_clone = shallow_bio_clone(device, bio_data->deep_clone);
            if (!bio_data->shallow_clone) {
                printk(KERN_ERR "Could not create shallow clone");
                return DM_MAPIO_REMAPPED;
            }
            bio_data->shallow_clone->bi_end_io = write_disk_end_io;

            // Set shared data between clones
            atomic_set(&bio_data->ref_counter, 2);
            bio_data->deep_clone->bi_private = bio_data;
            bio_data->shallow_clone->bi_private = bio_data;

            // Request merkle tree parent pages from disk
            fetch_parent_hashes(device, bio_data);

            submit_bio_noacct(bio_data->shallow_clone);
            break;
        case READ:
            break;
    }

    return DM_MAPIO_REMAPPED;
}

inline size_t bio_checksum_and_iv_size(int num_sectors) { return num_sectors / ROLLBACCINE_SECTORS_PER_ENCRYPTION * AES_GCM_INTEGRITY_SIZE; }

inline unsigned char *alloc_bio_checksum_and_iv(int num_sectors) {
    if (num_sectors != 0) {
        return kmalloc(bio_checksum_and_iv_size(num_sectors), GFP_KERNEL);
    } else {
        return NULL;
    }
}

inline unsigned char *get_bio_checksum(unsigned char *checksum_and_iv, sector_t start_sector, sector_t current_sector) {
    return checksum_and_iv + (current_sector - start_sector) / ROLLBACCINE_SECTORS_PER_ENCRYPTION * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE);
}

inline unsigned char *get_bio_iv(unsigned char *checksum_and_iv, sector_t start_sector, sector_t current_sector) {
    return checksum_and_iv + (current_sector - start_sector) / ROLLBACCINE_SECTORS_PER_ENCRYPTION * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE) + AES_GCM_AUTH_SIZE;
}

unsigned char *enc_or_dec_bio(struct bio_data *bio_data, enum EncDecType enc_or_dec, bool *error) {
    int ret = 0;
    struct bio *bio;
    struct bio_vec bv;
    uint64_t curr_sector;
    struct aead_request *req;
    struct scatterlist sg[4];
    struct page *page_verify;
    DECLARE_CRYPTO_WAIT(wait);
    unsigned char *bio_checksum_and_iv;
    unsigned char *iv;
    unsigned char *checksum;
    *error = false;

    if (bio_data->end_sector == bio_data->start_sector) {
        // printk(KERN_INFO "Skipping encryption/decryption for empty bio");
        return NULL;
    }

    switch (enc_or_dec) {
        case ROLLBACCINE_ENCRYPT:
            // Operate on the deep clone, since otherwise we may overwrite buffers from the user and can cause a crash
            bio = bio_data->deep_clone;
            // Store new checksum and IV of write into array (instead of updating global checksum/iv) so the global checksum/iv can be updated in-order later
            bio_checksum_and_iv = alloc_bio_checksum_and_iv(bio_sectors(bio));
            if (!bio_checksum_and_iv) {
                printk(KERN_ERR "Could not allocate checksum and iv for bio");
                goto free_and_return;
            }
            break;
        case ROLLBACCINE_DECRYPT:
            bio = bio_data->bio_src;
            // Assume checksum and IVs were already read into bio_data
            bio_checksum_and_iv = bio_data->checksum_and_iv;
            break;
    }

    while (bio->bi_iter.bi_size) {
        // printk(KERN_INFO "enc/dec starting");
        curr_sector = bio->bi_iter.bi_sector;
        bv = bio_iter_iovec(bio, bio->bi_iter);

        checksum = get_bio_checksum(bio_checksum_and_iv, bio_data->start_sector, curr_sector);
        iv = get_bio_iv(bio_checksum_and_iv, bio_data->start_sector, curr_sector);

        switch (enc_or_dec) {
            case ROLLBACCINE_ENCRYPT:
                get_random_bytes(iv, AES_GCM_IV_SIZE);
                break;
        }

        // Lazily allocate the AEAD request, because a lot of reads are over blocks that have not been written to (so they will not pass !has_checksum and won't need to alloc)
        if (req == NULL) {
            req = aead_request_alloc(bio_data->device->tfm, GFP_KERNEL);
            if (!req) {
                printk(KERN_ERR "aead request allocation failed");
                return NULL;
            }
        }

        // Set up scatterlist to encrypt/decrypt
        sg_init_table(sg, 4);
        sg_set_buf(&sg[0], &curr_sector, sizeof(uint64_t));
        sg_set_buf(&sg[1], iv, AES_GCM_IV_SIZE);
        sg_set_page(&sg[2], bv.bv_page, ROLLBACCINE_ENCRYPTION_GRANULARITY, bv.bv_offset);
        sg_set_buf(&sg[3], checksum, AES_GCM_AUTH_SIZE);

        // /* AEAD request:
        //  *  |----- AAD -------|------ DATA -------|-- AUTH TAG --|
        //  *  | (authenticated) | (auth+encryption) |              |
        //  *  | sector_LE |  IV |  sector in/out    |  tag in/out  |
        //  */
        aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
        // sector + iv size
        aead_request_set_ad(req, sizeof(uint64_t) + AES_GCM_IV_SIZE);
        switch (enc_or_dec) {
            case ROLLBACCINE_ENCRYPT:
                aead_request_set_crypt(req, sg, sg, ROLLBACCINE_ENCRYPTION_GRANULARITY, iv);
                ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
                break;
            case ROLLBACCINE_DECRYPT:
                aead_request_set_crypt(req, sg, sg, ROLLBACCINE_ENCRYPTION_GRANULARITY + AES_GCM_AUTH_SIZE, iv);
                ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
                break;
        }

        if (ret) {
            if (ret == -EBADMSG) {
                printk_ratelimited(KERN_ERR "invalid integrity check");
            } else {
                printk_ratelimited(KERN_ERR "encryption/decryption failed with error code %d", ret);
            }
            *error = true;
            goto free_and_return;
        }

    enc_or_dec_next_sector:
        bio_advance_iter(bio, &bio->bi_iter, ROLLBACCINE_ENCRYPTION_GRANULARITY);
        reinit_completion(&wait.completion);
    }

free_and_return:
    aead_request_free(req);
    // Reset bio to start after iterating for encryption
    bio->bi_iter.bi_sector = bio_data->start_sector;
    bio->bi_iter.bi_size = (bio_data->end_sector - bio_data->start_sector) * SECTOR_SIZE;
    bio->bi_iter.bi_idx = 0;
    return bio_checksum_and_iv;  // NOTE: This will be NULL for reads
}

static int merkle_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    int i;

    printk(KERN_INFO "merkle constructor called\n");

    struct merkle_device *device = kmalloc(sizeof(struct merkle_device), GFP_KERNEL);
    if (device == NULL) {
        ti->error = "Cannot allocate context";
        return -ENOMEM;
    }

    bioset_init(&device->bs, 0, 0, BIOSET_NEED_BVECS);

    // Get the device from argv[0] and store it in device->dev
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &device->dev)) {
        ti->error = "Device lookup failed";
        kfree(device);
        return -EINVAL;
    }

    device->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(device->tfm)) {
        printk(KERN_ERR "Error allocating AEAD");
        return PTR_ERR(device->tfm);
    }
    crypto_aead_setauthsize(device->tfm, AES_GCM_AUTH_SIZE);

    ti->error = crypto_aead_setkey(device->tfm, "abcdefghijklmnop", KEY_SIZE);
    if (ti->error < 0) {
        printk(KERN_ERR "Error setting key");
        return ti->error;
    }

    ti->error = kstrtou64(argv[1], 10, &device->integrity_cache_num_pages);
    if (ti->error < 0) {
        printk(KERN_ERR "Error parsing integrity cache size");
        return ti->error;
    }
    device->checksums = vzalloc(device->integrity_cache_num_pages * PAGE_SIZE);

    device->num_sectors = ti->len;
    device->tree_height = calc_tree_height(device->integrity_cache_num_pages, device->num_sectors);

    device->merkle_tree_layers = kmalloc(device->tree_height * sizeof(struct rb_root), GFP_KERNEL);
    for (i = 0; i < device->tree_height; i++) {
        device->merkle_tree_layers[i] = RB_ROOT;
    }

    ti->private = device;

    return 0;
}

static void merkle_destructor(struct dm_target *ti) {
    printk(KERN_INFO "merkle destructor called\n");

    struct merkle_device *device = ti->private;
    dm_put_device(ti, device->dev);
    kfree(device);
}

static struct target_type merkle_target = {
    .name = "merkle",
    .version = {0, 1, 0},
    .module = THIS_MODULE,
    .ctr = merkle_constructor,
    .dtr = merkle_destructor,
    .map = merkle_map,
};

int __init dm_merkle_init(void) {
    int r = dm_register_target(&merkle_target);
    printk(KERN_INFO "merkle module loaded\n");

    if (r < 0) DMERR("register failed %d", r);

    return r;
}

void dm_merkle_exit(void) {
    dm_unregister_target(&merkle_target);
    printk(KERN_INFO "merkle module unloaded\n");
}

module_init(dm_merkle_init);
module_exit(dm_merkle_exit);

MODULE_LICENSE("GPL");
