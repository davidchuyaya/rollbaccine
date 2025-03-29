#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/internal/hash.h> /* SHA-256 Hash*/
#include <crypto/skcipher.h>
#include <linux/bio.h>
#include <linux/crypto.h>
#include <linux/device-mapper.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/scatterlist.h>

#define ROLLBACCINE_ENCRYPTION_GRANULARITY PAGE_SIZE
#define ROLLBACCINE_SECTORS_PER_ENCRYPTION (ROLLBACCINE_ENCRYPTION_GRANULARITY / SECTOR_SIZE)
#define ROLLBACCINE_MAX_BROADCAST_QUEUE_SIZE 1000000
#define SECTORS_PER_PAGE (PAGE_SIZE / SECTOR_SIZE)
#define AES_GCM_IV_SIZE 12
#define AES_GCM_AUTH_SIZE 16
#define AES_GCM_INTEGRITY_SIZE (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE)
#define AES_GCM_PER_PAGE (PAGE_SIZE / AES_GCM_INTEGRITY_SIZE)
#define KEY_SIZE 16
#define SHA256_SIZE 32
#define DM_MSG_PREFIX "merkle"

#define MEMORY_TRACKING

/**
 * Merkle tree:
 * merkle_tree_layers contains a list (layers) of tree roots
 * Each tree root is a merkle_bio_data
 * merkle_bio_data can be a LEAF or a NODE
 * LEAFs contain a tree root (pending_data_ops), containing read/write pending_checksum_ops. If it's a write, it contains just the checksum; if it's a read, it contains the read_bio that is blocking
 * NODEs contain a list of merkle_bio_data (pending_merkle_children) that are the children of this node. The checksum is the hash of the children
 * 
 * Verification:
 * A merkle_bio_data is verified if its parent is a merkle_tree_root (or is verified), and its hash matches what is stored on the parent.
 * Once it is verified, it can verify reads and process writes from its children.
 * A read that has been verified can return.
 * 
 * Eviction:
 * LEAFs that have processed all children can evict itself (by writing back to disk if it has been dirtied) and writing its new hash to its parent.
 * Once a LEAF is evicted, it can attempt to evict its parent NODE, which can be evicted if it has no further pending_merkle_children, which propagates up the merkle tree.
 */
struct merkle_device {
    struct dm_dev *dev;
    struct bio_set bs;
    sector_t num_sectors;

    struct crypto_aead *tfm;
    struct crypto_shash *insecure_hash_alg;
    struct mutex hash_lock;
    struct shash_desc *hash_desc;

    int merkle_tree_height;        // Number of layers in merkle tree, including the layer in memory
    int merkle_tree_num_pages; // Total number of pages in merkle tree (on disk)
    int *pages_above_merkle_tree_layer;  // Note: [0] = 0 since there is no layer above the root, and [1] = 0 since the root is in memory

    char *merkle_tree_root;  // Layer "0" of the merkle tree
    struct mutex merkle_tree_lock;
    struct rb_root *merkle_tree_layers;  // Note: [0] = NULL always, since that layer is represented by merkle_tree_root in memory
    
    struct workqueue_struct *read_hash_end_io_queue;
    struct workqueue_struct *write_hash_end_io_queue;
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
    unsigned char *checksum_and_iv; // TODO: Allocate this for reads so the parent can fill it up
};

struct merkle_bio_data {
    struct merkle_device *device;
    struct bio *bio_src;
    int page_num;
    bool verified;
    bool dirtied;
    int layer;
    struct merkle_bio_data *parent;  // Null if the parent is merkle_tree_root
    int parent_page_offset;
    char hash[SHA256_SIZE];      // Read: The hash of this node once loaded, to verify against
    struct rb_root pending_checksum_ops; // Children of merkle tree leaves, keyed by page offset
    struct list_head pending_merkle_children; // If this is not a merkle tree leaf, this is a list of merkle_bio_data from lower levels

    struct rb_node tree_node; // For merkle_tree_layers
    struct list_head list; // So this bio can be stored in the parent's pending_merkle_children
    struct work_struct work;  // So this bio can be queued in read/write_hash_end_io_queue
};

struct pending_checksum_op {
    int parent_page_offset; // Offset into the parent
    int read_checksum_offset; // Read: Within the read_bio, the offset of the checksum
    char checksum[AES_GCM_INTEGRITY_SIZE]; // Write: The hash of the written page
    struct bio *read_bio;     // NULL if this is a write, since writes can ACK early and don't need to wait here
    struct rb_node tree_node; // For the pending_ops tree in merkle_bio_data
};

enum EncDecType { ROLLBACCINE_ENCRYPT, ROLLBACCINE_DECRYPT };

int __init dm_merkle_init(void);
void dm_merkle_exit(void);

void init_merkle_tree(struct merkle_device *device, uint64_t max_merkle_root_pages) {
    int smallest_layer_pages, i;
    int total_integrity_pages = device->num_sectors * ROLLBACCINE_SECTORS_PER_ENCRYPTION * AES_GCM_INTEGRITY_SIZE / AES_GCM_PER_PAGE;

    device->merkle_tree_height = 0;

    do {
        smallest_layer_pages = total_integrity_pages;
        for (i = 0; i < device->merkle_tree_height; i++) {
            // Calculate the size of the smallest Merkle tree hash layer
            // Round layer size up so we have enough space
            smallest_layer_pages = (smallest_layer_pages + AES_GCM_PER_PAGE - 1) / AES_GCM_PER_PAGE;
        }

        device->merkle_tree_height++;
    } while (smallest_layer_pages > max_merkle_root_pages);

    printk(KERN_INFO "num_sectors: %d, max_merkle_root_pages: %llu, smallest_layer_pages: %llu, height: %d", device->num_sectors, max_merkle_root_pages, smallest_layer_pages, device->merkle_tree_height);

    device->merkle_tree_root = vzalloc(smallest_layer_pages * PAGE_SIZE);
    if (!device->merkle_tree_root) {
        printk(KERN_ERR "Could not allocate merkle tree root");
        return;
    }

    device->pages_above_merkle_tree_layer = kzalloc(device->merkle_tree_height * sizeof(int), GFP_KERNEL);
    device->pages_above_merkle_tree_layer[device->merkle_tree_height - 1] = total_integrity_pages;
    // Note: [0] = 0 since there is no layer above the root, and [1] = 0 since the root is in memory
    for (i = device->merkle_tree_height - 2; i > 1; i--) {
        device->pages_above_merkle_tree_layer[i] = (device->pages_above_merkle_tree_layer[i + 1] + AES_GCM_PER_PAGE - 1) / AES_GCM_PER_PAGE;
    }
    device->merkle_tree_num_pages = 0;
    for (i = 2; i < device->merkle_tree_height; i++) {
        device->merkle_tree_num_pages += device->pages_above_merkle_tree_layer[i];
    }

    device->merkle_tree_layers = kzalloc(device->merkle_tree_height * sizeof(struct rb_root), GFP_KERNEL);
    // Note: [0] = NULL always, since that layer is represented by merkle_tree_root in memory
    for (i = 1; i < device->merkle_tree_height; i++) {
        device->merkle_tree_layers[i] = RB_ROOT;
    }
}

void write_hash_end_io_task(struct work_struct *work) {
    // struct merkle_bio_data *bio_data = container_of(work, struct merkle_bio_data, work);
    // struct bio *bio = bio_data->bio_src;
    // struct merkle_device *device = bio_data->device;
    // struct pending_checksum_list *pending_checksum_list = bio_data->pending_checksum_list;
    // bool no_more_pending_ops;

    // mutex_lock(&device->merkle_tree_lock);
    // no_more_pending_ops = list_empty(&pending_checksum_list->ops);
    // if (no_more_pending_ops) {
    //     // Remove from pending ops tree
    //     rb_erase(&pending_checksum_list->tree_node, &device->merkle_tree_layers[pending_checksum_list->layer]);
    // }
    // mutex_unlock(&device->merkle_tree_lock);

    // if (!no_more_pending_ops) {
    //     // If there are still pending operations for this page, we need to reissue the read
    //     bio_reset(bio, device->dev->bdev, REQ_OP_READ);
    //     bio->bi_end_io = read_hash_end_io;
    //     submit_bio_noacct(bio);
    // }
}

void write_hash_end_io(struct bio *bio) {
    struct merkle_bio_data *bio_data = bio->bi_private;
    INIT_WORK(&bio_data->work, write_hash_end_io_task);
    queue_work(bio_data->device->write_hash_end_io_queue, &bio_data->work);
}

void read_hash_end_io_task(struct work_struct *work) {
    // struct bio_data *bio_data = container_of(work, struct merkle_bio_data, work);
    // struct bio *bio = bio_data->bio_src;
    // struct merkle_device *device = bio_data->device;
    // struct pending_checksum_list *pending_checksum_list = bio_data->pending_checksum_list;
    // struct pending_checksum_op *pending_checksum_op, *next_pending_checksum_op;
    // struct bio_data *pending_bio_data;
    // bool encrypt_error;
    // bool dirtied = false;

    // struct page *page = bio_page(bio);
    // void *page_addr = kmap(page);

    // // Execute any pending checksum operations
    // mutex_lock(&device->merkle_tree_lock);
    // list_for_each_entry_safe(pending_checksum_op, next_pending_checksum_op, &pending_checksum_list->ops, list) {
    //     pending_bio_data = pending_checksum_op->bio_data;
    //     if (pending_bio_data->is_write) {
    //         // Write to the parent (the page read)
    //         memcpy(pending_bio_data->checksum + pending_checksum_op->checksum_offset, page_addr + pending_checksum_op->parent_page_offset, AES_GCM_INTEGRITY_SIZE);
    //         dirtied = true;

    //         try_free_bio(pending_bio_data);

    //         list_del(&pending_checksum_op->list);
    //         kfree(pending_checksum_op);
    //     } else {
    //         // TODO: Read from the page
    //     }
    // }
    // if (!dirtied) {
    //     // Remove from pending ops tree
    //     // Note: We don't remove if the page is dirtied, because we want to prevent the next read from happening until the dirtied page makes it to disk, so the pending ops structures should remain
    //     rb_erase(&pending_checksum_list->tree_node, &device->merkle_tree_layers[pending_checksum_list->layer]);
    // }
    // mutex_unlock(&device->merkle_tree_lock);

    // kunmap(page);

    // // Add to this page's parent's pending ops, then write this bio to disk
    // if (dirtied) {
    //     // Encrypt
    //     bio_data->checksum = enc_or_dec_bio(bio_data, ROLLBACCINE_ENCRYPT, &encrypt_error);
    //     if (encrypt_error) {
    //         printk_ratelimited(KERN_ERR "Error encrypting hash %llu", bio_data->start_sector);
    //         return;
    //     }
    //     // Queue this write to the parent and fetch the parents
    //     fetch_merkle_leaf(device, bio_data);

    //     bio_reset(bio, device->dev->bdev, REQ_OP_WRITE);
    //     bio->bi_end_io = write_hash_end_io;
    //     submit_bio_noacct(bio);
    // } else {
    //     // Decrement ref count
    //     try_free_bio(bio_data);
    // }
}

void read_hash_end_io(struct bio *bio) {
    struct merkle_bio_data *bio_data = bio->bi_private;
    INIT_WORK(&bio_data->work, read_hash_end_io_task);
    queue_work(bio_data->device->read_hash_end_io_queue, &bio_data->work);
}

struct merkle_bio_data *create_merkle_bio(struct merkle_device *device, int layer, int page, int page_offset) {
    struct merkle_bio_data *bio_data;
    struct page *page;
    struct bio *bio = bio_alloc_bioset(device->dev->bdev, 1, REQ_OP_READ, GFP_NOIO, &device->bs);
    bio->bi_iter.bi_sector = page * SECTORS_PER_PAGE;

    page = alloc_page(GFP_KERNEL);
    if (!page) {
        printk(KERN_ERR "Could not allocate page");
        return NULL;
    }
    _bio_add_page(bio, page, PAGE_SIZE, 0);
    bio->bi_end_io = read_hash_end_io;

    bio_data = kzalloc(sizeof(struct merkle_bio_data), GFP_KERNEL);
    bio_data->device = device;
    bio_data->bio_src = bio;
    bio_data->page_num = bio->bi_iter.bi_sector / SECTORS_PER_PAGE;
    bio_data->layer = layer;
    // Note: parent should be filled in once the parent bio is created
    bio_data->parent_page_offset = page_offset;
    bio_data->pending_checksum_ops = RB_ROOT;
    INIT_LIST_HEAD(&bio_data->pending_merkle_children);

    bio->bi_private = bio_data;

    return bio_data;
}

void add_merkle_node_request(struct merkle_device *device, struct merkle_bio_data *child, int layer, int parent_page_num, int parent_page_offset, struct merkle_bio_data **parent_bio_datas, int *num_parent_bios) {
    struct rb_node **tree_node_location;
    struct rb_node *tree_node;
    struct merkle_bio_data *merkle_node;
    struct pending_checksum_op *other_pending_checksum_op;

    // Stop if the parent must be in memory
    if (layer < 1) {
        return;
    }

    tree_node_location = &(device->merkle_tree_layers[layer].rb_node);

    // See if the parent page has already been requested
    while (*tree_node_location != NULL) {
        merkle_node = container_of(*tree_node_location, struct merkle_bio_data, tree_node);
        tree_node = *tree_node_location;

        if (parent_page_num < merkle_node->page_num)
            tree_node_location = &tree_node->rb_left;
        else if (parent_page_num > merkle_node->page_num)
            tree_node_location = &tree_node->rb_right;
        else {
            // Request for this merkle node exists, add to the tail and stop
            list_add_tail(&child->list, &merkle_node->pending_merkle_children);
            child->parent = merkle_node;
            return;
        }
    }

    // Page hasn't been requested, add it
    merkle_node = create_merkle_bio(device, layer, parent_page_num, parent_page_offset);
    parent_bio_datas[*num_parent_bios] = merkle_node;
    (*num_parent_bios)++;
    rb_link_node(&merkle_node->tree_node, tree_node, tree_node_location);
    rb_insert_color(&merkle_node->tree_node, &device->merkle_tree_layers[layer]);

    child->parent = merkle_node;

    // Iterate through all ancestors to fetch the pages if necessary
    add_merkle_node_request(device, merkle_node, layer - 1, parent_page_num / AES_GCM_PER_PAGE, parent_page_num % AES_GCM_PER_PAGE, parent_bio_datas, num_parent_bios);
}

void add_merkle_leaf_request(struct merkle_device *device, struct pending_checksum_op *pending_checksum_op, int parent_page_num, struct merkle_bio_data **parent_bio_datas, int *num_parent_bios) {
    struct rb_node **tree_node_location = &(device->merkle_tree_layers[device->merkle_tree_height - 1].rb_node);
    struct rb_node *tree_node;
    struct merkle_bio_data *merkle_leaf;
    struct pending_checksum_op *other_pending_checksum_op;

    // See if the parent page has already been requested
    while (*tree_node_location != NULL) {
        merkle_leaf = container_of(*tree_node_location, struct merkle_bio_data, tree_node);
        tree_node = *tree_node_location;

        if (parent_page_num < merkle_leaf->page_num)
            tree_node_location = &tree_node->rb_left;
        else if (parent_page_num > merkle_leaf->page_num)
            tree_node_location = &tree_node->rb_right;
        else {
            // Request for this merkle node exists, add this pending op to *that* tree
            tree_node_location = &merkle_leaf->pending_checksum_ops.rb_node;
            while (*tree_node_location != NULL) {
                other_pending_checksum_op = container_of(*tree_node_location, struct pending_checksum_op, tree_node);
                if (pending_checksum_op->parent_page_offset < other_pending_checksum_op->parent_page_offset)
                    tree_node_location = other_pending_checksum_op->tree_node.rb_left;
                else if (pending_checksum_op->parent_page_offset > other_pending_checksum_op->parent_page_offset)
                    tree_node_location = other_pending_checksum_op->tree_node.rb_right;
                else {
                    // Shouldn't happen
                    printk_ratelimited(KERN_ERR "Detected concurrent read/write to the same block in add_merkle_leaf_request, parent_page_num: %d, parent_page_offset: %d", parent_page_num, pending_checksum_op->parent_page_offset);
                    return;
                }
            }
            // Add this pending op to that page and return
            rb_link_node(&pending_checksum_op->tree_node, tree_node, tree_node_location);
            rb_insert_color(&pending_checksum_op->tree_node, &merkle_leaf->pending_checksum_ops);
            return;
        }
    }

    // Page hasn't been requested, add it
    merkle_leaf = create_merkle_bio(device, device->merkle_tree_height - 1, parent_page_num, pending_checksum_op->parent_page_offset);
    rb_link_node(&merkle_leaf->tree_node, tree_node, tree_node_location);
    rb_insert_color(&merkle_leaf->tree_node, &device->merkle_tree_layers[device->merkle_tree_height - 1]);
    parent_bio_datas[*num_parent_bios] = merkle_leaf;
    (*num_parent_bios)++;

    // Add this pending op to the new page
    rb_link_node(&pending_checksum_op->tree_node, tree_node, &merkle_leaf->pending_checksum_ops.rb_node);
    rb_insert_color(&pending_checksum_op->tree_node, &merkle_leaf->pending_checksum_ops);

    // Iterate through all ancestors to fetch the pages if necessary
    add_merkle_node_request(device, merkle_leaf, device->merkle_tree_height - 2, parent_page_num / AES_GCM_PER_PAGE, parent_page_num % AES_GCM_PER_PAGE, parent_bio_datas, num_parent_bios);
}

void fetch_merkle_nodes(struct merkle_device *device, struct bio_data *bio_data, struct merkle_bio_data **parent_bio_datas, int *num_parent_bios) {
    struct bio *bio = bio_data->bio_src;
    struct pending_checksum_op *pending_checksum_op;
    int parent_page_num, curr_sector, curr_page;
    int checksum_offset = 0;

    // Create a pending_checksum_op for each page in the bio
    while (bio->bi_iter.bi_size) {
        curr_sector = bio->bi_iter.bi_sector;
        curr_page = curr_sector / SECTORS_PER_PAGE - device->merkle_tree_num_pages;

        pending_checksum_op = kmalloc(sizeof(struct pending_checksum_op), GFP_KERNEL);
        pending_checksum_op->parent_page_offset = curr_page % AES_GCM_PER_PAGE;

        switch (bio_data_dir(bio)) {
            case WRITE:
                // If this is a write, copy the relevant part of the checksum to write to the parent
                memcpy(pending_checksum_op->checksum, bio_data->checksum_and_iv + checksum_offset, AES_GCM_INTEGRITY_SIZE);
                break;
            case READ:
                // If this is a read, leave a reference to the bio so it can be notified when the read is ready
                pending_checksum_op->read_bio = bio;
                atomic_inc(&bio_data->ref_counter);
                pending_checksum_op->read_checksum_offset = checksum_offset;
                break;
        }
        
        parent_page_num = curr_page / AES_GCM_PER_PAGE;

        // Add to pending ops, check if the parent's parent also needs to be fetched
        add_merkle_leaf_request(device, pending_checksum_op, parent_page_num, parent_bio_datas, num_parent_bios);

        bio_advance_iter(bio, &bio->bi_iter, ROLLBACCINE_ENCRYPTION_GRANULARITY);
        checksum_offset += AES_GCM_INTEGRITY_SIZE;
    }

    // Reset bio to start after iterating
    bio->bi_iter.bi_sector = bio_data->start_sector;
    bio->bi_iter.bi_size = (bio_data->end_sector - bio_data->start_sector) * SECTOR_SIZE;
    bio->bi_iter.bi_idx = 0;
}

// Layer is 0 indexed. Layer = tree_height for data read/writes
void fetch_merkle_leaf(struct merkle_device *device, struct bio_data *bio_data) {
    int num_pages = bio_sectors(bio_data->bio_src) / SECTORS_PER_PAGE;
    struct merkle_bio_data **parent_bio_datas;
    int num_parent_bios = 0;
    int i;

    // TODO: Fast path if the entire tree is in memory
    if (device->merkle_tree_height == 1) {
        return;
    }

    parent_bio_datas = kmalloc(num_pages * (device->merkle_tree_height - 1) * sizeof(struct merkle_bio_data *), GFP_KERNEL);

    mutex_lock(&device->merkle_tree_lock);
    fetch_merkle_nodes(device, bio_data, parent_bio_datas, &num_parent_bios);
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
    int error;

    bio_set_dev(bio, device->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    bio_data = kmalloc(sizeof(struct bio_data), GFP_KERNEL);
    bio_data->device = device;
    bio_data->bio_src = bio;
    bio_data->start_sector = bio->bi_iter.bi_sector;
    bio_data->end_sector = bio->bi_iter.bi_sector + bio_sectors(bio);
    bio_data->is_write = bio_data_dir(bio) == WRITE;

    switch (bio_data_dir(bio)) {
        case WRITE:
            // Deep clone for encryption, otherwise we may overwrite buffers from the user and can cause a crash
            bio_data->deep_clone = deep_bio_clone(device, bio);
            if (!bio_data->deep_clone) {
                printk(KERN_ERR "Could not create deep clone");
                return DM_MAPIO_REMAPPED;
            }

            // Encrypt
            bio_data->checksum_and_iv = alloc_bio_checksum(bio_sectors(bio));
            if (!bio_data->checksum_and_iv) {
                printk(KERN_ERR "Could not allocate checksum_and_iv for bio");
                return DM_MAPIO_REMAPPED;
            }
            error = enc_or_dec_bio(bio_data, bio_data->checksum_and_iv, ROLLBACCINE_ENCRYPT);
            if (error) {
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
            fetch_merkle_leaf(device, bio_data);

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
        return kmalloc(bio_checksum_and_ivsize(num_sectors), GFP_KERNEL);
    } else {
        return NULL;
    }
}

inline unsigned char *get_bio_checksum(unsigned char *checksum, sector_t start_sector, sector_t current_sector) {
    return checksum + (current_sector - start_sector) / ROLLBACCINE_SECTORS_PER_ENCRYPTION * AES_GCM_INTEGRITY_SIZE;
}

int enc_or_dec_bio(struct bio_data *bio_data, unsigned char *full_checksum, enum EncDecType enc_or_dec) {
    int ret = 0;
    struct bio *bio;
    struct bio_vec bv;
    sector_t curr_sector;
    struct aead_request *req;
    struct scatterlist sg[4];
    struct page *page_verify;
    DECLARE_CRYPTO_WAIT(wait);
    unsigned char *sector_checksum;
    unsigned char *sector_iv;

    if (bio_data->end_sector == bio_data->start_sector) {
        // printk(KERN_INFO "Skipping encryption/decryption for empty bio");
        return 0;
    }

    switch (enc_or_dec) {
        case ROLLBACCINE_ENCRYPT:
            // Operate on the deep clone, since otherwise we may overwrite buffers from the user and can cause a crash
            bio = bio_data->deep_clone;
            break;
        case ROLLBACCINE_DECRYPT:
            bio = bio_data->bio_src;
            break;
    }

    while (bio->bi_iter.bi_size) {
        // printk(KERN_INFO "enc/dec starting");
        curr_sector = bio->bi_iter.bi_sector;
        bv = bio_iter_iovec(bio, bio->bi_iter);

        sector_checksum = get_bio_checksum(full_checksum, bio_data->start_sector, curr_sector);
        sector_iv = sector_checksum + AES_GCM_AUTH_SIZE;

        // Lazily allocate the AEAD request, because a lot of reads are over blocks that have not been written to (so they will not pass !has_checksum and won't need to alloc)
        if (req == NULL) {
            req = aead_request_alloc(bio_data->device->tfm, GFP_KERNEL);
            if (!req) {
                printk(KERN_ERR "aead request allocation failed");
                return 1;
            }
        }

        // Set up scatterlist to encrypt/decrypt
        sg_init_table(sg, 4);
        sg_set_buf(&sg[0], &curr_sector, sizeof(uint64_t));
        sg_set_buf(&sg[1], sector_iv, AES_GCM_IV_SIZE);
        sg_set_page(&sg[2], bv.bv_page, ROLLBACCINE_ENCRYPTION_GRANULARITY, bv.bv_offset);
        sg_set_buf(&sg[3], sector_checksum, AES_GCM_AUTH_SIZE);

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
                aead_request_set_crypt(req, sg, sg, ROLLBACCINE_ENCRYPTION_GRANULARITY, sector_iv);
                ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
                break;
            case ROLLBACCINE_DECRYPT:
                aead_request_set_crypt(req, sg, sg, ROLLBACCINE_ENCRYPTION_GRANULARITY + AES_GCM_AUTH_SIZE, sector_iv);
                ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
                break;
        }

        if (ret) {
            if (ret == -EBADMSG) {
                printk_ratelimited(KERN_ERR "invalid integrity check");
            } else {
                printk_ratelimited(KERN_ERR "encryption/decryption failed with error code %d", ret);
            }
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
    return ret;
}

static int merkle_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    int i;
    uint64_t max_merkle_root_pages;

    printk(KERN_INFO "merkle constructor called\n");

    struct merkle_device *device = kmalloc(sizeof(struct merkle_device), GFP_KERNEL);
    if (device == NULL) {
        ti->error = "Cannot allocate context";
        return -ENOMEM;
    }

    bioset_init(&device->bs, 0, 0, BIOSET_NEED_BVECS);

    device->read_hash_end_io_queue = alloc_workqueue("read_hash_end_io_queue", 0, 0);
    if (!device->read_hash_end_io_queue) {
        printk(KERN_ERR "Cannot allocate read_hash_end_io_queue");
        return -ENOMEM;
    }

    device->write_hash_end_io_queue = alloc_workqueue("write_hash_end_io_queue", 0, 0);
    if (!device->write_hash_end_io_queue) {
        printk(KERN_ERR "Cannot allocate write_hash_end_io_queue");
        return -ENOMEM;
    }

    // Get the device from argv[0] and store it in device->dev
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &device->dev)) {
        ti->error = "Device lookup failed";
        kfree(device);
        return -EINVAL;
    }

    // Set up hashing
    device->insecure_hash_alg = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(device->insecure_hash_alg)) {
        printk(KERN_ERR "Error allocating hash");
        return PTR_ERR(device->insecure_hash_alg);
    }
    device->hash_desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(device->insecure_hash_alg), GFP_KERNEL);
    if (!device->hash_desc) {
        printk(KERN_ERR "Error allocating hash desc");
        return -ENOMEM;
    }
    device->hash_desc->tfm = device->insecure_hash_alg;

    // Set up AEAD
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

    device->num_sectors = ti->len;

    ti->error = kstrtou64(argv[1], 10, max_merkle_root_pages);
    if (ti->error < 0) {
        printk(KERN_ERR "Error parsing max_merkle_root_pages");
        return ti->error;
    }

    mutex_init(&device->merkle_tree_lock);
    init_merkle_tree(device, max_merkle_root_pages);

    // TODO: Remap write sectors to be after where we store the merkle tree on disk

    ti->private = device;

    return 0;
}

static void merkle_destructor(struct dm_target *ti) {
    printk(KERN_INFO "merkle destructor called\n");

    struct merkle_device *device = ti->private;

    crypto_free_aead(device->tfm);
    crypto_free_shash(device->insecure_hash_alg);
    kfree(device->hash_desc);
    kvfree(device->merkle_tree_root);
    destroy_workqueue(device->read_hash_end_io_queue);
    destroy_workqueue(device->write_hash_end_io_queue);
    dm_put_device(ti, device->dev);
    bioset_exit(&device->bs);
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
