/**
 * This file is heavily inspired by https://github.com/sysprog21/kecho/tree/master and https://github.com/LINBIT/drbd.
 * Note: In order to kill threads on shutdown, we create a list of all open sockets that threads could be blocked on, and close them on shutdown.
 *       We also set shutting_down = true so a thread who returns from a blocking operation sees it and exits.
 *       We don't use kthread_stop() because it's blocking, and we need to close the sockets, which wakes the threads up before they see they should stop.
 */

#include <crypto/aead.h>
#include <crypto/drbg.h>
#include <crypto/hash.h>
#include <crypto/if_alg.h>
#include <crypto/internal/hash.h> /* SHA-256 Hash*/
#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <linux/device-mapper.h>
#include <linux/inet.h>  // For in4_pton to translate IP addresses from strings
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/tcp.h>
#include <linux/vmalloc.h>
#include <net/handshake.h>  // For TLS
#include <net/sock.h>
#include <net/tls_prot.h>

#define ROLLBACCINE_MAX_CONNECTIONS 10
#define ROLLBACCINE_RETRY_TIMEOUT 5000  // Number of milliseconds before client attempts to connect to a server again
#define ROLLBACCINE_INIT_WRITE_INDEX 0
#define ROLLBACCINE_TLS_TIMEOUT 5000  // Number of milliseconds to wait for TLS handshake to complete
#define ROLLBACCINE_AVG_HASHES_PER_WRITE 4
#define ROLLBACCINE_ENCRYPTION_GRANULARITY PAGE_SIZE
// #define ROLLBACCINE_ENCRYPTION_GRANULARITY SECTOR_SIZE
#define AES_GCM_IV_SIZE 12
#define AES_GCM_AUTH_SIZE 16
#define KEY_SIZE 16
#define MODULE_NAME "rollbaccine"

#define TLS_ON
// #define MULTITHREADED_NETWORK
#define MEMORY_TRACKING  // Check the number of mallocs/frees and see if we're leaking memory

// Used to compare against checksums to see if they have been set yet (or if they're all 0)
static const char ZERO_AUTH[AES_GCM_AUTH_SIZE] = {0};

// TODO: Expand with protocol message types
enum MsgType { ROLLBACCINE_WRITE, ROLLBACCINE_FSYNC, FOLLOWER_ACK };

// Note: These message types are sent over network, so they need to be packed & int sizes need to be specific
struct ballot {
    uint64_t id;
    uint64_t num;
} __attribute__((packed));

struct metadata_msg {
    enum MsgType type;
    struct ballot bal;
    uint64_t write_index;
    uint64_t num_pages;

    // Metadata about the bio
    uint64_t bi_opf;
    sector_t sector;
} __attribute__((packed));

// Allow us to keep track of threads' sockets so we can shut them down and free them on exit.
struct socket_list {
    struct socket *sock;
    struct list_head list;
};

struct rollbaccine_device {
    struct dm_dev *dev;
    struct bio_set bs;
    struct kmem_cache *bio_data_cache;
    spinlock_t page_cache_lock;
    struct page *page_cache;
    int page_cache_size;
    bool is_leader;
    bool shutting_down;  // Set to true when user triggers shutdown. All threads check this and abort if true. Used instead of kthread_should_stop(), since the function that flips that boolean to true (kthread_stop()) is blocking, which creates a race condition when we kill the socket & also wait for the thread to stop.
    int f;
    int n;

    struct ballot bal;
    int write_index;        // Doesn't need to be atomic because only the broadcast thread will modify this
    spinlock_t index_lock;  // Must be obtained for any operation modifying write_index and queues ordered by those indices

    // Logic for fsyncs blocking on replication
    // IMPORTANT: If both replica_fsync_lock and index_lock must be obtained, obtain index_lock first.
    spinlock_t replica_fsync_lock;
    int *replica_fsync_indices;  // Len = n
    int max_replica_fsync_index;
    struct bio_list fsyncs_pending_replication;  // List of all fsyncs waiting for replication. Ordered by write index.

    // Logic for writes that block on conflicting writes
    struct rb_root outstanding_ops;  // Tree of all outstanding operations, sorted by the sectors they write to
    struct list_head pending_ops;    // List of all operations that conflict with outstanding operations (or other pending operations)
    bool processing_pending_ops;  // Set to true when a bio is being popped off pending_ops by another bio during its end_io. If the other bio submits the pending op while holding index_lock, it could result in deadlock (because this bio can then trigger its own end_io, which would need to obtain the same index_lock). Instead, the other bio sets this flag to true, then submits the bio without a lock, then reobtains the lock and removes the bio from the pending_ops list. While this flag is on, other bios will not pop things off the pending_ops queue. This guarantees consistent ordering between primary and replicas

    // Communication between main threads and the networking thread
    struct workqueue_struct *broadcast_queue;

    // Sockets, tracked so we can kill them on exit.
    struct list_head server_sockets;
    struct list_head client_sockets;

    // Connected sockets. Should be a subset of the sockets above. Handy for broadcasting
    // TODO: Need to figure out network handshake so we know who we're talking to.
    struct mutex connected_sockets_lock;
    struct list_head connected_sockets;

    // AEAD
    struct crypto_aead *tfm;
    char *key;
    char *checksums;

    // Counters for tracking memory usage
#ifdef MEMORY_TRACKING
    // These counters will tell us if there's a memory leak
    atomic_t num_bio_pages_not_freed;
    atomic_t num_bio_data_not_freed;
    atomic_t num_shallow_clones_not_freed;
    atomic_t num_deep_clones_not_freed;
    int num_rb_nodes;
    int num_bio_sector_ranges;
    int num_fsyncs_pending_replication;
    atomic_t num_checksum_and_ivs;
    // These counters tell us the maximum amount of memory we need to prealloc
    atomic_t max_outstanding_num_bio_pages;
    atomic_t max_outstanding_num_bio_data;
    atomic_t max_outstanding_num_shallow_clones;
    atomic_t max_outstanding_num_deep_clones;
    int max_outstanding_num_rb_nodes;
    int max_outstanding_num_bio_sector_ranges;
    int max_outstanding_fsyncs_pending_replication;
#endif
};

// Associated data for each bio, shared between clones
struct bio_data {
    struct rollbaccine_device *device;
    struct bio *bio_src;
    struct bio *deep_clone;
    struct bio *shallow_clone;
    int write_index;
    bool is_fsync;
    atomic_t ref_counter;               // The number of clones. Once it hits 0, the bio can be freed
    struct work_struct broadcast_work;  // So this bio can be scheduled as a job
    struct rb_node tree_node;           // So this bio can be inserted into a tree
    unsigned char *checksum_and_iv;     // Checksums and IVs for each sector or page, if this is a write
};

// For each bio that is placed on the pending_ops queue. Necessary to keep separate from bio_data because the bio may be submitted (and its bio_data deleted) before it is removed from the pending_ops
// queue, in order to avoid deadlock. See the note on processing_pending_ops.
struct bio_sector_range {
    sector_t start_sector;
    sector_t end_sector;
    struct bio *shallow_clone;
    struct list_head list;
};

// Thread params: Parameters passed into threads. Should be freed by the thread when it exits.

struct client_thread_params {
    struct socket *sock;
    struct sockaddr_in addr;
    struct rollbaccine_device *device;
};

struct accepted_thread_params {
    struct socket *sock;
    struct rollbaccine_device *device;
};

struct listen_thread_params {
    struct socket *sock;
    struct rollbaccine_device *device;
};

// Returns true if the insert was successful, false if there's a conflict
bool try_insert_into_outstanding_ops(struct rollbaccine_device *device, struct bio *shallow_clone); 
void remove_from_outstanding_ops_and_unblock(struct rollbaccine_device *device, struct bio *shallow_clone);
void page_cache_free(struct rollbaccine_device *device, struct page *page_to_free);
void page_cache_destroy(struct rollbaccine_device *device);
struct page *page_cache_alloc(struct rollbaccine_device *device);
void atomic_max(atomic_t *old, int new);
void down_interruptible_with_retry(struct semaphore *sem);
struct bio_data *alloc_bio_data(struct rollbaccine_device *device);
void ack_bio_to_user_without_executing(struct bio *bio);
void process_follower_fsync_index(struct rollbaccine_device *device, int follower_id, int follower_fsync_index);
bool requires_fsync(struct bio *bio);
unsigned int remove_fsync_flags(unsigned int bio_opf);
void free_pages_end_io(struct bio *received_bio);
void try_free_clones(struct bio *clone);
void disk_end_io(struct bio *shallow_clone);
void leader_write_disk_end_io(struct bio *shallow_clone);
void leader_read_disk_end_io(struct bio *shallow_clone);
void replica_disk_end_io(struct bio *received_bio);
void network_end_io(struct bio *deep_clone);
void broadcast_bio(struct work_struct *work);
struct bio *shallow_bio_clone(struct rollbaccine_device *device, struct bio *bio_src);
struct bio *deep_bio_clone(struct rollbaccine_device *device, struct bio *bio_src);
// Returns array of checksums and IVs for writes, NULL for reads
unsigned char *enc_or_dec_bio(struct bio_data *bio_data, int enc_or_dec);
void kill_thread(struct socket *sock);
void blocking_read(struct rollbaccine_device *device, struct socket *sock);
#ifdef TLS_ON
void on_tls_handshake_done(void *data, int status, key_serial_t peerid);
#endif
int connect_to_server(void *args);
int start_client_to_server(struct rollbaccine_device *device, char *addr, ushort port);
int listen_to_accepted_socket(void *args);
int listen_for_connections(void *args);
int start_server(struct rollbaccine_device *device, ushort port);
int __init rollbaccine_init_module(void);
void rollbaccine_exit_module(void);

inline bool has_checksum(unsigned char *checksum) {
    return memcmp(checksum, ZERO_AUTH, AES_GCM_AUTH_SIZE) != 0;
}

inline unsigned char *global_checksum(struct rollbaccine_device *device, sector_t sector) {
    return &device->checksums[sector * SECTOR_SIZE / ROLLBACCINE_ENCRYPTION_GRANULARITY * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE)];
}

inline unsigned char *global_iv(struct rollbaccine_device *device, sector_t sector) {
    return &device->checksums[sector * SECTOR_SIZE / ROLLBACCINE_ENCRYPTION_GRANULARITY * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE) + AES_GCM_AUTH_SIZE];
}

inline unsigned char *alloc_bio_checksum_and_iv(int num_sectors) {
    return kmalloc(num_sectors * SECTOR_SIZE / ROLLBACCINE_ENCRYPTION_GRANULARITY * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE), GFP_KERNEL);
}

inline unsigned char *get_bio_checksum(unsigned char *checksum_and_iv, sector_t start_sector, sector_t current_sector) {
    return &checksum_and_iv[(current_sector - start_sector) * SECTOR_SIZE / ROLLBACCINE_ENCRYPTION_GRANULARITY * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE)];
}

inline unsigned char *get_bio_iv(unsigned char *checksum_and_iv, sector_t start_sector, sector_t current_sector) {
    return &checksum_and_iv[(current_sector - start_sector) * SECTOR_SIZE / ROLLBACCINE_ENCRYPTION_GRANULARITY * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE) + AES_GCM_AUTH_SIZE];
}

inline void update_global_checksum_and_iv(struct rollbaccine_device *device, unsigned char *checksum_and_iv, sector_t start_sector, int num_sectors) {
    sector_t curr_sector;
    for (curr_sector = start_sector; curr_sector < start_sector + num_sectors; curr_sector += ROLLBACCINE_ENCRYPTION_GRANULARITY / SECTOR_SIZE) {
        memcpy(global_checksum(device, curr_sector), get_bio_checksum(checksum_and_iv, start_sector, curr_sector), AES_GCM_AUTH_SIZE);
        memcpy(global_iv(device, curr_sector), get_bio_iv(checksum_and_iv, start_sector, curr_sector), AES_GCM_IV_SIZE);
    }
}

// Note: Caller must hold index_lock
bool try_insert_into_outstanding_ops(struct rollbaccine_device *device, struct bio *shallow_clone) {
    struct bio_data *bio_data = shallow_clone->bi_private;
    struct bio_sector_range *sector_range;
    sector_t start_sector = shallow_clone->bi_iter.bi_sector;
    sector_t end_sector = start_sector + bio_sectors(shallow_clone);
    struct bio_sector_range *pending_bio_range;
    struct rb_node **potential_tree_node_location = &(device->outstanding_ops.rb_node);
    struct rb_node *potential_parent_node = NULL;
    struct bio_data *potential_parent_bio_data;
    sector_t potential_parent_start_sector, potential_parent_end_sector;

    // See if we conflict with any operations that are already blocked
    list_for_each_entry(pending_bio_range, &device->pending_ops, list) {
        if (start_sector < pending_bio_range->end_sector && pending_bio_range->start_sector < end_sector) {
            goto block;
        }
    }

    // See if we conflict with any outstanding operations. If not, then get the place in the red black tree where we should insert this bio
    while (*potential_tree_node_location != NULL) {
        potential_parent_bio_data = container_of(*potential_tree_node_location, struct bio_data, tree_node);
        potential_parent_start_sector = potential_parent_bio_data->bio_src->bi_iter.bi_sector;
        potential_parent_end_sector = potential_parent_start_sector + bio_sectors(potential_parent_bio_data->bio_src);

        potential_parent_node = *potential_tree_node_location;
        if (end_sector <= potential_parent_start_sector)
            potential_tree_node_location = &potential_parent_node->rb_left;
        else if (start_sector >= potential_parent_end_sector)
            potential_tree_node_location = &potential_parent_node->rb_right;
        else
            goto block;
    }
    // No conflicts, add this bio to the red black tree
#ifdef MEMORY_TRACKING
    device->num_rb_nodes += 1;
#endif
    rb_link_node(&bio_data->tree_node, potential_parent_node, potential_tree_node_location);
    rb_insert_color(&bio_data->tree_node, &device->outstanding_ops);
    return true;

block:
    // Add to pending list. Malloc a sector range
    sector_range = kmalloc(sizeof(struct bio_sector_range), GFP_KERNEL);
    if (!sector_range) {
        printk(KERN_ERR "Could not allocate sector range");
        return false;
    }
#ifdef MEMORY_TRACKING
    device->num_bio_sector_ranges += 1;
#endif
    sector_range->start_sector = start_sector;
    sector_range->end_sector = end_sector;
    sector_range->shallow_clone = shallow_clone;
    list_add_tail(&sector_range->list, &device->pending_ops);
    return false;
}

void remove_from_outstanding_ops_and_unblock(struct rollbaccine_device *device, struct bio *shallow_clone) {
    struct bio_data *bio_data = shallow_clone->bi_private;
    struct bio_sector_range *other_bio_sector_range;
    struct bio_data *other_bio_data;

    spin_lock(&device->index_lock);
#ifdef MEMORY_TRACKING
    device->num_rb_nodes -= 1;
    device->max_outstanding_num_rb_nodes = umax(device->max_outstanding_num_rb_nodes, device->num_rb_nodes + 1);
#endif
    rb_erase(&bio_data->tree_node, &device->outstanding_ops);
    // If another bio is processing pending ops, then we don't need to (if we do, we might actually mess up ordering)
    if (device->processing_pending_ops) {
        spin_unlock(&device->index_lock);
        return;
    }
    device->processing_pending_ops = true;
    while (!list_empty(&device->pending_ops)) {
        other_bio_sector_range = list_first_entry(&device->pending_ops, struct bio_sector_range, list);
        list_del(&other_bio_sector_range->list);
        // Check, in order, if the first pending op can be executed. If not, then break
        if (!try_insert_into_outstanding_ops(device, other_bio_sector_range->shallow_clone)) {
            kfree(other_bio_sector_range);  // Free this range, because the try function will alloc another range on failure
#ifdef MEMORY_TRACKING
            device->num_bio_sector_ranges -= 1;
            device->max_outstanding_num_bio_sector_ranges = umax(device->max_outstanding_num_bio_sector_ranges, device->num_bio_sector_ranges + 1);
#endif
            break;
        }

        // Submit the other bio without holding the spinlock, since the other bio could then finish, and attempt to call this function, causing deadlock
        spin_unlock(&device->index_lock);
        // Update global checksum/ivs
        other_bio_data = other_bio_sector_range->shallow_clone->bi_private;
        if (other_bio_data->checksum_and_iv != NULL) {
            update_global_checksum_and_iv(device, other_bio_data->checksum_and_iv, other_bio_sector_range->start_sector, bio_sectors(other_bio_sector_range->shallow_clone));
        }
        submit_bio_noacct(other_bio_sector_range->shallow_clone);
        spin_lock(&device->index_lock);

        // Remove the other bio
        kfree(other_bio_sector_range);
#ifdef MEMORY_TRACKING
        device->num_bio_sector_ranges -= 1;
        device->max_outstanding_num_bio_sector_ranges = umax(device->max_outstanding_num_bio_sector_ranges, device->num_bio_sector_ranges + 1);
#endif
    }
    device->processing_pending_ops = false;
    spin_unlock(&device->index_lock);
}

// Put the freed page back in the cache for reuse
void page_cache_free(struct rollbaccine_device *device, struct page *page_to_free) {
    spin_lock(&device->page_cache_lock);
    if (device->page_cache_size == 0) {
        device->page_cache = page_to_free;
    } else {
        // Point the new page to the current page_cache
        page_private(page_to_free) = (unsigned long)device->page_cache;
        device->page_cache = page_to_free;
    }
    device->page_cache_size++;
    spin_unlock(&device->page_cache_lock);
}

void page_cache_destroy(struct rollbaccine_device *device) {
    struct page *tmp;

    spin_lock(&device->page_cache_lock);
    while (device->page_cache_size > 0) {
        tmp = device->page_cache;
        device->page_cache = (struct page *)page_private(device->page_cache);
        __free_page(tmp);
        device->page_cache_size--;
    }
    spin_unlock(&device->page_cache_lock);
}

// Get a previously allocated page or allocate a new one if necessary. Store pointers to next pages in page_private, like in drbd.
struct page *page_cache_alloc(struct rollbaccine_device *device) {
    struct page *new_page;
    bool need_new_page = false;

    spin_lock(&device->page_cache_lock);
    if (device->page_cache_size == 0) {
        need_new_page = true;
    } else if (device->page_cache_size == 1) {
        // Set page_cache to NULL now that the list is empty
        new_page = device->page_cache;
        device->page_cache = NULL;
        device->page_cache_size--;
    } else {
        // Point page_cache to the next element in the list
        new_page = device->page_cache;
        device->page_cache = (struct page *)page_private(device->page_cache);
        device->page_cache_size--;
    }
    spin_unlock(&device->page_cache_lock);

    if (need_new_page) {
        new_page = alloc_page(GFP_KERNEL);
        if (!new_page) {
            printk(KERN_ERR "Could not allocate page");
            return NULL;
        }
    }

    return new_page;
}

// If the new value is greater than the old value, swap the old for the new. While loop necessary because the old value may have been concurrently updated, in which case no swap happens.
void atomic_max(atomic_t *old, int new) {
    int old_val;
    do {
        old_val = atomic_read(old);
    } while (old_val < new &&atomic_cmpxchg(old, old_val, new) != old_val);
}

// Semaphore down may return before it actually locks on the semaphore because of a signal. Retry.
void down_interruptible_with_retry(struct semaphore *sem) {
    int ret;
    do {
        ret = down_interruptible(sem);
        if (ret == -ERESTARTSYS) {
            printk(KERN_ERR "down_interruptible_with_retry(sem) interrupted by signal, retrying");
        }
    } while (ret != 0);
}

struct bio_data *alloc_bio_data(struct rollbaccine_device *device) {
    struct bio_data *data = kmem_cache_alloc(device->bio_data_cache, GFP_KERNEL);
    // struct bio_data *data = kmalloc(sizeof(struct bio_data), GFP_KERNEL);
    if (!data) {
        printk(KERN_ERR "Could not allocate bio_data");
        return NULL;
    }
#ifdef MEMORY_TRACKING
    atomic_inc(&device->num_bio_data_not_freed);
#endif
    return data;
}

// TODO: Make super sure that bios ended this way actually don't go to disk
void ack_bio_to_user_without_executing(struct bio *bio) {
    bio->bi_status = BLK_STS_OK;
    bio_endio(bio);
}

// Returns the max int that a quorum agrees to. Note that since the leader itself must have fsync index >= followers' fsync index, the quorum size is f (not f+1).
// Assumes that the bio->bi_private field stores the write index
void process_follower_fsync_index(struct rollbaccine_device *device, int follower_id, int follower_fsync_index) {
    int i, j, num_geq_replica_fsync_indices = 0;
    bool max_index_changed = false;
    struct bio *bio;
    int bio_write_index;

    spin_lock(&device->replica_fsync_lock);
    // Special case for f = 1, n = 2, since there's only 1 follower, so we don't need to iterate.
    // Also, we don't need to compare maxes (the latest message should always have a larger fsync index).
    // TODO: Once we move away from a single network model, we'll need to compare maxes
    if (device->f == 1 && device->n == 2) {
        device->max_replica_fsync_index = follower_fsync_index;
        max_index_changed = true;
    }
    // Special case for f = 1, n = 3.
    // What the quorum agrees on = max of what any 1 follower has (plus the leader's fsync index, which must be higher).
    else if (device->f == 1 && device->n == 3) {
        if (device->max_replica_fsync_index < follower_fsync_index) {
            device->max_replica_fsync_index = follower_fsync_index;
            max_index_changed = true;
        }
    }
    // Otherwise, find the largest fsync index that a quorum agrees to
    else {
        device->replica_fsync_indices[follower_id] = follower_fsync_index;
        for (i = 0; i < device->n; i++) {
            if (device->max_replica_fsync_index >= device->replica_fsync_indices[i]) {
                continue;
            }

            // Count the number of followers with an index >= this index
            num_geq_replica_fsync_indices = 0;
            for (j = 0; j < device->n; j++) {
                if (device->replica_fsync_indices[j] >= device->replica_fsync_indices[i]) {
                    num_geq_replica_fsync_indices++;
                }
            }
            // If a quorum (including the leader) is reached on this index, store it
            if (num_geq_replica_fsync_indices >= device->f) {
                device->max_replica_fsync_index = device->replica_fsync_indices[i];
                max_index_changed = true;
            }
        }
    }

    // Loop through all blocked fsyncs if the max index has changed
    if (max_index_changed) {
        // printk(KERN_INFO "New max quorum write index: %d", device->max_replica_fsync_index);
#ifdef MEMORY_TRACKING
        device->max_outstanding_fsyncs_pending_replication = umax(device->max_outstanding_fsyncs_pending_replication, device->num_fsyncs_pending_replication);
#endif
        while (!bio_list_empty(&device->fsyncs_pending_replication)) {
            bio = bio_list_peek(&device->fsyncs_pending_replication);
            bio_write_index = bio->bi_private;
            if (bio_write_index <= device->max_replica_fsync_index) {
                // printk(KERN_INFO "Fsync with write index %d satisfied", bio_data->write_index);
                // Ack the fsync to the user
                ack_bio_to_user_without_executing(bio);
                // Remove from queue
                bio_list_pop(&device->fsyncs_pending_replication);
#ifdef MEMORY_TRACKING
                device->num_fsyncs_pending_replication -= 1;
#endif
            } else {
                break;
            }
        }
    }
    spin_unlock(&device->replica_fsync_lock);
}

// TODO: Replace with op_is_sync() to handle REQ_SYNC?
bool requires_fsync(struct bio *bio) { return bio->bi_opf & (REQ_PREFLUSH | REQ_FUA); }

unsigned int remove_fsync_flags(unsigned int bio_opf) { return bio_opf & ~REQ_PREFLUSH & ~REQ_FUA; }

// Because we alloc pages when we receive the bios, we have to free them when it's done writing
void free_pages_end_io(struct bio *received_bio) {
    struct bio_data *bio_data = received_bio->bi_private;
    struct rollbaccine_device *device = bio_data->device;
    struct bio_vec bvec;
    struct bvec_iter iter;

    bio_for_each_segment(bvec, received_bio, iter) {
        page_cache_free(device, bvec.bv_page);
        // __free_page(bvec.bv_page);
#ifdef MEMORY_TRACKING
        int num_bio_pages = atomic_dec_return(&device->num_bio_pages_not_freed);
        atomic_max(&device->max_outstanding_num_bio_pages, num_bio_pages + 1);
#endif
    }
    if (bio_data->checksum_and_iv != NULL) {
#ifdef MEMORY_TRACKING
        atomic_dec(&device->num_checksum_and_ivs);
#endif
        kfree(bio_data->checksum_and_iv);
    }
    kmem_cache_free(device->bio_data_cache, bio_data);
    // kfree(bio_data);
#ifdef MEMORY_TRACKING
    int num_bio_data = atomic_dec_return(&device->num_bio_data_not_freed);
    atomic_max(&device->max_outstanding_num_bio_data, num_bio_data + 1);
#endif
    bio_put(received_bio);
}

// Decrement the reference counter tracking the number of clones. Free both deep & shallow clones when it hits 0.
void try_free_clones(struct bio *clone) {
    struct bio_data *bio_data = clone->bi_private;
    // If ref_counter == 0
    if (atomic_dec_and_test(&bio_data->ref_counter)) {
        // printk(KERN_INFO "Freeing clone, write index: %d", deep_clone_bio_data->write_index);
#ifdef MEMORY_TRACKING
        // Note: Decrement first, because after the function executes, bio_data will be freed and we won't have a valid pointer to device
        int num_shallow_clones = atomic_dec_return(&bio_data->device->num_shallow_clones_not_freed);
        atomic_max(&bio_data->device->max_outstanding_num_shallow_clones, num_shallow_clones + 1);
        int num_deep_clones = atomic_dec_return(&bio_data->device->num_deep_clones_not_freed);
        atomic_max(&bio_data->device->max_outstanding_num_deep_clones, num_deep_clones + 1);
#endif
        bio_put(bio_data->shallow_clone);
        free_pages_end_io(bio_data->deep_clone);
    } else {
        // printk(KERN_INFO "Decrementing clone ref count to %d, write index: %d", atomic_read(&deep_clone_bio_data->ref_counter), deep_clone_bio_data->write_index);
    }
}

void disk_end_io(struct bio *shallow_clone) {
    struct bio_data *bio_data = shallow_clone->bi_private;
    struct rollbaccine_device *device = bio_data->device;

    // Try to wake any pending writes
    remove_from_outstanding_ops_and_unblock(device, shallow_clone);
}

void leader_read_disk_end_io(struct bio *shallow_clone) {
    struct bio_data *bio_data = shallow_clone->bi_private;
    struct rollbaccine_device *device = bio_data->device;

    // Decrypt
    enc_or_dec_bio(bio_data, READ);
    // Unblock pending writes
    disk_end_io(shallow_clone);
    // Return to user
    bio_endio(bio_data->bio_src);

    // Free shallow clone and bio_data
#ifdef MEMORY_TRACKING
    int num_shallow_clones = atomic_dec_return(&bio_data->device->num_shallow_clones_not_freed);
    atomic_max(&bio_data->device->max_outstanding_num_shallow_clones, num_shallow_clones + 1);
    int num_bio_data = atomic_dec_return(&device->num_bio_data_not_freed);
    atomic_max(&device->max_outstanding_num_bio_data, num_bio_data + 1);
#endif
    bio_put(shallow_clone);
    if (bio_data->checksum_and_iv != NULL) {
        kfree(bio_data->checksum_and_iv);
    }
    kmem_cache_free(device->bio_data_cache, bio_data);
}

void leader_write_disk_end_io(struct bio *shallow_clone) {
    struct bio_data *bio_data = shallow_clone->bi_private;
    // printk(KERN_INFO "Leader end_io shallow clone %p bio data write index: %d, deep clone: %p", shallow_clone, bio_data->write_index, bio_data->deep_clone);
    disk_end_io(shallow_clone);
    // Return to the user
    ack_bio_to_user_without_executing(bio_data->bio_src);
    // Unlike replica_disk_end_io, the clone is sharing data with the clone used for networking, so we have to check if we can free
    try_free_clones(shallow_clone);
}

void replica_disk_end_io(struct bio *received_bio) {
    // printk(KERN_INFO "Replica clone ended, freeing");
    disk_end_io(received_bio);
    free_pages_end_io(received_bio);
}

void network_end_io(struct bio *deep_clone) {
    // See if we can free
    // printk(KERN_INFO "Network broadcast %d completed", deep_clone_bio_data->write_index);
    try_free_clones(deep_clone);
}

void broadcast_bio(struct work_struct *work) {
    //TODO: Also send hashes & IVs
    int sent;
    struct bio_data *clone_bio_data = container_of(work, struct bio_data, broadcast_work);
    struct bio *clone = clone_bio_data->deep_clone;
    struct rollbaccine_device *device = clone_bio_data->device;
    struct msghdr msg_header;
    struct kvec vec;
    struct socket_list *curr, *next;
    struct metadata_msg metadata;
    struct bio_vec bvec, chunked_bvec;
    struct bvec_iter iter;

    metadata.type = clone_bio_data->is_fsync ? ROLLBACCINE_FSYNC : ROLLBACCINE_WRITE;
    metadata.bal = device->bal;
    metadata.write_index = clone_bio_data->write_index;
    metadata.num_pages = clone->bi_iter.bi_size / PAGE_SIZE;
    metadata.bi_opf = clone->bi_opf;
    metadata.sector = clone->bi_iter.bi_sector;

    // printk(KERN_INFO "Broadcasting write with write_index: %llu, is fsync: %d, bi_opf: %llu", metadata.write_index, requires_fsync(clone), metadata.bi_opf);
    WARN_ON(metadata.write_index == 0);  // Should be at least one. Means that bio_data was retrieved incorrectly

    // Note: If bi_size is not a multiple of PAGE_SIZE, we have to send by sector chunks
    WARN_ON(metadata.num_pages * PAGE_SIZE != clone->bi_iter.bi_size);

    msg_header.msg_name = NULL;
    msg_header.msg_namelen = 0;
    msg_header.msg_control = NULL;
    msg_header.msg_controllen = 0;
    msg_header.msg_flags = 0;

    // Using mutex instead of spinlock because kernel_sendmsg sleeps for TLS and that triggers an error (sleep while holding spinlock)
    mutex_lock(&device->connected_sockets_lock);
    list_for_each_entry_safe(curr, next, &device->connected_sockets, list) {
        vec.iov_base = &metadata;
        vec.iov_len = sizeof(struct metadata_msg);

        // 1. Send metadata
        // Keep retrying send until the whole message is sent
        while (vec.iov_len > 0) {
            sent = kernel_sendmsg(curr->sock, &msg_header, &vec, 1, vec.iov_len);
            if (sent <= 0) {
                printk(KERN_ERR "Error broadcasting message header, aborting");
                // TODO: Should remove the socket from the list and shut down the connection?
                goto finish_sending_to_socket;
            } else {
                vec.iov_base += sent;
                vec.iov_len -= sent;
            }
        }

        bio_for_each_segment(bvec, clone, iter) {
            // TODO 2. Send hash

            // 3. Send bios
            // Note: Replaced with bvec_set_page() in newer kernel versions
            // Note: I'm not really sure if the length is always actually page size. If not, then we have a problem on the receiver
            chunked_bvec.bv_page = bvec.bv_page;
            chunked_bvec.bv_offset = bvec.bv_offset;
            chunked_bvec.bv_len = bvec.bv_len;

            // Keep retrying send until the whole message is sent
            while (chunked_bvec.bv_len > 0) {
                // Note: Replaced WRITE with ITER_SOURCE in newer kernel versions
                iov_iter_bvec(&msg_header.msg_iter, WRITE, &chunked_bvec, 1, chunked_bvec.bv_len);

                sent = sock_sendmsg(curr->sock, &msg_header);
                if (sent <= 0) {
                    printk(KERN_ERR "Error broadcasting message pages");
                    // TODO: Should remove the socket from the list and shut down the connection?
                    goto finish_sending_to_socket;
                } else {
                    chunked_bvec.bv_offset += sent;
                    chunked_bvec.bv_len -= sent;
                }
            }
        }
        // Label to jump to if socket cannot be written to, so we can iterate the next socket
    finish_sending_to_socket:
    }
    // printk(KERN_INFO "Sent metadata message and bios, sector: %llu, num pages: %llu", metadata.sector, metadata.num_pages);
    mutex_unlock(&device->connected_sockets_lock);

    network_end_io(clone);
}

struct bio *shallow_bio_clone(struct rollbaccine_device *device, struct bio *bio_src) {
    struct bio *clone;
    clone = bio_alloc_clone(bio_src->bi_bdev, bio_src, GFP_NOIO, &device->bs);
    if (!clone) {
        printk(KERN_INFO "Could not create clone");
        return NULL;
    }
#ifdef MEMORY_TRACKING
    atomic_inc(&device->num_shallow_clones_not_freed);
#endif

    clone->bi_iter.bi_sector = bio_src->bi_iter.bi_sector;
    return clone;
}

struct bio *deep_bio_clone(struct rollbaccine_device *device, struct bio *bio_src) {
    struct bio *clone;
    struct bio_vec bvec;
    struct bvec_iter iter;
    struct page *page;

    // Note: If bi_size is not a multiple of PAGE_SIZE, we have a BIG problem :(
    clone = bio_alloc_bioset(bio_src->bi_bdev, bio_src->bi_iter.bi_size / PAGE_SIZE, bio_src->bi_opf, GFP_NOIO, &device->bs);
    if (!clone) {
        return NULL;
    }
#ifdef MEMORY_TRACKING
    atomic_inc(&device->num_deep_clones_not_freed);
#endif

    clone->bi_iter.bi_sector = bio_src->bi_iter.bi_sector;

    // TODO: dm-crypt uses alloc_pages first to alloc 2^x pages, then mempool_alloc for the rest. We may want to do that too for performance.
    bio_for_each_segment(bvec, bio_src, iter) {
        page = page_cache_alloc(device);
        // page = alloc_page(GFP_KERNEL);
        // if (!page) {
        //     bio_put(clone);
        //     return NULL;
        // }
#ifdef MEMORY_TRACKING
        atomic_inc(&device->num_bio_pages_not_freed);
#endif
        memcpy(kmap(page), kmap(bvec.bv_page) + bvec.bv_offset, bvec.bv_len);
        kunmap(page);
        kunmap(bvec.bv_page);

        __bio_add_page(clone, page, bvec.bv_len, 0);
    }
    return clone;
}

static int rollbaccine_map(struct dm_target *ti, struct bio *bio) {
    bool is_fsync = false;
    bool is_cloned = false;
    bool doesnt_conflict_with_other_writes = true;
    struct rollbaccine_device *device = ti->private;
    struct bio *deep_clone, *shallow_clone;  // deep clone is for the network, shallow clone is for submission to disk when necessary
    struct bio_data *bio_data;
    unsigned char *bio_checksum_and_iv;
    // For encryption so we can reset the write to the beginning of the block when we are done
    sector_t original_sector = bio->bi_iter.bi_sector;
    unsigned int original_size = bio->bi_iter.bi_size;
    unsigned int original_idx = bio->bi_iter.bi_idx;

    bio_set_dev(bio, device->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    // Copy bio if it's a write
    if (device->is_leader) {
        is_cloned = true;

        bio_data = alloc_bio_data(device);
        bio_data->device = device;
        bio_data->bio_src = bio;
        
        switch (bio_data_dir(bio)) {
            case WRITE:
                is_fsync = requires_fsync(bio);
                bio->bi_opf = remove_fsync_flags(bio->bi_opf);  // All fsyncs become logical fsyncs

                // Encrypt
                bio_checksum_and_iv = enc_or_dec_bio(bio_data, WRITE);
                bio->bi_iter.bi_sector = original_sector;
                bio->bi_iter.bi_size = original_size;
                bio->bi_iter.bi_idx = original_idx;

                // Create the network clone
                deep_clone = deep_bio_clone(device, bio);
                if (!deep_clone) {
                    printk(KERN_ERR "Could not create deep clone");
                    return DM_MAPIO_REMAPPED;
                }

                // Create the disk clone. Necessary because we change the bi_end_io function, so we can't submit the original.
                shallow_clone = shallow_bio_clone(device, deep_clone);
                if (!shallow_clone) {
                    printk(KERN_ERR "Could not create shallow clone");
                    return DM_MAPIO_REMAPPED;
                }
                // Set end_io so once this write completes, queued writes can be unblocked
                shallow_clone->bi_end_io = leader_write_disk_end_io;

                // Set shared data between clones
                bio_data->shallow_clone = shallow_clone;
                bio_data->deep_clone = deep_clone;
                bio_data->is_fsync = is_fsync;
                bio_data->checksum_and_iv = bio_checksum_and_iv;
                atomic_set(&bio_data->ref_counter, 2);
                INIT_WORK(&bio_data->broadcast_work, broadcast_bio);
                deep_clone->bi_private = bio_data;
                shallow_clone->bi_private = bio_data;

                // Increment indices, place ops on queue, submit cloned ops to disk
                spin_lock(&device->index_lock);
                // Increment write index
                bio_data->write_index = ++device->write_index;
                doesnt_conflict_with_other_writes = try_insert_into_outstanding_ops(device, shallow_clone);
                // printk(KERN_INFO "Inserted clone %p, write index: %d", shallow_clone, bio_data->write_index);
                if (is_fsync) {
                    // Add original bio to fsyncs blocked on replication
                    bio->bi_private = bio_data->write_index;  // HACK: Store the write index in this fsync's bi_private field so it can be checked when network fsyncs are being acknowledged
                    spin_lock(&device->replica_fsync_lock);
                    bio_list_add(&device->fsyncs_pending_replication, bio);
#ifdef MEMORY_TRACKING
                    device->num_fsyncs_pending_replication += 1;
#endif
                    spin_unlock(&device->replica_fsync_lock);
                }
                queue_work(device->broadcast_queue, &bio_data->broadcast_work);
                spin_unlock(&device->index_lock);

                // Even though submit order != write index order, any conflicting writes will only be submitted later so any concurrency here is fine
                if (doesnt_conflict_with_other_writes) {
                    update_global_checksum_and_iv(device, bio_checksum_and_iv, original_sector, bio_sectors(bio));
                    submit_bio_noacct(shallow_clone);
                }
                break;
            case READ:
                // Create the disk clone. Necessary because we change the bi_end_io function, so we can't submit the original.
                shallow_clone = shallow_bio_clone(device, bio);
                if (!shallow_clone) {
                    printk(KERN_ERR "Could not create shallow clone");
                    return DM_MAPIO_REMAPPED;
                }
                // Set end_io so once this cloned read completes, we can decrypt and send the original read along
                shallow_clone->bi_end_io = leader_read_disk_end_io;
                shallow_clone->bi_private = bio_data;

                // Block read if it conflicts with any other outstanding operations
                spin_lock(&device->index_lock);
                doesnt_conflict_with_other_writes = try_insert_into_outstanding_ops(device, shallow_clone);
                spin_unlock(&device->index_lock);

                if (doesnt_conflict_with_other_writes) {
                    submit_bio_noacct(shallow_clone);
                }
                break;
        }
    }

    // Anything we clone and submit ourselves is marked submitted
    return is_cloned ? DM_MAPIO_SUBMITTED : DM_MAPIO_REMAPPED;
}

unsigned char *enc_or_dec_bio(struct bio_data *bio_data, int enc_or_dec) {
    int ret = 0;
    struct bio_vec bv;
    uint64_t start_sector, curr_sector;
    struct aead_request *req;
    struct scatterlist sg[4];
    DECLARE_CRYPTO_WAIT(wait);
    unsigned char *bio_checksum_and_iv;
    unsigned char *iv;
    unsigned char *checksum;

    req = aead_request_alloc(bio_data->device->tfm, GFP_KERNEL);
    if (!req) {
        printk(KERN_ERR "aead request allocation failed");
        return NULL;
    }

    // Store new checksum and IV of write into array (instead of updating global checksum/iv) so the global checksum/iv can be updated in-order later
    if (enc_or_dec == WRITE) {
        bio_checksum_and_iv = alloc_bio_checksum_and_iv(bio_sectors(bio_data->bio_src));
#ifdef MEMORY_TRACKING
        atomic_inc(&bio_data->device->num_checksum_and_ivs);
#endif
        if (!bio_checksum_and_iv) {
            printk(KERN_ERR "Could not allocate checksum and iv for bio");
            goto free_and_return;
        }

        start_sector = bio_data->bio_src->bi_iter.bi_sector;
    }

    while (bio_data->bio_src->bi_iter.bi_size) {
        // printk(KERN_INFO "enc/dec starting");
        curr_sector = bio_data->bio_src->bi_iter.bi_sector;
        bv = bio_iter_iovec(bio_data->bio_src, bio_data->bio_src->bi_iter);

        switch (enc_or_dec) {
            case WRITE:
                checksum = get_bio_checksum(bio_checksum_and_iv, start_sector, curr_sector);
                iv = get_bio_iv(bio_checksum_and_iv, start_sector, curr_sector);
                break;
            case READ:
                checksum = global_checksum(bio_data->device, curr_sector);
                iv = global_iv(bio_data->device, curr_sector);
                // Skip decryption for any block that has not been written to
                if (!has_checksum(checksum)) {
                    goto enc_or_dec_next_sector;
                }
                break;
        }

        
        // TODO: Randomly generate IVs and don't hardcode
        // Set up scatterlist to encrypt/decrypt
        memcpy(iv, "123456789012", AES_GCM_IV_SIZE);
        sg_init_table(sg, 4);
        sg_set_buf(&sg[0], &curr_sector, sizeof(uint64_t));
        sg_set_buf(&sg[1], iv, AES_GCM_IV_SIZE);
        sg_set_page(&sg[2], bv.bv_page, ROLLBACCINE_ENCRYPTION_GRANULARITY, bv.bv_offset);
        sg_set_buf(&sg[3], checksum, AES_GCM_AUTH_SIZE);
        // TODO: If we're encrypting, return checksum and iv index, and only modify later in atomic context

        // /* AEAD request:
        //  *  |----- AAD -------|------ DATA -------|-- AUTH TAG --|
        //  *  | (authenticated) | (auth+encryption) |              |
        //  *  | sector_LE |  IV |  sector in/out    |  tag in/out  |
        //  */
        aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
        // sector + iv size
        aead_request_set_ad(req, sizeof(uint64_t) + AES_GCM_IV_SIZE);
        switch (enc_or_dec) {
            case WRITE:
                aead_request_set_crypt(req, sg, sg, ROLLBACCINE_ENCRYPTION_GRANULARITY, iv);
                ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
                break;
            case READ:
                aead_request_set_crypt(req, sg, sg, ROLLBACCINE_ENCRYPTION_GRANULARITY + AES_GCM_AUTH_SIZE, iv);
                ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
                break;
        }

        if (ret) {
            if (ret == -EBADMSG) {
                printk(KERN_ERR "invalid integrity check");
            } else {
                printk_ratelimited(KERN_ERR "encryption/decryption failed with error code %d", ret);
            }
            goto free_and_return;
        }

        enc_or_dec_next_sector:
        bio_advance_iter(bio_data->bio_src, &bio_data->bio_src->bi_iter, ROLLBACCINE_ENCRYPTION_GRANULARITY);
        reinit_completion(&wait.completion);
    }

    free_and_return:
    aead_request_free(req);
    return bio_checksum_and_iv; // NOTE: This will be NULL for reads
}

void kill_thread(struct socket *sock) {
    // Shut down the socket, causing the thread to unblock (if it was blocked on a socket)
    if (sock != NULL) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
    }
}

// Function used by all listening sockets to block and listen to messages
void blocking_read(struct rollbaccine_device *device, struct socket *sock) {
    struct metadata_msg metadata;
    struct bio *received_bio;
    struct bio_data *bio_data;
    struct page *page;
    struct msghdr msg_header;
    struct kvec vec;
    int sent, received, i;
#ifdef TLS_ON
    union {
        struct cmsghdr cmsg;
        u8 buf[CMSG_SPACE(sizeof(u8))];
    } u;
#endif

    msg_header.msg_name = 0;
    msg_header.msg_namelen = 0;
    msg_header.msg_flags = MSG_WAITALL | MSG_NOSIGNAL;
#ifdef TLS_ON
    msg_header.msg_control = &u;
    msg_header.msg_controllen = sizeof(u);
#else
    msg_header.msg_control = NULL;
    msg_header.msg_controllen = 0;
#endif

    while (!device->shutting_down) {
        // 1. Receive metadata message
        vec.iov_base = &metadata;
        vec.iov_len = sizeof(struct metadata_msg);

        received = kernel_recvmsg(sock, &msg_header, &vec, vec.iov_len, vec.iov_len, msg_header.msg_flags);
        if (received <= 0) {
            printk(KERN_ERR "Error reading from socket");
            break;
        }

#ifdef TLS_ON
        // Handle the TLS control messages.
        if (msg_header.msg_controllen != sizeof(u)) {
            switch (tls_get_record_type(sock->sk, &u.cmsg)) {
                case 0:
                    fallthrough;
                case TLS_RECORD_TYPE_DATA:
                    // printk(KERN_INFO "We got some TLS control msg but it's all good");
                    break;
                case TLS_RECORD_TYPE_ALERT:
                    printk(KERN_ERR "TLS alert received. Uhoh.");
                    break;
                default:
                    break;
            }
        }
#endif

        // printk(KERN_INFO "Received metadata sector: %llu, num pages: %llu, bi_opf: %llu, is fsync: %llu", metadata.sector, metadata.num_pages, metadata.bi_opf, metadata.bi_opf&(REQ_PREFLUSH |
        // REQ_FUA));

        // Received ack for fsync
        if (metadata.type == FOLLOWER_ACK && device->is_leader) {
            // printk(KERN_INFO "Received fsync ack for write index: %llu", metadata.write_index);
            process_follower_fsync_index(device, metadata.bal.id, metadata.write_index);
            continue;
        }

        received_bio = bio_alloc_bioset(device->dev->bdev, metadata.num_pages, metadata.bi_opf, GFP_NOIO, &device->bs);
        received_bio->bi_iter.bi_sector = metadata.sector;
        received_bio->bi_end_io = replica_disk_end_io;

        bio_data = alloc_bio_data(device);
        bio_data->device = device;
        bio_data->write_index = metadata.write_index;
        received_bio->bi_private = bio_data;

        // 2. Expect hash next
        // 3. Receive pages of bio
        for (i = 0; i < metadata.num_pages; i++) {
            page = page_cache_alloc(device);
            // page = alloc_page(GFP_KERNEL);
            // if (page == NULL) {
            //     printk(KERN_ERR "Error allocating page");
            //     break;
            // }
#ifdef MEMORY_TRACKING
            atomic_inc(&device->num_bio_pages_not_freed);
#endif
            vec.iov_base = page_address(page);
            vec.iov_len = PAGE_SIZE;

            received = kernel_recvmsg(sock, &msg_header, &vec, vec.iov_len, vec.iov_len, msg_header.msg_flags);
            if (received <= 0) {
                printk(KERN_ERR "Error reading from socket");
                break;
            }
            // printk(KERN_INFO "Received bio page: %i", i);
            __bio_add_page(received_bio, page, PAGE_SIZE, 0);
        }

        // 4. Verify against hash

        // 5. If the message is an fsync, reply.
        if (metadata.type == ROLLBACCINE_FSYNC) {
            metadata.type = FOLLOWER_ACK;
            metadata.bal.id = device->bal.id;

            vec.iov_base = &metadata;
            vec.iov_len = sizeof(struct metadata_msg);

#ifdef TLS_ON
            // Clear TLS message headers (not populated by us) before responding
            msg_header.msg_name = 0;
            msg_header.msg_namelen = 0;
            msg_header.msg_control = NULL;
            msg_header.msg_controllen = 0;
            msg_header.msg_flags = 0;
#endif

            // Keep retrying send until the whole message is sent
            while (vec.iov_len > 0) {
                sent = kernel_sendmsg(sock, &msg_header, &vec, 1, vec.iov_len);
                if (sent <= 0) {
                    printk(KERN_ERR "Error replying to fsync, aborting");
                    break;
                } else {
                    vec.iov_base += sent;
                    vec.iov_len -= sent;
                }
            }
            // printk(KERN_INFO "Acked fsync for write index: %llu", metadata.write_index);
        }

        // 6. Submit bio, if there are no conflicts. Otherwise blocks and waits for a finished bio to unblock it.
        if (try_insert_into_outstanding_ops(device, received_bio)) {
            // TODO: Get checksum and IV and update global
            submit_bio_noacct(received_bio);
        }
    }

    printk(KERN_INFO "Shutting down, exiting blocking read");
    kernel_sock_shutdown(sock, SHUT_RDWR);
    // TODO: Releasing the socket is problematic because it makes future calls to shutdown() crash, which may happen if the connection dies, the socket is freed, and later the destructor tries to shut
    // it down.
    //     sock_release(sock);
}

#ifdef TLS_ON
void on_tls_handshake_done(void *data, int status, key_serial_t peerid) {
    struct completion *tls_handshake_completed = data;

    if (status != 0) {
        printk(KERN_ERR "TLS handshake failed with status %d", status);
    }

    complete(tls_handshake_completed);
}
#endif

int connect_to_server(void *args) {
    struct client_thread_params *thread_params = (struct client_thread_params *)args;
    struct socket_list *sock_list;
    int error = -1;
#ifdef TLS_ON
    struct tls_handshake_args tls_args;
    struct completion tls_handshake_completed;
    struct file *sock_file;
    unsigned long timeout_remainder;
#endif

    // Retry connecting to server until it succeeds
    printk(KERN_INFO "Attempting to connect for the first time");
    while (error != 0 && !thread_params->device->shutting_down) {
        error = kernel_connect(thread_params->sock, (struct sockaddr *)&thread_params->addr, sizeof(thread_params->addr), 0);
        if (error != 0) {
            printk(KERN_ERR "Error connecting to server, retrying...");
            msleep(ROLLBACCINE_RETRY_TIMEOUT);
        }
    }

    if (thread_params->device->shutting_down) {
        goto cleanup;
    }
    printk(KERN_INFO "Connected to server");

    // Add this socket to the list of connected sockets
    sock_list = kmalloc(sizeof(struct socket_list), GFP_KERNEL);
    if (sock_list == NULL) {
        printk(KERN_ERR "Error creating socket_list");
        goto cleanup;
    }
    sock_list->sock = thread_params->sock;
    mutex_lock(&thread_params->device->connected_sockets_lock);
    list_add(&sock_list->list, &thread_params->device->connected_sockets);
    mutex_unlock(&thread_params->device->connected_sockets_lock);

#ifdef TLS_ON
    // TLS setup
    printk(KERN_INFO "Client starting TLS handshake");
    sock_file = sock_alloc_file(thread_params->sock, O_NONBLOCK, NULL);
    if (IS_ERR(sock_file)) {
        printk(KERN_ERR "Error creating file from socket");
    }
    // TODO: Free the sock_file. Has the same problem with freeing as sock_release()
    init_completion(&tls_handshake_completed);
    tls_args.ta_sock = thread_params->sock;
    tls_args.ta_done = on_tls_handshake_done;
    tls_args.ta_data = &tls_handshake_completed;
    error = tls_client_hello_x509(&tls_args, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Client error starting TLS handshake: %d", error);
        return 0;
    } else {
        // Wait until TLS handshake is done
        printk(KERN_INFO "Client waiting for TLS handshake to complete");
        timeout_remainder = wait_for_completion_timeout(&tls_handshake_completed, ROLLBACCINE_TLS_TIMEOUT);
        if (!timeout_remainder) {
            printk(KERN_ERR "Client TLS handshake timed out");
            return 0;
        } else {
            printk(KERN_INFO "Client TLS handshake completed");
        }
    }
#endif

    blocking_read(thread_params->device, thread_params->sock);

cleanup:
    kfree(thread_params);
    return 0;
}

int start_client_to_server(struct rollbaccine_device *device, char *addr, ushort port) {
    struct socket_list *sock_list;
    struct client_thread_params *thread_params;
    struct task_struct *connect_thread;
    int error;

    thread_params = kmalloc(sizeof(struct client_thread_params), GFP_KERNEL);
    if (thread_params == NULL) {
        printk(KERN_ERR "Error creating client thread params");
        return -1;
    }
    thread_params->device = device;

    error = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &thread_params->sock);
    if (error < 0) {
        printk(KERN_ERR "Error creating client socket");
        return error;
    }

    // Set sockaddr_in
    memset(&thread_params->addr, 0, sizeof(thread_params->addr));
    thread_params->addr.sin_family = AF_INET;
    // Instead of using inet_addr(), which we don't have access to, use in4_pton() to convert IP address from string
    if (in4_pton(addr, strlen(addr) + 1, (u8 *)&thread_params->addr.sin_addr.s_addr, '\n', NULL) == 0) {
        printk(KERN_ERR "Error converting IP address");
        return -1;
    }
    thread_params->addr.sin_port = htons(port);

    // Add this socket to the list so we can close it later in order to shut the thread down
    sock_list = kmalloc(sizeof(struct socket_list), GFP_KERNEL);
    if (sock_list == NULL) {
        printk(KERN_ERR "Error creating sock_list");
        return -1;
    }
    sock_list->sock = thread_params->sock;
    list_add(&sock_list->list, &device->client_sockets);

    // start a thread for this connection
    connect_thread = kthread_run(connect_to_server, thread_params, "connect to server");
    if (IS_ERR(connect_thread)) {
        printk(KERN_ERR "Error creating connect to server thread.");
        return -1;
    }

    return 0;
}

int listen_to_accepted_socket(void *args) {
    struct accepted_thread_params *thread_params = (struct accepted_thread_params *)args;
#ifdef TLS_ON
    struct tls_handshake_args tls_args;
    struct completion tls_handshake_completed;
    struct file *sock_file;
    unsigned long timeout_remainder;
    int error;

    // TLS setup
    printk(KERN_INFO "Server starting TLS handshake");
    sock_file = sock_alloc_file(thread_params->sock, O_NONBLOCK, NULL);
    if (IS_ERR(sock_file)) {
        printk(KERN_ERR "Error creating file from socket");
    }
    // TODO: Free the sock_file. Has the same problem with freeing as sock_release()
    init_completion(&tls_handshake_completed);
    tls_args.ta_sock = thread_params->sock;
    tls_args.ta_done = on_tls_handshake_done;
    tls_args.ta_data = &tls_handshake_completed;
    error = tls_server_hello_x509(&tls_args, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Server error starting TLS handshake: %d", error);
        return 0;
    } else {
        // Wait until TLS handshake is done
        timeout_remainder = wait_for_completion_timeout(&tls_handshake_completed, ROLLBACCINE_TLS_TIMEOUT);
        if (!timeout_remainder) {
            printk(KERN_ERR "Server TLS handshake timed out");
            return 0;
        } else {
            printk(KERN_INFO "Server TLS handshake completed");
        }
    }
#endif

    blocking_read(thread_params->device, thread_params->sock);

    printk(KERN_INFO "Exiting listen to accepted socket");
    kfree(thread_params);
    return 0;
}

// Thread that listens to connecting clients
int listen_for_connections(void *args) {
    struct listen_thread_params *thread_params = (struct listen_thread_params *)args;
    struct rollbaccine_device *device = thread_params->device;
    struct socket *new_sock;
    struct accepted_thread_params *new_thread_params;
    struct socket_list *new_server_socket_list;
    struct socket_list *new_connected_socket_list;
    struct task_struct *accepted_thread;
    int error;

    while (!device->shutting_down) {
        // Blocks until a connection is accepted
        error = kernel_accept(thread_params->sock, &new_sock, 0);
        if (error < 0) {
            printk(KERN_ERR "Error accepting connection");
            continue;
        }
        printk(KERN_INFO "Accepted connection");

        // Create parameters for the new thread
        new_thread_params = kmalloc(sizeof(struct accepted_thread_params), GFP_KERNEL);
        if (new_thread_params == NULL) {
            printk(KERN_ERR "Error creating accepted thread params");
            break;
        }
        new_thread_params->sock = new_sock;
        new_thread_params->device = device;

        // Add to list of connected sockets
        new_connected_socket_list = kmalloc(sizeof(struct socket_list), GFP_KERNEL);
        if (new_connected_socket_list == NULL) {
            printk(KERN_ERR "Error creating socket_list");
            break;
        }
        new_connected_socket_list->sock = new_sock;
        mutex_lock(&device->connected_sockets_lock);
        list_add(&new_connected_socket_list->list, &device->connected_sockets);
        mutex_unlock(&device->connected_sockets_lock);

        // Add to list of server sockets
        new_server_socket_list = kmalloc(sizeof(struct socket_list), GFP_KERNEL);
        if (new_server_socket_list == NULL) {
            printk(KERN_ERR "Error creating socket_list");
            break;
        }
        new_server_socket_list->sock = new_sock;
        // Note: No locks needed here, because only the listener thread writes this list
        list_add(&new_server_socket_list->list, &device->server_sockets);

        accepted_thread = kthread_run(listen_to_accepted_socket, new_thread_params, "listen to accepted socket");
        if (IS_ERR(accepted_thread)) {
            printk(KERN_ERR "Error creating accepted thread.");
            break;
        }
    }

    kernel_sock_shutdown(thread_params->sock, SHUT_RDWR);
    // TODO: Releasing the socket is problematic because it makes future calls to shutdown() crash, which may happen if the connection dies, the socket is freed, and later the destructor tries to shut
    // it down.
    //     sock_release(thread_params->sock);
    kfree(thread_params);
    return 0;
}

// Returns error code if it fails
int start_server(struct rollbaccine_device *device, ushort port) {
    struct listen_thread_params *thread_params;
    struct socket_list *sock_list;
    struct sockaddr_in addr;
    struct task_struct *listener_thread;
    int error;
    int opt = 1;
    sockptr_t kopt = {.kernel = (char *)&opt, .is_kernel = 1};

    // Create struct to pass parameters to listener thread
    thread_params = kmalloc(sizeof(struct listen_thread_params), GFP_KERNEL);
    if (thread_params == NULL) {
        printk(KERN_ERR "Error creating listen_thread_params");
        return -1;
    }
    thread_params->device = device;

    // Create struct to add the socket to the list of sockets
    sock_list = kmalloc(sizeof(struct socket_list), GFP_KERNEL);
    if (sock_list == NULL) {
        printk(KERN_ERR "Error creating socket_list");
        return -1;
    }

    error = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &thread_params->sock);
    if (error < 0) {
        printk(KERN_ERR "Error creating server socket");
        return error;
    }

    // Add the newly created socket to our list of sockets
    sock_list->sock = thread_params->sock;
    list_add(&sock_list->list, &device->server_sockets);

    // TCP nodelay
    error = thread_params->sock->ops->setsockopt(thread_params->sock, SOL_TCP, TCP_NODELAY, kopt, sizeof(opt));
    if (error < 0) {
        printk(KERN_ERR "Error setting TCP_NODELAY");
        return error;
    }

    error = sock_setsockopt(thread_params->sock, SOL_SOCKET, SO_REUSEPORT, kopt, sizeof(opt));
    if (error < 0) {
        printk(KERN_ERR "Error setting SO_REUSEPORT");
        return error;
    }

    // Set sockaddr_in
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    error = kernel_bind(thread_params->sock, (struct sockaddr *)&addr, sizeof(addr));
    if (error < 0) {
        printk(KERN_ERR "Error binding socket");
        return error;
    }

    error = kernel_listen(thread_params->sock, ROLLBACCINE_MAX_CONNECTIONS);
    if (error < 0) {
        printk(KERN_ERR "Error listening on socket");
        return error;
    }

    // Listen for connections
    listener_thread = kthread_run(listen_for_connections, thread_params, "listener");
    if (IS_ERR(listener_thread)) {
        printk(KERN_ERR "Error creating listener thread");
        return -1;
    }

    return 0;
}

static void rollbaccine_status(struct dm_target *ti, status_type_t type, unsigned int status_flags, char *result, unsigned int maxlen) {
    struct rollbaccine_device *device = ti->private;
    unsigned int sz = 0;  // Required by DMEMIT

    DMEMIT("\n");

#ifndef MEMORY_TRACKING
    DMEMIT("Memory tracking is NOT ON! The following statistics will be unreliable.\n");
#endif
    DMEMIT("Num bio pages not freed: %d\n", atomic_read(&device->num_bio_pages_not_freed));
    DMEMIT("Num bio_data not freed: %d\n", atomic_read(&device->num_bio_data_not_freed));
    DMEMIT("Num deep clones not freed: %d\n", atomic_read(&device->num_deep_clones_not_freed));
    DMEMIT("Num shallow clones not freed: %d\n", atomic_read(&device->num_shallow_clones_not_freed));
    DMEMIT("Num rb nodes still in tree: %d\n", device->num_rb_nodes);
    DMEMIT("Num bio sectors still in queue: %d\n", device->num_bio_sector_ranges);
    DMEMIT("Num fsyncs still pending replication: %d\n", device->num_fsyncs_pending_replication);
    DMEMIT("Num checksums and IVs not freed: %d\n", atomic_read(&device->num_checksum_and_ivs));
    DMEMIT("Max outstanding num bio pages: %d\n", atomic_read(&device->max_outstanding_num_bio_pages));
    DMEMIT("Max outstanding num bio_data: %d\n", atomic_read(&device->max_outstanding_num_bio_data));
    DMEMIT("Max outstanding num deep clones: %d\n", atomic_read(&device->max_outstanding_num_deep_clones));
    DMEMIT("Max outstanding num shallow clones: %d\n", atomic_read(&device->max_outstanding_num_shallow_clones));
    DMEMIT("Max size of rb tree for outgoing operations: %d\n", device->max_outstanding_num_rb_nodes);
    DMEMIT("Max number of conflicting operations: %d\n", device->max_outstanding_num_bio_sector_ranges);
    DMEMIT("Max number of fsyncs pending replication: %d\n", device->max_outstanding_fsyncs_pending_replication);
}

// Arguments: 0 = underlying device name, like /dev/ram0. 1 = f, 2 = n, 3 = id, 4 = is_leader. 5 = listen port. 6+ = server addr & ports
static int rollbaccine_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    struct rollbaccine_device *device;
    ushort port;
    int error;
    int i;
    unsigned long projected_bytes_used = 0;

    device = kmalloc(sizeof(struct rollbaccine_device), GFP_KERNEL);
    if (device == NULL) {
        printk(KERN_ERR "Error creating device");
        return -ENOMEM;
    }

    bioset_init(&device->bs, 0, 0, BIOSET_NEED_BVECS);
    device->bio_data_cache = kmem_cache_create("bio_data", sizeof(struct bio_data), 0, 0, NULL);
    spin_lock_init(&device->page_cache_lock);
    device->page_cache = NULL;
    device->page_cache_size = 0;

    device->shutting_down = false;
    mutex_init(&device->connected_sockets_lock);

    device->broadcast_queue = alloc_ordered_workqueue("broadcast queue", 0);
    if (!device->broadcast_queue) {
        printk(KERN_ERR "Cannot allocate broadcast queue");
        return -ENOMEM;
    }

    // Get the device from argv[0] and store it in device->dev
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &device->dev)) {
        printk(KERN_ERR "Error getting device");
        return -ENOMEM;
    }

    error = kstrtoint(argv[1], 10, &device->f);
    if (error < 0) {
        printk(KERN_ERR "Error parsing f");
        return error;
    }
    printk(KERN_INFO "f: %i", device->f);

    error = kstrtoint(argv[2], 10, &device->n);
    if (error < 0) {
        printk(KERN_ERR "Error parsing n");
        return error;
    }
    printk(KERN_INFO "n: %i", device->n);

    error = kstrtou64(argv[3], 10, &device->bal.id);
    if (error < 0) {
        printk(KERN_ERR "Error parsing id");
        return error;
    }
    printk(KERN_INFO "id: %llu", device->bal.id);
    device->bal.num = 0;
    device->write_index = ROLLBACCINE_INIT_WRITE_INDEX;
    spin_lock_init(&device->index_lock);

    device->max_replica_fsync_index = ROLLBACCINE_INIT_WRITE_INDEX;
    spin_lock_init(&device->replica_fsync_lock);
    device->replica_fsync_indices = kzalloc(sizeof(int) * device->n, GFP_KERNEL);
    bio_list_init(&device->fsyncs_pending_replication);

    device->outstanding_ops = RB_ROOT;
    INIT_LIST_HEAD(&device->pending_ops);
    device->processing_pending_ops = false;

    device->is_leader = strcmp(argv[4], "true") == 0;

    // Start server
    error = kstrtou16(argv[5], 10, &port);
    if (error < 0) {
        printk(KERN_ERR "Error parsing port");
        return error;
    }
    printk(KERN_INFO "Starting server at port: %u", port);

    INIT_LIST_HEAD(&device->connected_sockets);
    INIT_LIST_HEAD(&device->server_sockets);
    error = start_server(device, port);
    if (error < 0) {
        printk(KERN_ERR "Error starting server");
        return error;
    }

    // Connect to other servers. argv[6], argv[7], etc are all server addresses and ports to connect to.
    INIT_LIST_HEAD(&device->client_sockets);
    for (i = 6; i < argc; i += 2) {
        error = kstrtou16(argv[i + 1], 10, &port);
        if (error < 0) {
            printk(KERN_ERR "Error parsing port");
            return error;
        }
        printk(KERN_INFO "Starting thread to connect to server at port: %u", port);
        start_client_to_server(device, argv[i], port);
    }

    // Set up AEAD
    device->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(device->tfm)) {
        printk(KERN_ERR "Error allocating AEAD");
        return PTR_ERR(device->tfm);
    }
    crypto_aead_setauthsize(device->tfm, AES_GCM_AUTH_SIZE);

    // TODO: Accept key as input
    device->key = "1234567890123456";
    error = crypto_aead_setkey(device->tfm, device->key, KEY_SIZE);
    if (error < 0) {
        printk(KERN_ERR "Error setting key");
        return error;
    }

    device->checksums = kvmalloc_array(ti->len * SECTOR_SIZE / ROLLBACCINE_ENCRYPTION_GRANULARITY, AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE, GFP_KERNEL | __GFP_ZERO);
    if (device->checksums == NULL) {
        printk(KERN_ERR "Error allocating checksums");
        return -ENOMEM;
    }
    projected_bytes_used += ti->len * SECTOR_SIZE / ROLLBACCINE_ENCRYPTION_GRANULARITY * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE);

#ifdef MEMORY_TRACKING
    atomic_set(&device->num_bio_data_not_freed, 0);
    atomic_set(&device->num_bio_pages_not_freed, 0);
    atomic_set(&device->num_deep_clones_not_freed, 0);
    atomic_set(&device->num_shallow_clones_not_freed, 0);
    device->num_rb_nodes = 0;
    device->num_bio_sector_ranges = 0;
    device->num_fsyncs_pending_replication = 0;
    atomic_set(&device->num_checksum_and_ivs, 0);
    atomic_set(&device->max_outstanding_num_bio_data, 0);
    atomic_set(&device->max_outstanding_num_bio_pages, 0);
    atomic_set(&device->max_outstanding_num_deep_clones, 0);
    atomic_set(&device->max_outstanding_num_shallow_clones, 0);
    device->max_outstanding_num_rb_nodes = 0;
    device->max_outstanding_num_bio_sector_ranges = 0;
    device->max_outstanding_fsyncs_pending_replication = 0;
#endif

    // Enable FUA and PREFLUSH flags
    ti->num_flush_bios = 1;
    ti->flush_supported = 1;

    ti->private = device;

    printk(KERN_INFO "Server %llu constructed, projected to use %luMB", device->bal.id, projected_bytes_used >> 20);
    return 0;
}

static void rollbaccine_destructor(struct dm_target *ti) {
    struct socket_list *curr, *next;
    struct rollbaccine_device *device = ti->private;
    if (device == NULL) return;

    // Warning: Changing this boolean should technically be atomic. I don't think it's a big deal tho, since by the time shutting_down is true, we don't care what the protocol does. *Ideally* it shuts
    // down gracefully.
    device->shutting_down = true;

    // Kill threads
    printk(KERN_INFO "Killing server sockets");
    list_for_each_entry_safe(curr, next, &device->server_sockets, list) {
        kill_thread(curr->sock);
        list_del(&curr->list);
        kfree(curr);
    }
    printk(KERN_INFO "Killing client sockets");
    list_for_each_entry_safe(curr, next, &device->client_sockets, list) {
        kill_thread(curr->sock);
        list_del(&curr->list);
        kfree(curr);
    }

    // Free socket list (sockets should already be freed)
    list_for_each_entry_safe(curr, next, &device->connected_sockets, list) {
        list_del(&curr->list);
        kfree(curr);
    }

    kvfree(device->checksums);
    crypto_free_aead(device->tfm);
    // Note: I'm not sure how to free theses queues which may have outstanding bios. Hopefully nothing breaks horribly
    destroy_workqueue(device->broadcast_queue);
    dm_put_device(ti, device->dev);
    bioset_exit(&device->bs);
    kmem_cache_destroy(device->bio_data_cache);
    page_cache_destroy(device);
    kfree(device);

    printk(KERN_INFO "Server destructed");
}

static struct target_type rollbaccine_target = {
    .name = MODULE_NAME,
    .version = {0, 1, 0},
    .features = DM_TARGET_INTEGRITY,  // TODO: Figure out what this means
    .module = THIS_MODULE,
    .ctr = rollbaccine_constructor,
    .dtr = rollbaccine_destructor,
    .map = rollbaccine_map,
    .status = rollbaccine_status,
};

int __init rollbaccine_init_module(void) {
    int r = dm_register_target(&rollbaccine_target);
    printk(KERN_INFO "rollbaccine module loaded");
    return r;
}

void rollbaccine_exit_module(void) {
    dm_unregister_target(&rollbaccine_target);
    printk(KERN_INFO "rollbaccine module unloaded");
}

module_init(rollbaccine_init_module);
module_exit(rollbaccine_exit_module);
MODULE_LICENSE("GPL");