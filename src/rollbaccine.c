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
#include <linux/timex.h>
#include <linux/vmalloc.h>
#include <net/sock.h>

#define ROLLBACCINE_MAX_CONNECTIONS 10
#define ROLLBACCINE_RETRY_TIMEOUT 5000  // Number of milliseconds before client attempts to connect to a server again
#define ROLLBACCINE_INIT_WRITE_INDEX 0
#define ROLLBACCINE_ENCRYPTION_GRANULARITY PAGE_SIZE
// #define ROLLBACCINE_ENCRYPTION_GRANULARITY SECTOR_SIZE
#define ROLLBACCINE_SECTORS_PER_ENCRYPTION (ROLLBACCINE_ENCRYPTION_GRANULARITY / SECTOR_SIZE)
#define SECTORS_PER_PAGE (PAGE_SIZE / SECTOR_SIZE)
#define AES_GCM_IV_SIZE 12
#define AES_GCM_AUTH_SIZE 16
#define KEY_SIZE 16
#define ROLLBACCINE_AVG_HASHES_PER_WRITE 4
#define ROLLBACCINE_METADATA_CHECKSUM_IV_SIZE (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE) * ROLLBACCINE_AVG_HASHES_PER_WRITE
#define SHA256_SIZE 32
#define MODULE_NAME "rollbaccine"

// #define MULTITHREADED_NETWORK
#define MEMORY_TRACKING  // Check the number of mallocs/frees and see if we're leaking memory
// #define LATENCY_TRACKING

// Used to compare against checksums to see if they have been set yet (or if they're all 0)
static const char ZERO_AUTH[AES_GCM_AUTH_SIZE] = {0};

// TODO: Expand with protocol message types
enum MsgType { ROLLBACCINE_WRITE, ROLLBACCINE_FSYNC, FOLLOWER_ACK };
enum EncDecType { ROLLBACCINE_ENCRYPT, ROLLBACCINE_DECRYPT, ROLLBACCINE_VERIFY };

// Note: These message types are sent over network, so they need to be packed & int sizes need to be specific
struct ballot {
    uint64_t id;
    uint64_t num;
} __attribute__((packed));

struct metadata_msg {
    char msg_hash[SHA256_SIZE];
    enum MsgType type;
    struct ballot bal;
    uint64_t sender_id;
    uint64_t msg_index;
    uint64_t write_index;
    uint64_t num_pages;

    // Metadata about the bio
    uint64_t bi_opf;
    sector_t sector;
    // Hash and IV for each write
    char checksum_and_iv[ROLLBACCINE_METADATA_CHECKSUM_IV_SIZE];
} __attribute__((packed));

// Flexible array since we don't know how many extra checksums we will include. Be very careful when using sizeof()
struct additional_hash_msg {
    char msg_hash[SHA256_SIZE];
    uint64_t sender_id;
    uint64_t msg_index;
    char checksum_and_iv[];
};

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

    // For limiting the amount of memory used. Do not access ints without obtaining the waitqueue lock.
    wait_queue_head_t memory_wait_queue;
    int max_memory_pages;
    int num_used_memory_pages;

    bool is_leader;
    bool shutting_down;  // Set to true when user triggers shutdown. All threads check this and abort if true. Used instead of kthread_should_stop(), since the function that flips that boolean to true (kthread_stop()) is blocking, which creates a race condition when we kill the socket & also wait for the thread to stop.
    int f;
    int n;
    uint64_t id;

    struct ballot bal;
    int write_index;
    // TODO: Track last msg index per unique sender (since the primary may change)
    uint64_t last_sent_msg_index;     // Doesn't need to be atomic because only the broadcast thread will modify this
    uint64_t next_incoming_msg_index;
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

    // Communication between main threads and the networking thread
    struct workqueue_struct *broadcast_queue;
    // Workqueue to submit pending bios because bio_endio can't submit work (because it might sleep)
    struct workqueue_struct *submit_bio_queue;

    // Sockets, tracked so we can kill them on exit.
    struct list_head server_sockets;
    struct list_head client_sockets;
    // Connected sockets. Should be a subset of the sockets above. Handy for broadcasting
    // TODO: Need to figure out network handshake so we know who we're talking to.
    struct mutex connected_sockets_lock;
    struct list_head connected_sockets;

    // AEAD
    struct crypto_aead *tfm;
    char *checksums;
    struct page *verification_page;

    // Hashing
    struct mutex hash_mutex;
    struct crypto_shash *hash_alg;
    struct shash_desc *hash_desc;

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
    atomic_t num_bios_on_broadcast_queue;
    // These counters tell us the maximum amount of memory we need to prealloc
    atomic_t max_outstanding_num_bio_pages;
    atomic_t max_outstanding_num_bio_data;
    atomic_t max_outstanding_num_shallow_clones;
    atomic_t max_outstanding_num_deep_clones;
    int max_outstanding_num_rb_nodes;
    int max_outstanding_num_bio_sector_ranges;
    int max_outstanding_fsyncs_pending_replication;
    int max_num_pages_in_memory;
    atomic_t max_bios_on_broadcast_queue;
#endif
};

// Associated data for each bio, shared between clones
struct bio_data {
    struct rollbaccine_device *device;
    struct bio *bio_src;
    struct bio *deep_clone; // Only present in leader, for broadcasting
    struct bio *shallow_clone; // Only present in leader, for submitting to disk with a different end_io
    sector_t start_sector; // Start: For checking against conflicts. These values may change after the bio is submitted, so store them here
    sector_t end_sector;
    int write_index;
    bool is_fsync;
    atomic_t ref_counter;               // The number of clones. Once it hits 0, the bio can be freed
    struct work_struct broadcast_work;  // So this bio can be scheduled as a job
    struct work_struct submit_bio_work; // So this bio can be scheduled for submission after popping off pending ops
    struct rb_node tree_node;           // So this bio can be inserted into a tree
    struct list_head pending_list;      // So this bio can be inserted into pending_ops
    unsigned char *checksum_and_iv;     // Checksums and IVs for each sector or page, if this is a write
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

void print_and_update_latency(char *text, cycles_t *prev_time);  // Also updates prev_time
void submit_bio_task(struct work_struct *work);
void add_to_pending_ops_tail(struct rollbaccine_device *device, struct bio_data *bio_data);
// Returns true if the insert was successful, false if there's a conflict
bool try_insert_into_outstanding_ops(struct rollbaccine_device *device, struct bio_data *bio_data, bool check_pending); 
void remove_from_outstanding_ops_and_unblock(struct rollbaccine_device *device, struct bio *shallow_clone);
void page_cache_free(struct rollbaccine_device *device, struct page *page_to_free);
void page_cache_destroy(struct rollbaccine_device *device);
struct page *page_cache_alloc(struct rollbaccine_device *device);
void atomic_max(atomic_t *old, int new);
void block_if_not_enough_memory(struct rollbaccine_device *device, int num_pages_needed);
void release_memory(struct rollbaccine_device *device, int num_pages_released);
struct bio_data *alloc_bio_data(struct rollbaccine_device * device);
void ack_bio_to_user_without_executing(struct bio * bio);
void process_follower_fsync_index(struct rollbaccine_device * device, int follower_id, int follower_fsync_index);
bool requires_fsync(struct bio * bio);
unsigned int remove_fsync_flags(unsigned int bio_opf);
void free_pages_end_io(struct bio * received_bio);
void try_free_clones(struct bio * clone);
void leader_write_disk_end_io(struct bio * shallow_clone);
void leader_read_disk_end_io(struct bio * shallow_clone);
void replica_disk_end_io(struct bio * received_bio);
void network_end_io(struct bio * deep_clone);
void broadcast_bio(struct work_struct * work);
struct bio *shallow_bio_clone(struct rollbaccine_device * device, struct bio * bio_src);
struct bio *deep_bio_clone(struct rollbaccine_device * device, struct bio * bio_src);
bool verify_msg(struct rollbaccine_device *device, void *msg, size_t msg_size, char *expected_hash, uint64_t msg_index);
void hash_buffer(struct rollbaccine_device *device, char *buffer, size_t len, char *out);
// Returns array of checksums and IVs for writes, NULL for reads
unsigned char *enc_or_dec_bio(struct bio_data * bio_data, enum EncDecType type);
void kill_thread(struct socket * sock);
void blocking_read(struct rollbaccine_device * device, struct socket *sock);
int connect_to_server(void *args);
int start_client_to_server(struct rollbaccine_device *device, char *addr, ushort port);
int listen_to_accepted_socket(void *args);
int listen_for_connections(void *args);
int start_server(struct rollbaccine_device *device, ushort port);
int __init rollbaccine_init_module(void);
void rollbaccine_exit_module(void);

inline void *alloc_additional_hash_msg(struct rollbaccine_device *device, size_t checksum_and_iv_size) { return kmalloc(sizeof(struct additional_hash_msg) + checksum_and_iv_size, GFP_KERNEL); }

inline size_t additional_hash_msg_size(size_t checksum_and_iv_size) { return sizeof(struct additional_hash_msg) + checksum_and_iv_size; }

inline bool has_checksum(unsigned char *checksum) {
    return memcmp(checksum, ZERO_AUTH, AES_GCM_AUTH_SIZE) != 0;
}

inline unsigned char *global_checksum(struct rollbaccine_device *device, sector_t sector) {
    return &device->checksums[sector / ROLLBACCINE_SECTORS_PER_ENCRYPTION * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE)];
}

inline unsigned char *global_iv(struct rollbaccine_device *device, sector_t sector) {
    return &device->checksums[sector / ROLLBACCINE_SECTORS_PER_ENCRYPTION * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE) + AES_GCM_AUTH_SIZE];
}

inline size_t bio_checksum_and_iv_size(int num_sectors) {
    return num_sectors / ROLLBACCINE_SECTORS_PER_ENCRYPTION * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE);
}

inline unsigned char *alloc_bio_checksum_and_iv(struct rollbaccine_device *device, int num_sectors) {
    if (num_sectors != 0) {
#ifdef MEMORY_TRACKING
        atomic_inc(&device->num_checksum_and_ivs);
#endif
        return kmalloc(bio_checksum_and_iv_size(num_sectors), GFP_KERNEL);
    } else {
        return NULL;
    }
}

inline unsigned char *get_bio_checksum(unsigned char *checksum_and_iv, sector_t start_sector, sector_t current_sector) {
    return &checksum_and_iv[(current_sector - start_sector) / ROLLBACCINE_SECTORS_PER_ENCRYPTION * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE)];
}

inline unsigned char *get_bio_iv(unsigned char *checksum_and_iv, sector_t start_sector, sector_t current_sector) {
    return &checksum_and_iv[(current_sector - start_sector) / ROLLBACCINE_SECTORS_PER_ENCRYPTION * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE) + AES_GCM_AUTH_SIZE];
}

inline void update_global_checksum_and_iv(struct rollbaccine_device *device, unsigned char *checksum_and_iv, sector_t start_sector, int num_sectors) {
    sector_t curr_sector;
    for (curr_sector = start_sector; curr_sector < start_sector + num_sectors; curr_sector += ROLLBACCINE_SECTORS_PER_ENCRYPTION) {
        memcpy(global_checksum(device, curr_sector), get_bio_checksum(checksum_and_iv, start_sector, curr_sector), AES_GCM_AUTH_SIZE);
        memcpy(global_iv(device, curr_sector), get_bio_iv(checksum_and_iv, start_sector, curr_sector), AES_GCM_IV_SIZE);
    }
}

inline cycles_t get_cycles_if_flag_on(void) {
#ifdef LATENCY_TRACKING
    return get_cycles();
#else
    return 0;
#endif
}

void print_and_update_latency(char *text, cycles_t *prev_time) {
#ifdef LATENCY_TRACKING
    cycles_t curr_time = get_cycles_if_flag_on();
    cycles_t diff = curr_time - *prev_time;
    // Anything with a fewer number of cycles is not important enough to print
    if (diff > 10000) {
        printk(KERN_INFO "%s: %llu cycles", text, diff);
    }
    *prev_time = get_cycles_if_flag_on();
#endif
}

void submit_bio_task(struct work_struct *work) {
    struct bio_data *bio_data = container_of(work, struct bio_data, submit_bio_work);
    struct rollbaccine_device *device = bio_data->device;
    // printk(KERN_INFO "Submitting bio from workqueue: %d", bio_data->write_index);

    if (bio_data->checksum_and_iv != NULL) {
        update_global_checksum_and_iv(device, bio_data->checksum_and_iv, bio_data->start_sector, bio_data->end_sector - bio_data->start_sector);
    }
    if (bio_data->shallow_clone != NULL) {
        submit_bio_noacct(bio_data->shallow_clone);
    }
    else {
        submit_bio_noacct(bio_data->bio_src);
    }
}

void add_to_pending_ops_tail(struct rollbaccine_device *device, struct bio_data *bio_data) {
#ifdef MEMORY_TRACKING
    device->num_bio_sector_ranges += 1;
    device->max_outstanding_num_bio_sector_ranges = umax(device->max_outstanding_num_bio_sector_ranges, device->num_bio_sector_ranges);
#endif
    list_add_tail(&bio_data->pending_list, &device->pending_ops);
}

// Note: Caller must hold index_lock
bool try_insert_into_outstanding_ops(struct rollbaccine_device *device, struct bio_data *bio_data, bool check_pending) {
    struct rb_node **other_bio_tree_node_location = &(device->outstanding_ops.rb_node);
    struct rb_node *other_bio_tree_node = NULL;
    struct bio_data *other_bio_data;

    // See if we conflict with any operations that are already blocked
    if (check_pending) {
        list_for_each_entry(other_bio_data, &device->pending_ops, pending_list) {
            if (bio_data->start_sector < other_bio_data->end_sector && other_bio_data->start_sector < bio_data->end_sector) {
                return false;
            }
        }
    }

    // See if we conflict with any outstanding operations. If not, then get the place in the red black tree where we should insert this bio
    while (*other_bio_tree_node_location != NULL) {
        other_bio_data = container_of(*other_bio_tree_node_location, struct bio_data, tree_node);
        other_bio_tree_node = *other_bio_tree_node_location;

        if (bio_data->end_sector <= other_bio_data->start_sector)
            other_bio_tree_node_location = &other_bio_tree_node->rb_left;
        else if (bio_data->start_sector >= other_bio_data->end_sector)
            other_bio_tree_node_location = &other_bio_tree_node->rb_right;
        else
            return false;
    }
    // No conflicts, add this bio to the red black tree
#ifdef MEMORY_TRACKING
    device->num_rb_nodes += 1;
#endif
    // Insert into rb tree with other_bio_tree_node as the parent at other_bio_tree_node_location
    rb_link_node(&bio_data->tree_node, other_bio_tree_node, other_bio_tree_node_location);
    rb_insert_color(&bio_data->tree_node, &device->outstanding_ops);
    return true;
}

void remove_from_outstanding_ops_and_unblock(struct rollbaccine_device *device, struct bio *bio) {
    struct bio_data *bio_data = bio->bi_private;
    struct bio_data *other_bio_data;
    unsigned long flags;

    spin_lock_irqsave(&device->index_lock, flags);
#ifdef MEMORY_TRACKING
    device->num_rb_nodes -= 1;
    device->max_outstanding_num_rb_nodes = umax(device->max_outstanding_num_rb_nodes, device->num_rb_nodes + 1);
#endif
    rb_erase(&bio_data->tree_node, &device->outstanding_ops);
    while (!list_empty(&device->pending_ops)) {
        other_bio_data = list_first_entry(&device->pending_ops, struct bio_data, pending_list);
        // Check, in order, if the first pending op can be executed. If not, then break
        if (!try_insert_into_outstanding_ops(device, other_bio_data, false)) {
            break;
        }

        // Submit the other bio
        list_del(&other_bio_data->pending_list);
        INIT_WORK(&other_bio_data->submit_bio_work, submit_bio_task);
        queue_work(device->submit_bio_queue, &other_bio_data->submit_bio_work);
#ifdef MEMORY_TRACKING
        device->num_bio_sector_ranges -= 1;
#endif
    }
    spin_unlock_irqrestore(&device->index_lock, flags);
}

// Put the freed page back in the cache for reuse
void page_cache_free(struct rollbaccine_device *device, struct page *page_to_free) {
    unsigned long flags;
    spin_lock_irqsave(&device->page_cache_lock, flags);
    if (device->page_cache_size == 0) {
        device->page_cache = page_to_free;
    } else {
        // Point the new page to the current page_cache
        page_private(page_to_free) = (unsigned long)device->page_cache;
        device->page_cache = page_to_free;
    }
    device->page_cache_size++;
    spin_unlock_irqrestore(&device->page_cache_lock, flags);
}

void page_cache_destroy(struct rollbaccine_device *device) {
    struct page *tmp;
    unsigned long flags;

    spin_lock_irqsave(&device->page_cache_lock, flags);
    while (device->page_cache_size > 0) {
        tmp = device->page_cache;
        device->page_cache = (struct page *)page_private(device->page_cache);
        __free_page(tmp);
        device->page_cache_size--;
    }
    spin_unlock_irqrestore(&device->page_cache_lock, flags);
}

// Get a previously allocated page or allocate a new one if necessary. Store pointers to next pages in page_private, like in drbd.
struct page *page_cache_alloc(struct rollbaccine_device *device) {
    struct page *new_page;
    bool need_new_page = false;
    unsigned long flags;

    spin_lock_irqsave(&device->page_cache_lock, flags);
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
    spin_unlock_irqrestore(&device->page_cache_lock, flags);

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

void block_if_not_enough_memory(struct rollbaccine_device *device, int num_pages_needed) {
    unsigned long flags;
    if (num_pages_needed > device->max_memory_pages) {
        printk_ratelimited(KERN_ERR "Write requires more memory than max pages allocated: %d, automatically allowing write through", num_pages_needed);
        return;
    }

    spin_lock_irqsave(&device->memory_wait_queue.lock, flags);
    wait_event_interruptible_locked(device->memory_wait_queue, device->num_used_memory_pages + num_pages_needed <= device->max_memory_pages);
    device->num_used_memory_pages += num_pages_needed;
    spin_unlock_irqrestore(&device->memory_wait_queue.lock, flags);
}

void release_memory(struct rollbaccine_device *device, int num_pages_released) {
    unsigned long flags;
    if (num_pages_released > 0) {
        spin_lock_irqsave(&device->memory_wait_queue.lock, flags);
#ifdef MEMORY_TRACKING
        device->max_num_pages_in_memory = umax(device->max_num_pages_in_memory, device->num_used_memory_pages);
#endif
        device->num_used_memory_pages -= num_pages_released;
        wake_up_locked(&device->memory_wait_queue);
        spin_unlock_irqrestore(&device->memory_wait_queue.lock, flags);
    }
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
    unsigned long flags;

    spin_lock_irqsave(&device->replica_fsync_lock, flags);
    // Special case for f = 1, n = 2, since there's only 1 follower, so we don't need to iterate.
    // Also, we don't need to compare maxes (the latest message should always have a larger fsync index).
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
    spin_unlock_irqrestore(&device->replica_fsync_lock, flags);
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

    release_memory(device, (bio_data->end_sector - bio_data->start_sector) / SECTORS_PER_PAGE);
    // Free each page. Reset bio to start first, in case it's pointing to the end
    received_bio->bi_iter.bi_sector = bio_data->start_sector;
    received_bio->bi_iter.bi_size = (bio_data->end_sector - bio_data->start_sector) * SECTOR_SIZE;
    received_bio->bi_iter.bi_idx = 0;
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
        release_memory(bio_data->device, (bio_data->end_sector - bio_data->start_sector) / SECTORS_PER_PAGE);
        bio_put(bio_data->shallow_clone);
        free_pages_end_io(bio_data->deep_clone);
    } else {
        // printk(KERN_INFO "Decrementing clone ref count to %d, write index: %d", atomic_read(&deep_clone_bio_data->ref_counter), deep_clone_bio_data->write_index);
    }
}

void leader_read_disk_end_io(struct bio *shallow_clone) {
    struct bio_data *bio_data = shallow_clone->bi_private;
    struct rollbaccine_device *device = bio_data->device;

    // Decrypt
    enc_or_dec_bio(bio_data, ROLLBACCINE_DECRYPT);
    // Unblock pending writes
    remove_from_outstanding_ops_and_unblock(device, shallow_clone);
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
    remove_from_outstanding_ops_and_unblock(bio_data->device, shallow_clone);
    // Return to the user. If this is an fsync, wait for replication
    if (!bio_data->is_fsync) {
        ack_bio_to_user_without_executing(bio_data->bio_src);
    }
    // Unlike replica_disk_end_io, the clone is sharing data with the clone used for networking, so we have to check if we can free
    try_free_clones(shallow_clone);
}

void replica_disk_end_io(struct bio *received_bio) {
    struct bio_data *bio_data = received_bio->bi_private;
    // printk(KERN_INFO "Replica clone ended, freeing");
    remove_from_outstanding_ops_and_unblock(bio_data->device, received_bio);
    free_pages_end_io(received_bio);
}

void network_end_io(struct bio *deep_clone) {
    // See if we can free
    // printk(KERN_INFO "Network broadcast %d completed", deep_clone_bio_data->write_index);
    try_free_clones(deep_clone);
}

void broadcast_bio(struct work_struct *work) {
    int sent;
    struct bio_data *clone_bio_data = container_of(work, struct bio_data, broadcast_work);
    struct bio *clone = clone_bio_data->deep_clone;
    unsigned char *checksum_and_iv = clone_bio_data->checksum_and_iv;
    size_t checksum_and_iv_size = bio_checksum_and_iv_size(clone_bio_data->end_sector - clone_bio_data->start_sector);
    size_t remaining_checksum_and_iv_size;
    struct rollbaccine_device *device = clone_bio_data->device;
    struct msghdr msg_header;
    struct kvec vec;
    struct socket_list *curr, *next;
    struct metadata_msg metadata;
    struct additional_hash_msg *additional_hash_msg;
    struct bio_vec bvec, chunked_bvec;
    struct bvec_iter iter;
    cycles_t time = get_cycles_if_flag_on();
    cycles_t total_time = get_cycles_if_flag_on();

    metadata.type = clone_bio_data->is_fsync ? ROLLBACCINE_FSYNC : ROLLBACCINE_WRITE;
    metadata.bal = device->bal;
    metadata.sender_id = device->id;
    metadata.msg_index = ++device->last_sent_msg_index;
    metadata.write_index = clone_bio_data->write_index;
    metadata.num_pages = clone->bi_iter.bi_size / PAGE_SIZE;
    metadata.bi_opf = clone->bi_opf;
    metadata.sector = clone->bi_iter.bi_sector;
    // Copy checksum and IV into metadata
    memcpy(metadata.checksum_and_iv, checksum_and_iv, checksum_and_iv_size);
    // Create a hash of the message
    hash_buffer(device, (char *)&metadata + SHA256_SIZE, sizeof(struct metadata_msg) - SHA256_SIZE, metadata.msg_hash);

    // printk(KERN_INFO "Broadcasting write with write_index: %llu, is fsync: %d, bi_opf: %llu", metadata.write_index, requires_fsync(clone), metadata.bi_opf);
    WARN_ON(metadata.write_index == 0);  // Should be at least one. Means that bio_data was retrieved incorrectly

    // Note: If bi_size is not a multiple of PAGE_SIZE, we have to send by sector chunks
    WARN_ON(metadata.num_pages * PAGE_SIZE != clone->bi_iter.bi_size);

    msg_header.msg_name = NULL;
    msg_header.msg_namelen = 0;
    msg_header.msg_control = NULL;
    msg_header.msg_controllen = 0;
    msg_header.msg_flags = 0;

    // Create message for additional hash & IVs if they exceed what could be sent with the metadata
    if (checksum_and_iv_size > ROLLBACCINE_METADATA_CHECKSUM_IV_SIZE) {
        remaining_checksum_and_iv_size = checksum_and_iv_size - ROLLBACCINE_METADATA_CHECKSUM_IV_SIZE;
        additional_hash_msg = alloc_additional_hash_msg(device, remaining_checksum_and_iv_size);
        additional_hash_msg->sender_id = device->id;
        additional_hash_msg->msg_index = ++device->last_sent_msg_index;
        memcpy(additional_hash_msg->checksum_and_iv, checksum_and_iv + ROLLBACCINE_METADATA_CHECKSUM_IV_SIZE, remaining_checksum_and_iv_size);
        hash_buffer(device, (char*) additional_hash_msg + SHA256_SIZE, additional_hash_msg_size(remaining_checksum_and_iv_size) - SHA256_SIZE, additional_hash_msg->msg_hash);
    }

    mutex_lock(&device->connected_sockets_lock);
    list_for_each_entry_safe(curr, next, &device->connected_sockets, list) {
        vec.iov_base = &metadata;
        vec.iov_len = sizeof(struct metadata_msg);
        print_and_update_latency("broadcast_bio: Set up broadcast message", &time);

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
        print_and_update_latency("broadcast_bio: Send metadata", &time);

        // 2. Send hash & IVs if they exceed what could be sent with the metadata
        if (additional_hash_msg != NULL) {
            vec.iov_base = additional_hash_msg;
            vec.iov_len = additional_hash_msg_size(remaining_checksum_and_iv_size);
            while (vec.iov_len > 0) {
                // printk(KERN_INFO "Sending checksums and IVs, size: %lu", vec.iov_len);
                sent = kernel_sendmsg(curr->sock, &msg_header, &vec, 1, vec.iov_len);
                if (sent <= 0) {
                    printk(KERN_ERR "Error broadcasting checksums and IVs");
                    goto finish_sending_to_socket;
                } else {
                    vec.iov_base += sent;
                    vec.iov_len -= sent;
                }
            }
            print_and_update_latency("broadcast_bio: Sent remaining checksums and IVs", &time);
        }

        // 3. Send bios
        bio_for_each_segment(bvec, clone, iter) {
            bvec_set_page(&chunked_bvec, bvec.bv_page, bvec.bv_len, bvec.bv_offset);

            // Keep retrying send until the whole message is sent
            while (chunked_bvec.bv_len > 0) {
                iov_iter_bvec(&msg_header.msg_iter, ITER_SOURCE, &chunked_bvec, 1, chunked_bvec.bv_len);

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
        print_and_update_latency("broadcast_bio: Send pages", &time);
        // Label to jump to if socket cannot be written to, so we can iterate the next socket
    finish_sending_to_socket:
    }
    // printk(KERN_INFO "Sent metadata message and bios, sector: %llu, num pages: %llu", metadata.sector, metadata.num_pages);
    mutex_unlock(&device->connected_sockets_lock);

    if (additional_hash_msg != NULL) {
        kfree(additional_hash_msg);
    }
    network_end_io(clone);
#ifdef MEMORY_TRACKING
    atomic_dec(&device->num_bios_on_broadcast_queue);
#endif
    print_and_update_latency("broadcast_bio: Broadcast bio", &total_time);
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
    cycles_t time = get_cycles_if_flag_on();

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
    print_and_update_latency("deep_bio_clone", &time);
    return clone;
}

static int rollbaccine_map(struct dm_target *ti, struct bio *bio) {
    bool is_cloned = false;
    bool doesnt_conflict_with_other_writes = true;
    struct rollbaccine_device *device = ti->private;
    struct bio_data *bio_data;
    cycles_t total_time = get_cycles_if_flag_on();
    cycles_t time = get_cycles_if_flag_on();
    unsigned long flags;

    bio_set_dev(bio, device->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    // Copy bio if it's a write
    if (device->is_leader) {
        is_cloned = true;

        bio_data = alloc_bio_data(device);
        bio_data->device = device;
        bio_data->bio_src = bio;
        bio_data->start_sector = bio->bi_iter.bi_sector;
        bio_data->end_sector = bio->bi_iter.bi_sector + bio_sectors(bio);
        
        switch (bio_data_dir(bio)) {
            case WRITE:
                // Wait until there's enough memory. Ask for 2 pages per page since we're deep cloning
                block_if_not_enough_memory(device, bio_sectors(bio) * 2 / SECTORS_PER_PAGE);

                bio_data->is_fsync = requires_fsync(bio);
                // NOTE: Removing the flags causes Azure to crash, so we'll keep them for now
                // bio->bi_opf = remove_fsync_flags(bio->bi_opf);  // All fsyncs become logical fsyncs

                // Encrypt
                bio_data->checksum_and_iv = enc_or_dec_bio(bio_data, ROLLBACCINE_ENCRYPT);
                print_and_update_latency("rollbaccine_map: encryption", &time);

                // Create the network clone
                bio_data->deep_clone = deep_bio_clone(device, bio);
                if (!bio_data->deep_clone) {
                    printk(KERN_ERR "Could not create deep clone");
                    return DM_MAPIO_REMAPPED;
                }

                // Create the disk clone. Necessary because we change the bi_end_io function, so we can't submit the original.
                bio_data->shallow_clone = shallow_bio_clone(device, bio_data->deep_clone);
                if (!bio_data->shallow_clone) {
                    printk(KERN_ERR "Could not create shallow clone");
                    return DM_MAPIO_REMAPPED;
                }
                // Set end_io so once this write completes, queued writes can be unblocked
                bio_data->shallow_clone->bi_end_io = leader_write_disk_end_io;

                // Set shared data between clones
                atomic_set(&bio_data->ref_counter, 2);
                INIT_WORK(&bio_data->broadcast_work, broadcast_bio);
                bio_data->deep_clone->bi_private = bio_data;
                bio_data->shallow_clone->bi_private = bio_data;

                // Increment indices, place ops on queue, submit cloned ops to disk
                spin_lock_irqsave(&device->index_lock, flags);
                print_and_update_latency("rollbaccine_map: encryption -> obtained index lock", &time);
                // Increment write index
                bio_data->write_index = ++device->write_index;
                doesnt_conflict_with_other_writes = try_insert_into_outstanding_ops(device, bio_data, true);
                if (!doesnt_conflict_with_other_writes) {
                    add_to_pending_ops_tail(device, bio_data);
                }
                // printk(KERN_INFO "Inserted clone %p, write index: %d", bio_data->shallow_clone, bio_data->write_index);
                if (bio_data->is_fsync) {
                    // Add original bio to fsyncs blocked on replication
                    bio->bi_private = bio_data->write_index;  // HACK: Store the write index in this fsync's bi_private field so it can be checked when network fsyncs are being acknowledged
                    spin_lock(&device->replica_fsync_lock);
                    print_and_update_latency("rollbaccine_map: index lock -> obtained replica fsync lock", &time);
                    bio_list_add(&device->fsyncs_pending_replication, bio);
#ifdef MEMORY_TRACKING
                    device->num_fsyncs_pending_replication += 1;
#endif
                    spin_unlock(&device->replica_fsync_lock);
                }
                queue_work(device->broadcast_queue, &bio_data->broadcast_work);
                print_and_update_latency("rollbaccine_map: queued to broadcast", &time);
                spin_unlock_irqrestore(&device->index_lock, flags);

#ifdef MEMORY_TRACKING
                atomic_inc(&device->num_bios_on_broadcast_queue);
                atomic_max(&device->max_bios_on_broadcast_queue, atomic_read(&device->num_bios_on_broadcast_queue));
#endif

                // Even though submit order != write index order, any conflicting writes will only be submitted later so any concurrency here is fine
                if (doesnt_conflict_with_other_writes) {
                    if (bio_data->checksum_and_iv != NULL) {
                        update_global_checksum_and_iv(device, bio_data->checksum_and_iv, bio_data->start_sector, bio_data->end_sector - bio_data->start_sector);
                    }
                    submit_bio_noacct(bio_data->shallow_clone);
                    print_and_update_latency("rollbaccine_map: submit", &time);
                }
                break;
            case READ:
                // Create the disk clone. Necessary because we change the bi_end_io function, so we can't submit the original.
                bio_data->shallow_clone = shallow_bio_clone(device, bio);
                if (!bio_data->shallow_clone) {
                    printk(KERN_ERR "Could not create shallow clone");
                    return DM_MAPIO_REMAPPED;
                }
                // Set end_io so once this cloned read completes, we can decrypt and send the original read along
                bio_data->shallow_clone->bi_end_io = leader_read_disk_end_io;
                bio_data->shallow_clone->bi_private = bio_data;

                // Block read if it conflicts with any other outstanding operations
                spin_lock_irqsave(&device->index_lock, flags);
                doesnt_conflict_with_other_writes = try_insert_into_outstanding_ops(device, bio_data, true); // Note: It actually doesn't matter for correctness whether reads check the pending list or not
                if (!doesnt_conflict_with_other_writes) {
                    add_to_pending_ops_tail(device, bio_data);
                }
                spin_unlock_irqrestore(&device->index_lock, flags);

                if (doesnt_conflict_with_other_writes) {
                    submit_bio_noacct(bio_data->shallow_clone);
                }
                break;
        }
    }
    print_and_update_latency("rollbaccine_map", &total_time);

    // Anything we clone and submit ourselves is marked submitted
    return is_cloned ? DM_MAPIO_SUBMITTED : DM_MAPIO_REMAPPED;
}

bool verify_msg(struct rollbaccine_device *device, void *msg, size_t msg_size, char *expected_hash, uint64_t msg_index) {
    char calculated_hash[SHA256_SIZE];
    bool hash_matches;
    bool msg_index_matches;

    hash_buffer(device, msg, msg_size, calculated_hash);
    hash_matches = memcmp(calculated_hash, expected_hash, SHA256_SIZE) == 0;
    msg_index_matches = device->next_incoming_msg_index == msg_index;

    if (!hash_matches) {
        printk(KERN_ERR "Received message with incorrect hash, expected: %s, received: %s", expected_hash, calculated_hash);
        return false;
    }
    if (!msg_index_matches) {
        printk(KERN_ERR "Received message with incorrect index, expected: %llu, received: %llu", device->next_incoming_msg_index, msg_index);
        return false;
    }
    // Increment the next expected message index
    device->next_incoming_msg_index += 1;
    return true;
}

void hash_buffer(struct rollbaccine_device *device, char *buffer, size_t len, char *out) {
    cycles_t time = get_cycles_if_flag_on();
    // Use a mutex (not lock, since it might schedule) while hashing in case it tries to hash 2 things concurrently
    mutex_lock(&device->hash_mutex);
    int ret = crypto_shash_digest(device->hash_desc, buffer, len, out);
    mutex_unlock(&device->hash_mutex);
    if (ret) {
        printk(KERN_ERR "Could not hash buffer");
    }
    print_and_update_latency("hash_buffer", &time);
}

// TODO: Alloc a page globally and just reuse since only 1 thread will attempt to verify at any time
unsigned char *enc_or_dec_bio(struct bio_data *bio_data, enum EncDecType enc_or_dec) {
    int ret = 0;
    struct bio_vec bv;
    uint64_t curr_sector;
    struct aead_request *req;
    struct scatterlist sg[4], sg_verify[4];
    DECLARE_CRYPTO_WAIT(wait);
    unsigned char *bio_checksum_and_iv;
    unsigned char *iv;
    // TODO: Reenable when testing on machines with RDRAND
    // long iv_long;
    // bool rd_rand_success = false;
    // size_t iv_copy_num_bytes_remaining;
    unsigned char *checksum;
    cycles_t time = get_cycles_if_flag_on();
    cycles_t total_time = get_cycles_if_flag_on();

    if (bio_data->end_sector == bio_data->start_sector) {
        // printk(KERN_INFO "Skipping encryption/decryption for empty bio");
        return NULL;
    }

    if (enc_or_dec == ROLLBACCINE_ENCRYPT) {
        // Store new checksum and IV of write into array (instead of updating global checksum/iv) so the global checksum/iv can be updated in-order later
        bio_checksum_and_iv = alloc_bio_checksum_and_iv(bio_data->device, bio_sectors(bio_data->bio_src));
        if (!bio_checksum_and_iv) {
            printk(KERN_ERR "Could not allocate checksum and iv for bio");
            goto free_and_return;
        }
        print_and_update_latency("enc_or_dec_bio: alloc_bio_checksum_and_iv", &time);
    }

    while (bio_data->bio_src->bi_iter.bi_size) {
        // printk(KERN_INFO "enc/dec starting");
        curr_sector = bio_data->bio_src->bi_iter.bi_sector;
        bv = bio_iter_iovec(bio_data->bio_src, bio_data->bio_src->bi_iter);

        switch (enc_or_dec) {
            case ROLLBACCINE_ENCRYPT:
                checksum = get_bio_checksum(bio_checksum_and_iv, bio_data->start_sector, curr_sector);
                iv = get_bio_iv(bio_checksum_and_iv, bio_data->start_sector, curr_sector);
                print_and_update_latency("enc_or_dec_bio: get bio checksum and iv", &time);
                // Generate a new IV
                // TODO: Uncomment when testing on machines with RDRAND to see if this works
                // iv_copy_num_bytes_remaining = AES_GCM_IV_SIZE;
                // while (iv_copy_num_bytes_remaining > 0) {
                //     rd_rand_success = rdrand_long(&iv_long);
                //     if (!rd_rand_success) {
                //         printk(KERN_ERR "Could not generate random number for IV");
                //         goto free_and_return;
                //     }
                //     memcpy(iv + (AES_GCM_IV_SIZE - iv_copy_num_bytes_remaining), &iv_long, min(iv_copy_num_bytes_remaining, sizeof(long)));
                //     iv_copy_num_bytes_remaining -= sizeof(long);
                // }
                get_random_bytes(iv, AES_GCM_IV_SIZE);
                print_and_update_latency("enc_or_dec_bio: get_random_bytes", &time);
                break;
            case ROLLBACCINE_DECRYPT:
                checksum = global_checksum(bio_data->device, curr_sector);
                iv = global_iv(bio_data->device, curr_sector);
                // Skip decryption for any block that has not been written to
                if (!has_checksum(checksum)) {
                    goto enc_or_dec_next_sector;
                }
                break;
            case ROLLBACCINE_VERIFY:
                // Assume the existing checksum is stored in bio_data
                checksum = get_bio_checksum(bio_data->checksum_and_iv, bio_data->start_sector, curr_sector);
                iv = get_bio_iv(bio_data->checksum_and_iv, bio_data->start_sector, curr_sector);

                sg_init_table(sg_verify, 4);
                sg_set_buf(&sg_verify[0], &curr_sector, sizeof(uint64_t));
                sg_set_buf(&sg_verify[1], iv, AES_GCM_IV_SIZE);
                sg_set_page(&sg_verify[2], bio_data->device->verification_page, ROLLBACCINE_ENCRYPTION_GRANULARITY, bv.bv_offset);
                sg_set_buf(&sg_verify[3], checksum, AES_GCM_AUTH_SIZE);
                break;
        }

        // Lazily allocate the AEAD request, because a lot of reads are over blocks that have not been written to (so they will not pass !has_checksum and won't need to alloc)
        if (req == NULL) {
            req = aead_request_alloc(bio_data->device->tfm, GFP_KERNEL);
            if (!req) {
                printk(KERN_ERR "aead request allocation failed");
                return NULL;
            }
            print_and_update_latency("enc_or_dec_bio: aead_request_alloc", &time);
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
            case ROLLBACCINE_VERIFY: // Write output to page and discard
                aead_request_set_crypt(req, sg, sg_verify, ROLLBACCINE_ENCRYPTION_GRANULARITY + AES_GCM_AUTH_SIZE, iv);
                ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
                break;
        }
        print_and_update_latency("enc_or_dec_bio: crypto_aead_encrypt/decrypt", &time);

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
    // Reset bio to start after iterating for encryption
    bio_data->bio_src->bi_iter.bi_sector = bio_data->start_sector;
    bio_data->bio_src->bi_iter.bi_size = (bio_data->end_sector - bio_data->start_sector) * SECTOR_SIZE;
    bio_data->bio_src->bi_iter.bi_idx = 0;
    print_and_update_latency("enc_or_dec_bio", &total_time);
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
    int sent, received, i, num_sectors;
    size_t checksum_and_iv_size, remaining_checksum_and_iv_size;
    struct additional_hash_msg *additional_hash_msg;
    bool no_conflict;
    unsigned long flags;

    msg_header.msg_name = 0;
    msg_header.msg_namelen = 0;
    msg_header.msg_flags = MSG_WAITALL | MSG_NOSIGNAL;
    msg_header.msg_control = NULL;
    msg_header.msg_controllen = 0;

    while (!device->shutting_down) {
        // 1. Receive metadata message
        vec.iov_base = &metadata;
        vec.iov_len = sizeof(struct metadata_msg);

        received = kernel_recvmsg(sock, &msg_header, &vec, vec.iov_len, vec.iov_len, msg_header.msg_flags);
        if (received <= 0) {
            printk(KERN_ERR "Error reading metadata from socket");
            break;
        }

        // printk(KERN_INFO "Received metadata sector: %llu, num pages: %llu, bi_opf: %llu, is fsync: %llu", metadata.sector, metadata.num_pages, metadata.bi_opf, metadata.bi_opf&(REQ_PREFLUSH |
        // REQ_FUA));

        // Verify the message
        if (!verify_msg(device, (char*) &metadata + SHA256_SIZE, sizeof(struct metadata_msg) - SHA256_SIZE, metadata.msg_hash, metadata.msg_index)) {
            break;
        }

        // Received ack for fsync
        if (metadata.type == FOLLOWER_ACK && device->is_leader) {
            // printk(KERN_INFO "Received fsync ack for write index: %llu", metadata.write_index);
            process_follower_fsync_index(device, metadata.sender_id, metadata.write_index);
            continue;
        }

        received_bio = bio_alloc_bioset(device->dev->bdev, metadata.num_pages, metadata.bi_opf, GFP_NOIO, &device->bs);
        received_bio->bi_iter.bi_sector = metadata.sector;
        received_bio->bi_end_io = replica_disk_end_io;

        bio_data = alloc_bio_data(device);
        bio_data->device = device;
        bio_data->write_index = metadata.write_index;
        bio_data->bio_src = received_bio;
        bio_data->start_sector = metadata.sector;
        bio_data->end_sector = metadata.sector + metadata.num_pages * SECTORS_PER_PAGE;
        received_bio->bi_private = bio_data;

        // Copy hash and IV
        num_sectors = metadata.num_pages * SECTORS_PER_PAGE;
        checksum_and_iv_size = bio_checksum_and_iv_size(num_sectors);
        bio_data->checksum_and_iv = alloc_bio_checksum_and_iv(device, num_sectors);
        memcpy(bio_data->checksum_and_iv, metadata.checksum_and_iv, min(ROLLBACCINE_METADATA_CHECKSUM_IV_SIZE, checksum_and_iv_size));

        // 2. Expect hash if it wasn't done sending
        if (checksum_and_iv_size > ROLLBACCINE_METADATA_CHECKSUM_IV_SIZE) {
            remaining_checksum_and_iv_size = checksum_and_iv_size - ROLLBACCINE_METADATA_CHECKSUM_IV_SIZE;
            additional_hash_msg = alloc_additional_hash_msg(device, remaining_checksum_and_iv_size);

            vec.iov_base = additional_hash_msg;
            vec.iov_len = additional_hash_msg_size(remaining_checksum_and_iv_size);

            // printk(KERN_INFO "Receiving checksums and IVs, size: %lu", vec.iov_len);
            received = kernel_recvmsg(sock, &msg_header, &vec, vec.iov_len, vec.iov_len, msg_header.msg_flags);
            if (received <= 0) {
                printk(KERN_ERR "Error reading checksum and IV, %d", received);
                break;
            }

            // Verify the message
            if (!verify_msg(device, (char*) additional_hash_msg + SHA256_SIZE, sizeof(struct additional_hash_msg) - SHA256_SIZE, additional_hash_msg->msg_hash, additional_hash_msg->msg_index)) {
                break;
            }

            // Copy the checksums over
            memcpy(bio_data->checksum_and_iv + ROLLBACCINE_METADATA_CHECKSUM_IV_SIZE, additional_hash_msg->checksum_and_iv, remaining_checksum_and_iv_size);
            // Free the message
            kfree(additional_hash_msg);
        }

        // 3. Receive pages of bio (over the regular socket now, not TLS)
        block_if_not_enough_memory(device, metadata.num_pages);
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
        enc_or_dec_bio(bio_data, ROLLBACCINE_VERIFY);

        device->write_index = metadata.write_index;

        // 5. If the message is an fsync, reply.
        if (metadata.type == ROLLBACCINE_FSYNC) {
            metadata.type = FOLLOWER_ACK;
            metadata.sender_id = device->id;
            metadata.msg_index = ++device->last_sent_msg_index;
            metadata.bal = device->bal;
            hash_buffer(device, (char*) &metadata + SHA256_SIZE, sizeof(struct metadata_msg) - SHA256_SIZE, metadata.msg_hash);

            vec.iov_base = &metadata;
            vec.iov_len = sizeof(struct metadata_msg);

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
        spin_lock_irqsave(&device->index_lock, flags);
        no_conflict = try_insert_into_outstanding_ops(device, bio_data, true);
        if (!no_conflict) {
            add_to_pending_ops_tail(device, bio_data);
        }
        spin_unlock_irqrestore(&device->index_lock, flags);
        if (no_conflict) {
            if (metadata.num_pages != 0) {
                update_global_checksum_and_iv(device, bio_data->checksum_and_iv, metadata.sector, num_sectors);
            }
            submit_bio_noacct(received_bio);
        }
    }

    printk(KERN_INFO "Shutting down, exiting blocking read");
    kernel_sock_shutdown(sock, SHUT_RDWR);
    // TODO: Releasing the socket is problematic because it makes future calls to shutdown() crash, which may happen if the connection dies, the socket is freed, and later the destructor tries to shut
    // it down.
    //     sock_release(sock);
}

int connect_to_server(void *args) {
    struct client_thread_params *thread_params = (struct client_thread_params *)args;
    struct socket_list *sock_list;
    int error = -1;

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

    sock_list = kmalloc(sizeof(struct socket_list), GFP_KERNEL);
    if (sock_list == NULL) {
        printk(KERN_ERR "Error creating sock_list");
        goto cleanup;
    }
    sock_list->sock = thread_params->sock;
    mutex_lock(&thread_params->device->connected_sockets_lock);
    list_add(&sock_list->list, &thread_params->device->connected_sockets);
    mutex_unlock(&thread_params->device->connected_sockets_lock);

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
    
    blocking_read(thread_params->device, thread_params->sock);

    kfree(thread_params);
    return 0;
}

// Thread that listens to connecting clients
int listen_for_connections(void *args) {
    struct listen_thread_params *thread_params = (struct listen_thread_params *)args;
    struct rollbaccine_device *device = thread_params->device;
    struct socket *new_sock;
    struct accepted_thread_params *new_thread_params;
    struct socket_list *new_connected_socket_list, *new_server_socket_list;
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

    DMEMIT("Latest write index: %d\n", device->write_index);
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
    DMEMIT("Num pages still in memory: %d\n", device->num_used_memory_pages);
    DMEMIT("Num checksums and IVs not freed: %d\n", atomic_read(&device->num_checksum_and_ivs));
    DMEMIT("Num bios on broadcast queue: %d\n", atomic_read(&device->num_bios_on_broadcast_queue));
    DMEMIT("Max outstanding num bio pages: %d\n", atomic_read(&device->max_outstanding_num_bio_pages));
    DMEMIT("Max outstanding num bio_data: %d\n", atomic_read(&device->max_outstanding_num_bio_data));
    DMEMIT("Max outstanding num deep clones: %d\n", atomic_read(&device->max_outstanding_num_deep_clones));
    DMEMIT("Max outstanding num shallow clones: %d\n", atomic_read(&device->max_outstanding_num_shallow_clones));
    DMEMIT("Max size of rb tree for outgoing operations: %d\n", device->max_outstanding_num_rb_nodes);
    DMEMIT("Max number of conflicting operations: %d\n", device->max_outstanding_num_bio_sector_ranges);
    DMEMIT("Max number of fsyncs pending replication: %d\n", device->max_outstanding_fsyncs_pending_replication);
    DMEMIT("Max number of pages in memory: %d\n", device->max_num_pages_in_memory);
    DMEMIT("Max bios on broadcast queue: %d\n", atomic_read(&device->max_bios_on_broadcast_queue));
}

// Arguments: 0 = underlying device name, like /dev/ram0. 1 = f, 2 = n, 3 = id, 4 = is_leader, 5 = max_memory_pages, 6 = key, 7= listen port. 8+ = server addr & ports
// Note: Keys on the replicas are not used, since they cannot encrypt or decrypt
static int rollbaccine_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    struct rollbaccine_device *device;
    ushort port;
    int error;
    int i;
    unsigned long projected_bytes_used = 0;
    unsigned long checksum_and_iv_size;

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

    device->submit_bio_queue = alloc_workqueue("submit bio queue", 0, 0);
    if (!device->submit_bio_queue) {
        printk(KERN_ERR "Cannot allocate submit bio queue");
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

    error = kstrtou64(argv[3], 10, &device->id);
    if (error < 0) {
        printk(KERN_ERR "Error parsing id");
        return error;
    }
    printk(KERN_INFO "id: %llu", device->id);
    device->bal.id = 0;
    device->bal.num = 0;
    device->write_index = ROLLBACCINE_INIT_WRITE_INDEX;
    device->last_sent_msg_index = 0;
    device->next_incoming_msg_index = 1;
    spin_lock_init(&device->index_lock);

    device->max_replica_fsync_index = ROLLBACCINE_INIT_WRITE_INDEX;
    spin_lock_init(&device->replica_fsync_lock);
    device->replica_fsync_indices = kzalloc(sizeof(int) * device->n, GFP_KERNEL);
    bio_list_init(&device->fsyncs_pending_replication);

    device->outstanding_ops = RB_ROOT;
    INIT_LIST_HEAD(&device->pending_ops);

    device->is_leader = strcmp(argv[4], "true") == 0;

    error = kstrtoint(argv[5], 10, &device->max_memory_pages);
    if (error < 0) {
        printk(KERN_ERR "Error parsing max_memory_pages");
        return error;
    }
    device->num_used_memory_pages = 0;
    init_waitqueue_head(&device->memory_wait_queue);

    // Start server
    error = kstrtou16(argv[7], 10, &port);
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

    // Connect to other servers. argv[7], argv[8], etc are all server addresses and ports to connect to.
    INIT_LIST_HEAD(&device->client_sockets);
    for (i = 8; i < argc; i += 2) {
        error = kstrtou16(argv[i + 1], 10, &port);
        if (error < 0) {
            printk(KERN_ERR "Error parsing port");
            return error;
        }
        printk(KERN_INFO "Starting thread to connect to servers at port: %u", port);
        start_client_to_server(device, argv[i], port);
    }

    // Set up AEAD
    device->verification_page = alloc_page(GFP_KERNEL);
    if (device->verification_page == NULL) {
        printk(KERN_ERR "Error allocating verification page");
        return -ENOMEM;
    }
    device->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(device->tfm)) {
        printk(KERN_ERR "Error allocating AEAD");
        return PTR_ERR(device->tfm);
    }
    crypto_aead_setauthsize(device->tfm, AES_GCM_AUTH_SIZE);

    error = crypto_aead_setkey(device->tfm, argv[6], KEY_SIZE);
    if (error < 0) {
        printk(KERN_ERR "Error setting key");
        return error;
    }

    checksum_and_iv_size = (unsigned long)(ti->len / ROLLBACCINE_SECTORS_PER_ENCRYPTION) * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE);
    printk(KERN_INFO "Checksums and IVs size: %lu", checksum_and_iv_size);
    device->checksums = vzalloc(checksum_and_iv_size);
    if (device->checksums == NULL) {
        printk(KERN_ERR "Error allocating checksums");
        return -ENOMEM;
    }
    projected_bytes_used += checksum_and_iv_size;

    // Set up hashing
    mutex_init(&device->hash_mutex);
    device->hash_alg = crypto_alloc_shash("hmac(sha256)", 0, 0);
    crypto_shash_setkey(device->hash_alg, argv[6], KEY_SIZE);
    if (IS_ERR(device->hash_alg)) {
        printk(KERN_ERR "Error allocating hash");
        return PTR_ERR(device->hash_alg);
    }

    device->hash_desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(device->hash_alg), GFP_KERNEL);
    if (device->hash_desc == NULL) {
        printk(KERN_ERR "Error allocating hash desc");
        return -ENOMEM;
    }
    device->hash_desc->tfm = device->hash_alg;

#ifdef MEMORY_TRACKING
    atomic_set(&device->num_bio_data_not_freed, 0);
    atomic_set(&device->num_bio_pages_not_freed, 0);
    atomic_set(&device->num_deep_clones_not_freed, 0);
    atomic_set(&device->num_shallow_clones_not_freed, 0);
    device->num_rb_nodes = 0;
    device->num_bio_sector_ranges = 0;
    device->num_fsyncs_pending_replication = 0;
    atomic_set(&device->num_checksum_and_ivs, 0);
    atomic_set(&device->num_bios_on_broadcast_queue, 0);
    atomic_set(&device->max_outstanding_num_bio_data, 0);
    atomic_set(&device->max_outstanding_num_bio_pages, 0);
    atomic_set(&device->max_outstanding_num_deep_clones, 0);
    atomic_set(&device->max_outstanding_num_shallow_clones, 0);
    device->max_outstanding_num_rb_nodes = 0;
    device->max_outstanding_num_bio_sector_ranges = 0;
    device->max_outstanding_fsyncs_pending_replication = 0;
    atomic_set(&device->max_bios_on_broadcast_queue, 0);
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

    __free_page(device->verification_page);
    kvfree(device->checksums);
    crypto_free_aead(device->tfm);
    crypto_free_shash(device->hash_alg);
    kfree(device->hash_desc);
    // Note: I'm not sure how to free theses queues which may have outstanding bios. Hopefully nothing breaks horribly
    destroy_workqueue(device->broadcast_queue);
    destroy_workqueue(device->submit_bio_queue);
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
    // Only start if the RNG has been seeded
    wait_for_random_bytes();
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