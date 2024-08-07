/**
 * This file is heavily inspired by https://github.com/sysprog21/kecho/tree/master and https://github.com/LINBIT/drbd.
 * Note: In order to kill threads on shutdown, we create a list of all open sockets that threads could be blocked on, and close them on shutdown.
 *       We also set shutting_down = true so a thread who returns from a blocking operation sees it and exits.
 *       We don't use kthread_stop() because it's blocking, and we need to close the sockets, which wakes the threads up before they see they should stop.
 */

#include <linux/device-mapper.h>
#include <linux/blkdev.h> /* Needed for get_capacity() */
#include <linux/inet.h>  // For in4_pton to translate IP addresses from strings
#include <linux/init.h>
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/handshake.h> // For TLS
#include <net/tls_prot.h>

#define ROLLBACCINE_MAX_CONNECTIONS 10
#define ROLLBACCINE_ENCRYPT_GRANULARITY 4096 // Number of bytes to encrypt, hash, or send at a time
#define ROLLBACCINE_RETRY_TIMEOUT 5000 // Number of milliseconds before client attempts to connect to a server again
#define ROLLBACCINE_INIT_WRITE_INDEX 0
#define ROLLBACCINE_HASH_SIZE 256
#define ROLLBACCINE_POINTER_BYTES 8 // Size of a pointer
#define ROLLBACCINE_MAX_BUFFERED_OPS 1024 * 32 // Maximum number of write operations that we still have a pointer to in the system, because it's submitting to disk or network. Fio on David's VM on his laptop says 720 is the max, so overshoot by a bit.
#define ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE \
    ROLLBACCINE_MAX_BUFFERED_OPS * ROLLBACCINE_POINTER_BYTES  // Number of bios outstanding in any buffer
#define ROLLBACCINE_TLS_TIMEOUT 5000 // Number of milliseconds to wait for TLS handshake to complete
#define SHA256_LENGTH 256
#define AES_GCM_IV_SIZE 12
#define AES_GCM_AUTH_SIZE 16
#define KEY_SIZE 16
#define MIN_IOS 64
#define MODULE_NAME "server"

#define TLS_ON
// #define MULTITHREADED_NETWORK
#define MEMORY_TRACKING // Check the number of mallocs/frees and see if we're leaking memory

// TODO: Expand with protocol message types
enum MsgType { ROLLBACCINE_WRITE, FOLLOWER_ACK };

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

struct server_device {
    struct dm_dev *dev;
    struct bio_set bs;
    struct kmem_cache *bio_data_cache;
    spinlock_t page_cache_lock;
    struct page *page_cache;
    int page_cache_size;
    bool is_leader;
    bool shutting_down; // Set to true when user triggers shutdown. All threads check this and abort if true. Used instead of kthread_should_stop(), since the function that flips that boolean to true (kthread_stop()) is blocking, which creates a race condition when we kill the socket & also wait for the thread to stop.
    int f;
    int n;

    struct ballot bal;
    int write_index; // Doesn't need to be atomic because only the broadcast thread will modify this
    spinlock_t index_lock; // Must be obtained for any operation modifying write_index and queues ordered by those indices

    // Logic for fsyncs blocking on replication
    // IMPORTANT: If both replica_fsync_lock and index_lock must be obtained, obtain index_lock first.
    // IMPORTANT: If multiple semaphores must be obtained, obtain in order of their names (sem1, sem2, etc)
    spinlock_t replica_fsync_lock;
    int* replica_fsync_indices; // Len = n
    int max_replica_fsync_index;
    struct semaphore sem1_fsyncs_pending_replication;
    struct kfifo fsyncs_pending_replication; // List of all fsyncs waiting for replication. Best-effort ordered by write index.

    // Logic for writes that block on previous fsyncs going to disk
    atomic_t disk_unacked_ops; // Number of operations yet to be acked by disk
    atomic_t disk_unacked_fsync;
    wait_queue_head_t submit_queue_wait_queue;
    struct semaphore sem2_submit_queue;
    struct kfifo submit_queue; // Operations about to be submitted to disk, queued in here to avoid deadlock when bio_end_io is called on the same thread. Lock writes with index_lock, reads with submit_queue_out_lock.
    
    // Communication between main threads and the networking thread
    wait_queue_head_t broadcast_queue_wait_queue;
    spinlock_t broadcast_queue_lock;
    struct semaphore sem3_broadcast_queue;
    struct kfifo broadcast_queue;

    // Sockets, tracked so we can kill them on exit.
    struct list_head server_sockets;
    struct list_head client_sockets;

    // Connected sockets. Should be a subset of the sockets above. Handy for broadcasting
    // TODO: Need to figure out network handshake so we know who we're talking to.
    struct mutex connected_sockets_lock;
    struct list_head connected_sockets;


    // AEAD Encryption/Decryption Fields
    // symmetric key algorithm instance
    struct crypto_aead *tfm;
    // persist key
    char *key;
    // array of hashes of each sector
    char* checksums;
    // Counters for tracking memory usage
#ifdef MEMORY_TRACKING
    // These counters will tell us if there's a memory leak
    atomic_t num_bio_pages_not_freed;
    atomic_t num_bio_data_not_freed;
    atomic_t num_shallow_clones_not_freed;
    atomic_t num_deep_clones_not_freed;
    // These counters tell us the maximum amount of memory we need to prealloc
    atomic_t max_outstanding_num_bio_pages;
    atomic_t max_outstanding_num_bio_data;
    atomic_t max_outstanding_num_shallow_clones;
    atomic_t max_outstanding_num_deep_clones;
    // These counters tell us if our queue sizes need to change
    int num_times_fsyncs_pending_replication_full;
    int num_times_submit_queue_full;
    int num_times_broadcast_queue_full;
    int max_fsyncs_pending_replication_size;
    int max_submit_queue_size;
    int max_broadcast_queue_size;
#endif
};

// Associated data for each bio, shared between clones
struct bio_data {
    struct server_device *device;
    struct bio *deep_clone;
    struct bio *shallow_clone;
    int write_index;

    // AEAD fields
    struct bio *base_bio;

    atomic_t ref_counter; // The number of clones. Once it hits 0, the bio can be freed. Only exists in the deep clone
};

// Thread params: Parameters passed into threads. Should be freed by the thread when it exits.

struct client_thread_params {
    struct socket *sock;
    struct sockaddr_in addr;
    struct server_device *device;
};

struct accepted_thread_params {
    struct socket *sock;
    struct server_device *device;
};

struct listen_thread_params {
    struct socket *sock;
    struct server_device *device;
};

void page_cache_free(struct server_device *device, struct page *page_to_free);
void page_cache_destroy(struct server_device *device);
struct page *page_cache_alloc(struct server_device *device);
void atomic_max(atomic_t *old, int new);
void wait_event_interruptible_with_retry(wait_queue_head_t *queue, int condition);
void down_interruptible_with_retry(struct semaphore *sem);
struct bio_data *alloc_bio_data(struct server_device *device);
void ack_bio_to_user_without_executing(struct bio *bio);
void process_follower_fsync_index(struct server_device *device, int follower_id, int follower_fsync_index);
bool requires_fsync(struct bio *bio);
unsigned int remove_fsync_flags(unsigned int bio_opf);
void free_pages_end_io(struct bio *received_bio);
void try_free_clones(struct bio *clone);
void disk_end_io(struct bio *bio);
void leader_disk_end_io(struct bio *shallow_clone);
void replica_disk_end_io(struct bio *received_bio);
void network_end_io(struct bio *deep_clone);
void decrypt_at_end_io(struct bio *read_bio);
void broadcast_bio(struct bio *clone);
int broadcaster(void *args);
int submitter(void *args);
struct bio* shallow_bio_clone(struct server_device *device, struct bio *bio_src);
struct bio* deep_bio_clone(struct server_device *device, struct bio *bio_src);
unsigned char *checksum_index(struct encryption_io *io, sector_t index);
unsigned char *iv_index(struct encryption_io *io, sector_t index);
int enc_or_dec_bio(struct encryption_io *io, int enc_or_dec);
void kill_thread(struct socket *sock);
void blocking_read(struct server_device *device, struct socket *sock);
#ifdef TLS_ON
void on_tls_handshake_done(void *data, int status, key_serial_t peerid);
#endif
int connect_to_server(void *args);
int start_client_to_server(struct server_device *device, char *addr, ushort port);
int listen_to_accepted_socket(void *args);
int listen_for_connections(void *args);
int start_server(struct server_device *device, ushort port);
int __init server_init_module(void);
void server_exit_module(void);

// Put the freed page back in the cache for reuse
void page_cache_free(struct server_device *device, struct page *page_to_free) {
    spin_lock(&device->page_cache_lock);
    if (device->page_cache_size == 0) {
        device->page_cache = page_to_free;
    }
    else {
        // Point the new page to the current page_cache
        page_private(page_to_free) = (unsigned long) device->page_cache;
        device->page_cache = page_to_free;
    }
    device->page_cache_size++;
    spin_unlock(&device->page_cache_lock);
}

void page_cache_destroy(struct server_device *device) {
    struct page *tmp;

    spin_lock(&device->page_cache_lock);
    while (device->page_cache_size > 0) {
        tmp = device->page_cache;
        device->page_cache = (struct page *) page_private(device->page_cache);
        __free_page(tmp);
        device->page_cache_size--;
    }
    spin_unlock(&device->page_cache_lock);
}

// Get a previously allocated page or allocate a new one if necessary. Store pointers to next pages in page_private, like in drbd.
struct page *page_cache_alloc(struct server_device *device) {
    struct page *new_page;
    bool need_new_page = false;

    spin_lock(&device->page_cache_lock);
    if (device->page_cache_size == 0) {
        need_new_page = true;
    }
    else if (device->page_cache_size == 1) {
        // Set page_cache to NULL now that the list is empty
        new_page = device->page_cache;
        device->page_cache = NULL;
        device->page_cache_size--;
    }
    else {
        // Point page_cache to the next element in the list
        new_page = device->page_cache;
        device->page_cache = (struct page *) page_private(device->page_cache);
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
    } while (old_val < new && atomic_cmpxchg(old, old_val, new) != old_val);
}

// Waits may return before the condition is true because of a signal. Retry.
void wait_event_interruptible_with_retry(wait_queue_head_t *queue, int condition) {
    int ret;
    do {
        ret = wait_event_interruptible(*queue, condition);
        if (ret == -ERESTARTSYS) {
            printk(KERN_ERR "wait_event_interruptible_with_retry(queue) interrupted by signal, retrying");
        }
    }
    while (ret != 0);
}

// Semaphore down may return before it actually locks on the semaphore because of a signal. Retry.
void down_interruptible_with_retry(struct semaphore *sem) {
    int ret;
    do {
        ret = down_interruptible(sem);
        if (ret == -ERESTARTSYS) {
            printk(KERN_ERR "down_interruptible_with_retry(sem) interrupted by signal, retrying");
        }
    }
    while (ret != 0);
}

struct bio_data *alloc_bio_data(struct server_device *device) {
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
void ack_bio_to_user_without_executing(struct bio* bio) {
    bio->bi_status = BLK_STS_OK;
    bio_endio(bio);
}

// Returns the max int that a quorum agrees to. Note that since the leader itself must have fsync index >= followers' fsync index, the quorum size is f (not f+1).
// Assumes that the bio->bi_private field stores the write index
void process_follower_fsync_index(struct server_device *device, int follower_id, int follower_fsync_index) {
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

    // TODO: Locking here is overly strict. We just need to lock to change max index and lock when interacting with the kfifo
    // Loop through all blocked fsyncs if the max index has changed
    if (max_index_changed) {
        // printk(KERN_INFO "New max quorum write index: %d", device->max_replica_fsync_index);
#ifdef MEMORY_TRACKING
        device->max_fsyncs_pending_replication_size = umax(device->max_fsyncs_pending_replication_size, kfifo_len(&device->fsyncs_pending_replication));
        device->num_times_fsyncs_pending_replication_full += kfifo_is_full(&device->fsyncs_pending_replication);
#endif
        // Note: Because fsyncs_pending_replication is only best-effort ordered by write index, fsyncs may be stuck waiting for later fsyncs to be acked. This is fine since eventually all fsyncs will be acked anyway and concurrent fsyncs should be rare.
        while (kfifo_out_peek(&device->fsyncs_pending_replication, &bio, sizeof(struct bio*)) > 0) {
            bio_write_index = bio->bi_private;
            if (bio_write_index <= device->max_replica_fsync_index) {
                // printk(KERN_INFO "Fsync with write index %d satisfied", bio_data->write_index);
                // Ack the fsync to the user
                ack_bio_to_user_without_executing(bio);
                // Remove from queue. Assign to i to we don't get a warning that we're not checking the output
                i = kfifo_out(&device->fsyncs_pending_replication, &bio, sizeof(struct bio*));
                up(&device->sem1_fsyncs_pending_replication);
            }
            else {
                break;
            }
        }
    }
    spin_unlock(&device->replica_fsync_lock);
}

// TODO: Replace with op_is_sync() to handle REQ_SYNC?
bool requires_fsync(struct bio *bio) {
    return bio->bi_opf & (REQ_PREFLUSH | REQ_FUA);
}

unsigned int remove_fsync_flags(unsigned int bio_opf) {
    return bio_opf & ~REQ_PREFLUSH & ~REQ_FUA;
}

// Because we alloc pages when we receive the bios, we have to free them when it's done writing
void free_pages_end_io(struct bio *received_bio) {
    struct bio_data *bio_data = received_bio->bi_private;
    struct server_device *device = bio_data->device;
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

void disk_end_io(struct bio *bio) {
    struct bio_data *bio_data = bio->bi_private;
    struct server_device *device = bio_data->device;

    // If there are no more unacked ops, wake the submitter (it may have queued writes to submit)
    if (atomic_dec_and_test(&device->disk_unacked_ops)) {
        wake_up_interruptible(&device->submit_queue_wait_queue);
    }
}

void leader_disk_end_io(struct bio *shallow_clone) {
    // struct bio_data *bio_data = shallow_clone->bi_private;
    // printk(KERN_INFO "Leader end_io shallow clone %p bio data write index: %d, deep clone: %p", shallow_clone, bio_data->write_index, bio_data->deep_clone);
    disk_end_io(shallow_clone);
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

/**
 * How decrypting read works:
 *
 * 1. In map(), we create a clone of the read. At this point in time, the read does not have the actual data (which may be on disk).
 * 2. We submit the clone, triggering bio_end_io(), which calls this function.
 * 3. We release the clone with bio_put(). The data is fetched in the bio_vecs, so we decrypt it now for the read.
 * 4. We call bio_endio() on the original read, which returns the decrypted data to the user.
 */
void decrypt_at_end_io(struct bio *read_bio)
{
    struct bio_data *bio_data = clone->bi_private;

    // the cloned bio is no longer useful
    bio_put(clone);
    // decrypt
    enc_or_dec_bio(bio_data, READ);
    // release the read bio
    bio_endio(read_bio->base_bio);
}

void broadcast_bio(struct bio *clone) {
    int sent;
    struct bio_data *clone_bio_data = clone->bi_private;
    struct server_device *device = clone_bio_data->device;
    struct msghdr msg_header;
    struct kvec vec;
    struct socket_list *curr, *next;
    struct metadata_msg metadata;
    struct bio_vec bvec, chunked_bvec;
    struct bvec_iter iter;

    metadata.type = ROLLBACCINE_WRITE;
    metadata.bal = device->bal;
    metadata.write_index = clone_bio_data->write_index;
    metadata.num_pages = clone->bi_iter.bi_size / PAGE_SIZE;
    metadata.bi_opf = clone->bi_opf;
    metadata.sector = clone->bi_iter.bi_sector;

    // printk(KERN_INFO "Broadcasting write with write_index: %llu, is fsync: %d, bi_opf: %llu", metadata.write_index, requires_fsync(clone), metadata.bi_opf);
    WARN_ON(metadata.write_index == 0); // Should be at least one. Means that bio_data was retrieved incorrectly

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
}

// Thread that runs in the background and broadcasts bios
int broadcaster(void *args) {
    struct server_device *device = (struct server_device *)args;
    struct bio *clone;
    int num_bios_gotten;

    while (!device->shutting_down) {
#ifdef MEMORY_TRACKING
        device->max_broadcast_queue_size = umax(device->max_broadcast_queue_size, kfifo_len(&device->broadcast_queue));
        device->num_times_broadcast_queue_full += kfifo_is_full(&device->broadcast_queue);
#endif

        num_bios_gotten = kfifo_out(&device->broadcast_queue, &clone, sizeof(struct bio*));
        // printk(KERN_INFO "Checked bios, got %d", num_bios_gotten);
        if (num_bios_gotten == 0) {
            // Wait for new bios
            wait_event_interruptible(device->broadcast_queue_wait_queue, !kfifo_is_empty(&device->broadcast_queue));
            continue;
        }
        // Potentially wake those waiting on space in the kfifo queue
        up(&device->sem3_broadcast_queue);

        broadcast_bio(clone);
        network_end_io(clone);
    }

    return 0;
}

// Thread that runs in the background and submits bios to disk
int submitter(void *args) {
    struct server_device *device = (struct server_device *)args;
    struct bio *clone;
    int num_bios_gotten;
    bool is_fsync;

    while (!device->shutting_down) {
#ifdef MEMORY_TRACKING
        device->max_submit_queue_size = umax(device->max_submit_queue_size, kfifo_len(&device->submit_queue));
        device->num_times_submit_queue_full += kfifo_is_full(&device->submit_queue);
#endif

        num_bios_gotten = kfifo_out(&device->submit_queue, &clone, sizeof(struct bio *));
        // printk(KERN_INFO "Checked bios, got %d", num_bios_gotten);
        if (num_bios_gotten == 0) {
            // Wait for new bios
            wait_event_interruptible(device->submit_queue_wait_queue, !kfifo_is_empty(&device->submit_queue));
            continue;
        }
        // Potentially wake those waiting on space in the kfifo queue
        up(&device->sem2_submit_queue);

        // printk(KERN_INFO "Server %llu popped clone off submit queue", device->bal.id);

        // If the clone is an fsync and there are unacked ops, block
        // If there are any outstanding fsyncs, block until there are no outstanding operations (NOT FSYNCS!), which must include the outstanding fsync
        is_fsync = requires_fsync(clone);
        if ((is_fsync || atomic_read(&device->disk_unacked_fsync) != 0) && atomic_read(&device->disk_unacked_ops) != 0) {
            // printk(KERN_INFO "Server %llu clone blocked waiting for unacked ops", device->bal.id);
            wait_event_interruptible_with_retry(&device->submit_queue_wait_queue, atomic_read(&device->disk_unacked_ops) == 0);
            atomic_set(&device->disk_unacked_fsync, 0);
        }

        atomic_inc(&device->disk_unacked_ops);
        if (is_fsync) {
            atomic_inc(&device->disk_unacked_fsync);
        }

        // printk(KERN_INFO "Server %llu submitting clone to disk", device->bal.id);
        submit_bio_noacct(clone);
    }

    return 0;
}

struct bio* shallow_bio_clone(struct server_device *device, struct bio *bio_src) {
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

struct bio* deep_bio_clone(struct server_device *device, struct bio *bio_src) {
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

static int server_map(struct dm_target *ti, struct bio *bio) {
    bool is_fsync = false;
    bool is_cloned = false;
    struct server_device *device = ti->private;
    struct bio *deep_clone, *shallow_clone; // deep clone is for the network, shallow clone is for submission to disk when necessary
    struct bio_data *bio_data;

    bio_set_dev(bio, device->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
    // Set shared data between clones
    bio_data = alloc_bio_data(device);

    // initialize fields for bio data that will be useful for encryption
    bio_data->base_bio = bio;
    bio_data->device = device;

    // Copy bio if it's a write
    if (device->is_leader) {
        switch (bio_data_dir(bio)) {
            case WRITE:
                // ENCRYPTION LOGIC
                uint64_t original_sector = bio->bi_iter.bi_sector;
                unsigned int original_size = bio->bi_iter.bi_size;
                unsigned int original_idx = bio->bi_iter.bi_idx;

                // Encrypt
                enc_or_dec_bio(bio_data, WRITE);

                // Reset to the original beginning values of the bio, otherwise nothing will be written
                bio->bi_iter.bi_sector = original_sector;
                bio->bi_iter.bi_size = original_size;
                bio->bi_iter.bi_idx = original_idx;

                // Create the network clone
                deep_clone = deep_bio_clone(device, bio);
                if (!deep_clone) {
                    printk(KERN_ERR "Could not create deep clone");
                    return DM_MAPIO_REMAPPED;
                }

                // Create the disk clone
                shallow_clone = shallow_bio_clone(device, deep_clone);
                if (!shallow_clone) {
                    printk(KERN_ERR "Could not create shallow clone");
                    return DM_MAPIO_REMAPPED;
                }
                // Set end_io so once this write completes, queued writes can be unblocked
                shallow_clone->bi_end_io = leader_disk_end_io;

                
                bio_data->device = device;
                bio_data->shallow_clone = shallow_clone;
                bio_data->deep_clone = deep_clone;
                atomic_set(&bio_data->ref_counter, 2);
                deep_clone->bi_private = bio_data;
                shallow_clone->bi_private = bio_data;

                is_cloned = true;
                is_fsync = requires_fsync(bio);

                // Reserve space on kfifo queues with semaphores in case it is full
                if (is_fsync) {
                    // printk(KERN_INFO "Server received fsync with bi_opf: %u", bio->bi_opf);
                    down_interruptible_with_retry(&device->sem1_fsyncs_pending_replication);
                }
                down_interruptible_with_retry(&device->sem2_submit_queue);
                down_interruptible_with_retry(&device->sem3_broadcast_queue);

                // Increment indices, place ops on queue, submit cloned ops to disk
                spin_lock(&device->index_lock);
                // Increment write index
                bio_data->write_index = ++device->write_index;
                // Add write to submit queue and actually submit it outside spinlock to avoid deadlock from end_io acquiring the index_lock
                kfifo_in(&device->submit_queue, &shallow_clone, sizeof(struct bio *));
                // printk(KERN_INFO "Inserted clone %p, write index: %d", shallow_clone, bio_data->write_index);
                if (is_fsync) {
                    // Add original bio to fsyncs blocked on replication. Remove any fsync flags from the original so it won't trigger a disk IO.
                    bio->bi_opf = remove_fsync_flags(bio->bi_opf);
                    bio->bi_private = bio_data->write_index;  // HACK: Store the write index in this fsync's bi_private field so it can be checked when network fsyncs are being acknowledged
                    kfifo_in(&device->fsyncs_pending_replication, &bio, sizeof(struct bio *));
                }
                // If we're not multithreading the network, then we can use the single socket to preserve total order across the network, so add to the queue while holding the index lock
                #ifndef MULTITHREADED_NETWORK
                        kfifo_in(&device->broadcast_queue, &deep_clone, sizeof(struct bio *));
                #endif
                        spin_unlock(&device->index_lock);

                        // Wake up threads that process items on the queue
                        wake_up_interruptible(&device->submit_queue_wait_queue);
                #ifdef MULTITHREADED_NETWORK
                        kfifo_in_spinlocked(&device->broadcast_queue, &deep_clone, sizeof(struct bio *), &device->broadcast_queue_lock);
                #endif
                        wake_up_interruptible(&device->broadcast_queue_wait_queue);

                // Immediately ack non-fsync writes to the user. The writes are cloned and either queued or submitted
                if (!is_fsync) {
                    ack_bio_to_user_without_executing(bio);
                }
                break;
        case READ:
            // Create a clone that calls decrypt_at_end_io when the IO returns with actual read data
            shallow_clone = shallow_bio_clone(device, deep_clone);
            if (!shallow_clone) {
                printk(KERN_ERR "Could not create shallow clone");
                // TODO diff error return
                return DM_MAPIO_REMAPPED;
            }
            shallow_clone->bi_private = bio_data;
            shallow_clone->bi_end_io = decrypt_at_end_io;
            shallow_clone->bi_opf = bio->bi_opf;
            shallow_clone->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

            // Submit the clone, triggering end_io, where the read will actually have data and we can decrypt
            submit_bio_noacct(shallow_clone);

            return DM_MAPIO_SUBMITTED;
        }
    }

    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    // Anything we clone and submit ourselves is marked submitted
    return is_cloned ? DM_MAPIO_SUBMITTED : DM_MAPIO_REMAPPED;
}


static inline unsigned char *checksum_index(struct bio_data *bio_data, sector_t index) {
    return &bio_data->device->checksums[index * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE)];
}

static inline unsigned char *iv_index(struct bio_data *bio_data, sector_t index) {
    return &bio_data->device->checksums[index * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE) + AES_GCM_AUTH_SIZE];
}

static int enc_or_dec_bio(struct bio_data *bio_data, int enc_or_dec)
{
    int ret;
    struct bio_vec bv;
    while (bio_data->bi_iter.bi_size)
    {
        struct aead_request *req;
        struct scatterlist sg[4];
        uint64_t curr_sector = bio_data->base_bio->bi_iter.bi_sector;
        DECLARE_CRYPTO_WAIT(wait);
        bv = bio_iter_iovec(bio_data->base_bio, bio_data->base_bio->bi_iter);
        switch (enc_or_dec)
        {
        case READ:
            if (*checksum_index(bio_data, curr_sector) == 0) {
            return 0;
        }
            break;
        default:
            break;
        }
        memcpy(iv_index(bio_data, curr_sector), "123456789012", AES_GCM_IV_SIZE);
        sg_init_table(sg, 4);
        sg_set_buf(&sg[0], &curr_sector, sizeof(uint64_t));
        sg_set_buf(&sg[1], iv_index(bio_data, curr_sector), AES_GCM_IV_SIZE);
        sg_set_page(&sg[2], bv.bv_page, SECTOR_SIZE, bv.bv_offset);
        sg_set_buf(&sg[3], checksum_index(bio_data, curr_sector), AES_GCM_AUTH_SIZE);

        // /* AEAD request:
        //  *  |----- AAD -------|------ DATA -------|-- AUTH TAG --|
        //  *  | (authenticated) | (auth+encryption) |              |
        //  *  | sector_LE |  IV |  sector in/out    |  tag in/out  |
        //  */
        req = aead_request_alloc(bio_data->device->tfm, GFP_KERNEL);
        if (!req)
        {
            printk(KERN_INFO "aead request allocation failed");
            aead_request_free(req);
            ret = -ENOMEM;
            goto exit;
        }
        aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
        // sector + iv size
        aead_request_set_ad(req, sizeof(uint64_t) + AES_GCM_IV_SIZE);
        switch (enc_or_dec)
        {
        case WRITE:
            aead_request_set_crypt(req, sg, sg, SECTOR_SIZE, iv_index(io, curr_sector));
            ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
            break;
        case READ:
            aead_request_set_crypt(req, sg, sg, SECTOR_SIZE + AES_GCM_AUTH_SIZE, iv_index(io, curr_sector));
            ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
            break;
        }

        if (ret)
        {
            if (ret == -EBADMSG)
            {
                printk(KERN_INFO "invalid integrity check");
            }
            else
            {
                printk(KERN_INFO "encryption/decryption failed");
            }
            aead_request_free(req);
            goto exit;
        }
	aead_request_free(req);
    bio_advance_iter(bio_data, &bio_data->base_bio->bi_iter, SECTOR_SIZE);
    }
    return 0;
exit:
    cleanup(bio_data->device);
    return ret;
}

void kill_thread(struct socket *sock) {
    // Shut down the socket, causing the thread to unblock (if it was blocked on a socket)
    if (sock != NULL) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
    }
}

// Function used by all listening sockets to block and listen to messages
void blocking_read(struct server_device *device, struct socket *sock) {
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

        // printk(KERN_INFO "Received metadata sector: %llu, num pages: %llu, bi_opf: %llu, is fsync: %llu", metadata.sector, metadata.num_pages, metadata.bi_opf, metadata.bi_opf&(REQ_PREFLUSH | REQ_FUA));

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
        if (requires_fsync(received_bio)) {
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

        // 6. Submit bio
        down_interruptible_with_retry(&device->sem2_submit_queue);
        kfifo_in(&device->submit_queue, &received_bio, sizeof(struct bio *));
        wake_up_interruptible(&device->submit_queue_wait_queue);
    }

    printk(KERN_INFO "Shutting down, exiting blocking read");
    kernel_sock_shutdown(sock, SHUT_RDWR);
    // TODO: Releasing the socket is problematic because it makes future calls to shutdown() crash, which may happen if the connection dies, the socket is freed, and later the destructor tries to shut it down.
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
    struct file* sock_file;
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
    }
    else {
        // Wait until TLS handshake is done
        printk(KERN_INFO "Client waiting for TLS handshake to complete");
        timeout_remainder = wait_for_completion_timeout(&tls_handshake_completed, ROLLBACCINE_TLS_TIMEOUT);
        if (!timeout_remainder) {
            printk(KERN_ERR "Client TLS handshake timed out");
            return 0;
        }
        else {
            printk(KERN_INFO "Client TLS handshake completed");
        }
    }
#endif

    blocking_read(thread_params->device, thread_params->sock);

    cleanup:
    kfree(thread_params);
    return 0;
}

int start_client_to_server(struct server_device *device, char *addr, ushort port) {
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
    }
    else {
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
int listen_for_connections(void* args) {
    struct listen_thread_params *thread_params = (struct listen_thread_params *)args;
    struct server_device *device = thread_params->device;
    struct socket *new_sock;
    struct accepted_thread_params* new_thread_params;
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
int start_server(struct server_device *device, ushort port) {
    struct listen_thread_params *thread_params;
    struct socket_list *sock_list;
    struct sockaddr_in addr;
    struct task_struct *listener_thread;
    int error;
    int opt = 1;
    sockptr_t kopt = {.kernel = (char*)&opt, .is_kernel = 1};

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

static void server_status(struct dm_target *ti, status_type_t type, unsigned int status_flags, char *result, unsigned int maxlen) {
    struct server_device *device = ti->private;
    unsigned int sz = 0; // Required by DMEMIT

    DMEMIT("\n");
    
#ifndef MEMORY_TRACKING
    DMEMIT("Memory tracking is NOT ON! The following statistics will be unreliable.\n");
#endif
    DMEMIT("Num bio pages not freed: %d\n", atomic_read(&device->num_bio_pages_not_freed));
    DMEMIT("Num bio_data not freed: %d\n", atomic_read(&device->num_bio_data_not_freed));
    DMEMIT("Num deep clones not freed: %d\n", atomic_read(&device->num_deep_clones_not_freed));
    DMEMIT("Num shallow clones not freed: %d\n", atomic_read(&device->num_shallow_clones_not_freed));
    DMEMIT("Max outstanding num bio pages: %d\n", atomic_read(&device->max_outstanding_num_bio_pages));
    DMEMIT("Max outstanding num bio_data: %d\n", atomic_read(&device->max_outstanding_num_bio_data));
    DMEMIT("Max outstanding num deep clones: %d\n", atomic_read(&device->max_outstanding_num_deep_clones));
    DMEMIT("Max outstanding num shallow clones: %d\n", atomic_read(&device->max_outstanding_num_shallow_clones));
    DMEMIT("Num times fsync_pending_replication full: %d\n", device->num_times_fsyncs_pending_replication_full);
    DMEMIT("Num times submit_queue full: %d\n", device->num_times_submit_queue_full);
    DMEMIT("Num times broadcast_queue full: %d\n", device->num_times_broadcast_queue_full);
    DMEMIT("Max number of elements in fsync_pending_replication: %lu\n", device->max_fsyncs_pending_replication_size / sizeof(struct bio*));
    DMEMIT("Max number of elements in submit_queue: %lu\n", device->max_submit_queue_size / sizeof(struct bio*));
    DMEMIT("Max number of elements in broadcast_queue: %lu\n", device->max_broadcast_queue_size / sizeof(struct bio*));
}

// Arguments: 0 = underlying device name, like /dev/ram0. 1 = f, 2 = n, 3 = id, 4 = is_leader. 5 = listen port. 6+ = server addr & ports
static int server_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    struct server_device *device;
    struct task_struct *broadcast_thread, *submit_thread;
    ushort port;
    int error;
    int i;
    unsigned long projected_bytes_used = 0;

    device = kmalloc(sizeof(struct server_device), GFP_KERNEL);
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

    init_waitqueue_head(&device->broadcast_queue_wait_queue);
    spin_lock_init(&device->broadcast_queue_lock);
    sema_init(&device->sem3_broadcast_queue, ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE / sizeof(struct bio*));
    error = kfifo_alloc(&device->broadcast_queue, ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Error creating bio_kfifo");
        return error;
    }
    projected_bytes_used += ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE;

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
    sema_init(&device->sem1_fsyncs_pending_replication, ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE / sizeof(struct bio*));
    error = kfifo_alloc(&device->fsyncs_pending_replication, ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Error creating fsyncs_pending_replication");
        return error;
    }
    projected_bytes_used += ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE;
    
    atomic_set(&device->disk_unacked_ops, 0);
    atomic_set(&device->disk_unacked_fsync, 0);
    init_waitqueue_head(&device->submit_queue_wait_queue);
    sema_init(&device->sem2_submit_queue, ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE / sizeof(struct bio*));
    error = kfifo_alloc(&device->submit_queue, ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Error creating submit_queue");
        return error;
    }
    projected_bytes_used += ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE;

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
        error = kstrtou16(argv[i+1], 10, &port);
        if (error < 0) {
            printk(KERN_ERR "Error parsing port");
            return error;
        }
        printk(KERN_INFO "Starting thread to connect to server at port: %u", port);
        start_client_to_server(device, argv[i], port);
    }

    // Start broadcast thread
    if (device->is_leader) {
        broadcast_thread = kthread_run(broadcaster, device, "broadcast thread");
        if (IS_ERR(broadcast_thread)) {
            printk(KERN_ERR "Error creating broadcast thread");
            return -1;
        }
    }

    // Start submit thread
    submit_thread = kthread_run(submitter, device, "submit thread");
    if (IS_ERR(submit_thread)) {
        printk(KERN_ERR "Error creating submit thread");
        return -1;
    }

    // Set up AEAD Encryption/Decryption
    device->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(device->tfm))
    {
        printk(KERN_ERR "Cannot allocate transform");
        error = -ENOMEM;
        goto out;
    }

    crypto_aead_setauthsize(device->tfm, AES_GCM_AUTH_SIZE);

    device->key = "1234567890123456";
    if (crypto_aead_setkey(device->tfm, device->key, KEY_SIZE))
    {
        printk(KERN_ERR "Key could not be set");
        error = -EAGAIN;
        goto out;
    }

    device->checksums = kvmalloc_array(get_capacity(device->dev->bdev->bd_disk), AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE, GFP_KERNEL | __GFP_ZERO);
    if (!device->checksums) {
        printk(KERN_ERR "Cannot allocate checksums");
        ret = -ENOMEM;
        goto out;
    }
#ifdef MEMORY_TRACKING
    atomic_set(&device->num_bio_data_not_freed, 0);
    atomic_set(&device->num_bio_pages_not_freed, 0);
    atomic_set(&device->num_deep_clones_not_freed, 0);
    atomic_set(&device->num_shallow_clones_not_freed, 0);
    atomic_set(&device->max_outstanding_num_bio_data, 0);
    atomic_set(&device->max_outstanding_num_bio_pages, 0);
    atomic_set(&device->max_outstanding_num_deep_clones, 0);
    atomic_set(&device->max_outstanding_num_shallow_clones, 0);
    device->num_times_fsyncs_pending_replication_full = 0;
    device->num_times_submit_queue_full = 0;
    device->num_times_broadcast_queue_full = 0;
    device->max_fsyncs_pending_replication_size = 0;
    device->max_submit_queue_size = 0;
    device->max_broadcast_queue_size = 0;
#endif

    // Enable FUA and PREFLUSH flags
    ti->num_flush_bios = 1;
    ti->flush_supported = 1;

    ti->private = device;

    printk(KERN_INFO "Server %llu constructed, projected to use %luMB", device->bal.id, projected_bytes_used >> 20);
    return 0;

out:
    cleanup(device);
    return error;
}

void cleanup(struct server_device *device)
{
    if (device == NULL)
        return;
    if (device->checksums)
        kvfree(device->checksums);
    if (device->tfm)
        crypto_free_aead(device->tfm);
}

static void server_destructor(struct dm_target *ti) {
    struct socket_list *curr, *next;
    struct server_device *device = ti->private;
    if (device == NULL)
        return;

    // Warning: Changing this boolean should technically be atomic. I don't think it's a big deal tho, since by the time shutting_down is true, we don't care what the protocol does. •Ideally* it shuts down gracefully.
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


    // Note: I'm not sure how to free theses queues which may have outstanding bios. Hopefully nothing breaks horribly
    kfifo_free(&device->broadcast_queue);
    kfifo_free(&device->fsyncs_pending_replication);
    kfifo_free(&device->submit_queue);
    dm_put_device(ti, device->dev);
    bioset_exit(&device->bs);
    // mempool_destroy(device->page_mempool);
    // mempool_destroy(device->bio_data_mempool);
    cleanup(device);
    kmem_cache_destroy(device->bio_data_cache);
    page_cache_destroy(device);
    kfree(device);

    printk(KERN_INFO "Server destructed");
}

static struct target_type server_target = {
    .name = MODULE_NAME,
    .version = {0, 1, 0},
    .features = DM_TARGET_INTEGRITY,  // TODO: Figure out what this means
    .module = THIS_MODULE,
    .ctr = server_constructor,
    .dtr = server_destructor,
    .map = server_map,
    .status = server_status,
};

int __init server_init_module(void) {
    int r = dm_register_target(&server_target);
    printk(KERN_INFO "server module loaded");
    return r;
}

void server_exit_module(void) {
    dm_unregister_target(&server_target);
    printk(KERN_INFO "server module unloaded");
}

module_init(server_init_module);
module_exit(server_exit_module);
MODULE_LICENSE("GPL");
