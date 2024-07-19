/**
 * This file is heavily inspired by https://github.com/sysprog21/kecho/tree/master and https://github.com/LINBIT/drbd.
 * Note: In order to kill threads on shutdown, we create a list of all open sockets that threads could be blocked on, and close them on shutdown.
 *       We also set shutting_down = true so a thread who returns from a blocking operation sees it and exits.
 *       We don't use kthread_stop() because it's blocking, and we need to close the sockets, which wakes the threads up before they see they should stop.
 */

#include <linux/device-mapper.h>
#include <linux/inet.h>  // For in4_pton to translate IP addresses from strings
#include <linux/init.h>
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/handshake.h> // For TLS

#define ROLLBACCINE_MAX_CONNECTIONS 10
#define ROLLBACCINE_ENCRYPT_GRANULARITY 4096 // Number of bytes to encrypt, hash, or send at a time
#define ROLLBACCINE_RETRY_TIMEOUT 5000 // Number of milliseconds before client attempts to connect to a server again
#define ROLLBACCINE_INIT_WRITE_INDEX 0
#define ROLLBACCINE_HASH_SIZE 256
#define ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE 1024 // Number of bios that can be outstanding between main threads and network broadcast thread. Must be power of 2, according to kfifo specs
#define ROLLBACCINE_PAGE_POOL_SIZE 1024 // Number of pages to be allocated for the page pool. Should be larger than the set of pages used by bios in-flight.
#define ROLLBACCINE_BIO_DATA_POOL_SIZE 1024 // Number of bio_data structs to be allocated. Should be larger than the set of bios in-flight at any time.
#define ROLLBACCINE_TLS_TIMEOUT 5000 // Number of milliseconds to wait for TLS handshake to complete
#define MIN_IOS 64
#define MODULE_NAME "server"

// #define TLS_ON

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
    mempool_t *bio_data_mempool;
    mempool_t *page_mempool;
    bool is_leader;
    bool shutting_down; // Set to true when user triggers shutdown. All threads check this and abort if true. Used instead of kthread_should_stop(), since the function that flips that boolean to true (kthread_stop()) is blocking, which creates a race condition when we kill the socket & also wait for the thread to stop.
    int f;
    int n;

    struct ballot bal;
    int write_index; // Doesn't need to be atomic because only the broadcast thread will modify this
    spinlock_t index_lock; // Must be obtained for any operation modifying write_index and queues ordered by those indices

    // Logic for fsyncs blocking on replication
    // IMPORTANT: If both replica_fsync_lock and index_lock must be obtained, obtain index_lock first.
    spinlock_t replica_fsync_lock;
    int* replica_fsync_indices; // Len = n
    int max_replica_fsync_index;
    struct kfifo fsyncs_pending_replication; // List of all fsyncs waiting for replication. Best-effort ordered by write index.

    // Logic for writes that block on previous fsyncs going to disk
    int disk_unacked_ops; // Number of operations yet to be acked by disk
    struct kfifo queued_ops; // List of all blocked ops. Ordered by write index.
    wait_queue_head_t submit_queue_wait_queue;
    struct kfifo submit_queue; // Operations about to be submitted to disk, queued in here to avoid deadlock when bio_end_io is called on the same thread. Lock writes with index_lock, reads with submit_queue_out_lock.
    
    // Communication between main threads and the networking thread
    wait_queue_head_t broadcast_queue_wait_queue;
    spinlock_t broadcast_queue_lock;
    struct kfifo broadcast_queue;

    // Sockets, tracked so we can kill them on exit.
    struct list_head server_sockets;
    struct list_head client_sockets;

    // Connected sockets. Should be a subset of the sockets above. Handy for broadcasting
    // TODO: Need to figure out network handshake so we know who we're talking to.
    spinlock_t connected_sockets_lock;
    struct list_head connected_sockets;
};

// Associated data for each bio, shared between clones
struct bio_data {
    struct server_device *device;
    struct bio *deep_clone;
    struct bio *shallow_clone;
    int write_index;
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
void broadcast_bio(struct bio *clone);
int broadcaster(void *args);
int submitter(void *args);
struct bio* shallow_bio_clone(struct server_device *device, struct bio *bio_src);
struct bio* deep_bio_clone(struct server_device *device, struct bio *bio_src);
void kill_thread(struct socket *sock);
void blocking_read(struct server_device *device, struct socket *sock);
#ifdef TLS_ON
void on_tls_handshake_done(void *data, int status, key_serial_t peerid);
#endif
int connect_to_server(void *args);
int start_client_to_server(struct server_device *device, ushort port);
int listen_to_accepted_socket(void *args);
int listen_for_connections(void *args);
int start_server(struct server_device *device, ushort port);
int __init server_init_module(void);
void server_exit_module(void);

    struct bio_data *alloc_bio_data(struct server_device *device) {
    struct bio_data *data = mempool_alloc(device->bio_data_mempool, GFP_KERNEL);
    if (!data) {
        printk(KERN_ERR "Could not allocate bio_data");
        return NULL;
    }
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

    // Loop through all blocked fsyncs if the max index has changed
    if (max_index_changed) {
        // printk(KERN_INFO "New max quorum write index: %d", device->max_replica_fsync_index);
        // Note: Because fsyncs_pending_replication is only best-effort ordered by write index, fsyncs may be stuck waiting for later fsyncs to be acked. This is fine since eventually all fsyncs will be acked anyway and concurrent fsyncs should be rare.
        while (kfifo_out_peek(&device->fsyncs_pending_replication, &bio, sizeof(struct bio*)) > 0) {
            bio_write_index = bio->bi_private;
            if (bio_write_index <= device->max_replica_fsync_index) {
                // printk(KERN_INFO "Fsync with write index %d satisfied", bio_data->write_index);
                // Ack the fsync to the user
                ack_bio_to_user_without_executing(bio);
                // Remove from queue. Assign to i to we don't get a warning that we're not checking the output
                i = kfifo_out(&device->fsyncs_pending_replication, &bio, sizeof(struct bio*));
            }
            else {
                break;
            }
        }
    }
    spin_unlock(&device->replica_fsync_lock);
}

bool requires_fsync(struct bio *bio) {
    return bio->bi_opf & (REQ_PREFLUSH | REQ_FUA);
}

unsigned int remove_fsync_flags(unsigned int bio_opf) {
    return bio_opf & ~REQ_PREFLUSH & ~REQ_FUA;
}

// Because we alloc pages when we receive the bios, we haev to free them when it's done writing
void free_pages_end_io(struct bio *received_bio) {
    struct bio_data *bio_data = received_bio->bi_private;
    struct server_device *device = bio_data->device;
    struct bio_vec bvec;
    struct bvec_iter iter;

    bio_for_each_segment(bvec, received_bio, iter) {
        mempool_free(bvec.bv_page, device->page_mempool);
        // __free_page(bvec.bv_page); 
    }
    mempool_free(bio_data, device->bio_data_mempool);
    bio_put(received_bio);
}

// Decrement the reference counter tracking the number of clones. Free both deep & shallow clones when it hits 0.
void try_free_clones(struct bio *clone) {
    struct bio_data *bio_data = clone->bi_private;
    // If ref_counter == 0
    if (atomic_dec_and_test(&bio_data->ref_counter)) {
        // printk(KERN_INFO "Freeing clone, write index: %d", deep_clone_bio_data->write_index);
        bio_put(bio_data->shallow_clone);
        free_pages_end_io(bio_data->deep_clone);
    } else {
        // printk(KERN_INFO "Decrementing clone ref count to %d, write index: %d", atomic_read(&deep_clone_bio_data->ref_counter), deep_clone_bio_data->write_index);
    }
}

void disk_end_io(struct bio *bio) {
    struct bio_data *bio_data = bio->bi_private;
    struct server_device *device = bio_data->device;
    struct bio *next_bio;

    // Decrement counters and dequeue
    spin_lock(&device->index_lock);
    device->disk_unacked_ops--;
    // printk(KERN_INFO "Disk write %d completed, %d unacked ops, will be inaccurate on replicas", bio_data->write_index, device->disk_unacked_ops);
    if (device->disk_unacked_ops == 0) {
        // printk(KERN_INFO "Popping operations off queue");
        while (kfifo_out(&device->queued_ops, &next_bio, sizeof(struct bio *)) > 0) {
            // printk(KERN_INFO "Popped write %d off queue", next_bio_data->write_index);
            // Add write to submit queue and actually submit it outside spinlock to avoid deadlock from end_io acquiring the index_lock
            kfifo_in(&device->submit_queue, &next_bio, sizeof(struct bio *));
            device->disk_unacked_ops++;

            if (requires_fsync(next_bio)) {
                break;
            }
        }
    }
    spin_unlock(&device->index_lock);

    wake_up_interruptible(&device->submit_queue_wait_queue);
}

void leader_disk_end_io(struct bio *shallow_clone) {
    // struct bio_data *bio_data = shallow_clone->bi_private;
    // printk(KERN_INFO "Leader shallow clone %p bio data write index: %d, deep clone: %p", shallow_clone, bio_data->write_index, bio_data->deep_clone);
    disk_end_io(shallow_clone);
    // Unlike replica_disk_end_io, the clone is sharing data with the clone used for networking, so we have to check if we can free
    try_free_clones(shallow_clone);
}

void replica_disk_end_io(struct bio *received_bio) {
    disk_end_io(received_bio);
    free_pages_end_io(received_bio);
}

void network_end_io(struct bio *deep_clone) {
    // See if we can free
    // printk(KERN_INFO "Network broadcast %d completed", deep_clone_bio_data->write_index);
    try_free_clones(deep_clone);
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

    spin_lock(&device->connected_sockets_lock);
    list_for_each_entry_safe(curr, next, &device->connected_sockets, list) {
        vec.iov_base = &metadata;
        vec.iov_len = sizeof(struct metadata_msg);

        // 1. Send metadata
        // Keep retrying send until the whole message is sent
        while (vec.iov_len > 0) {
            sent = kernel_sendmsg(curr->sock, &msg_header, &vec, 1, vec.iov_len);
            if (sent <= 0) {
                printk(KERN_ERR "Error sending message, aborting send");
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
                    printk(KERN_ERR "Error sending message, aborting send");
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
    spin_unlock(&device->connected_sockets_lock);
}

// Thread that runs in the background and broadcasts bios
int broadcaster(void *args) {
    struct server_device *device = (struct server_device *)args;
    struct bio *clone;
    int num_bios_gotten;

    while (!device->shutting_down) {
        num_bios_gotten = kfifo_out(&device->broadcast_queue, &clone, sizeof(struct bio*));
        // printk(KERN_INFO "Checked bios, got %d", num_bios_gotten);
        if (num_bios_gotten == 0) {
            // Wait for new bios
            wait_event_interruptible(device->broadcast_queue_wait_queue, !kfifo_is_empty(&device->broadcast_queue));
            continue;
        }

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

    while (!device->shutting_down) {
        num_bios_gotten = kfifo_out(&device->submit_queue, &clone, sizeof(struct bio *));
        // printk(KERN_INFO "Checked bios, got %d", num_bios_gotten);
        if (num_bios_gotten == 0) {
            // Wait for new bios
            wait_event_interruptible(device->submit_queue_wait_queue, !kfifo_is_empty(&device->submit_queue));
            continue;
        }

        // if (device->is_leader) {
        //     printk(KERN_INFO "Got clone %p", clone);
        // }
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

    clone->bi_iter.bi_sector = bio_src->bi_iter.bi_sector;
    return clone;
}

// Note: This does NOT clone the bio_data!
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

    clone->bi_iter.bi_sector = bio_src->bi_iter.bi_sector;

    // TODO: dm-crypt uses alloc_pages first to alloc 2^x pages, then mempool_alloc for the rest. We may want to do that too for performance.
    bio_for_each_segment(bvec, bio_src, iter) {
        page = mempool_alloc(device->page_mempool, GFP_KERNEL);
        // page = alloc_page(GFP_KERNEL);
        if (!page) {
            bio_put(clone);
            return NULL;
        }
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

    // Copy bio if it's a write
    if (device->is_leader && bio_data_dir(bio) == WRITE) {
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

        // Set shared data between clones
        bio_data = alloc_bio_data(device);
        bio_data->device = device;
        bio_data->shallow_clone = shallow_clone;
        bio_data->deep_clone = deep_clone;
        atomic_set(&bio_data->ref_counter, 2);
        deep_clone->bi_private = bio_data;
        shallow_clone->bi_private = bio_data;

        is_cloned = true;
        is_fsync = requires_fsync(bio);

        // Increment indices, place ops on queue, submit cloned ops to disk
        spin_lock(&device->index_lock);
        // Increment write index
        bio_data->write_index = ++device->write_index;
        // Queue if the queue is non-empty or if this is an fsync and there are outstanding operations
        if (!kfifo_is_empty(&device->queued_ops) || (is_fsync && device->disk_unacked_ops > 0)) {
            // printk(KERN_INFO "Write %d blocked on prev fsync, is fsync: %d", bio_data->write_index, is_fsync);
            kfifo_in(&device->queued_ops, &shallow_clone, sizeof(struct bio *));
        }
        else {
            // printk(KERN_INFO "Write %d submitted to disk, is fsync: %d", bio_data->write_index, is_fsync);
            // Add write to submit queue and actually submit it outside spinlock to avoid deadlock from end_io acquiring the index_lock
            kfifo_in(&device->submit_queue, &shallow_clone, sizeof(struct bio *));
            // printk(KERN_INFO "Inserted clone %p, write index: %d", shallow_clone, bio_data->write_index);
            device->disk_unacked_ops++;
        }
        spin_unlock(&device->index_lock);

        wake_up_interruptible(&device->submit_queue_wait_queue);

        // Add original bio to fsyncs blocked on replication. Remove any fsync flags from the original so it won't trigger a disk IO.
        if (is_fsync) {
            bio->bi_opf = remove_fsync_flags(bio->bi_opf);
            bio->bi_private = bio_data->write_index; // HACK: Store the write index in this fsync's bi_private field so it can be checked when network fsyncs are being acknowledged
            kfifo_in_spinlocked(&device->fsyncs_pending_replication, &bio, sizeof(struct bio *), &device->replica_fsync_lock);
        }
        else {
            // Immediately ack non-fsync writes to the user. The writes are cloned and either queued or submitted
            ack_bio_to_user_without_executing(bio);
        }

        // Add to networking queue
        kfifo_in_spinlocked(&device->broadcast_queue, &deep_clone, sizeof(struct bio*), &device->broadcast_queue_lock);
        wake_up_interruptible(&device->broadcast_queue_wait_queue);
    }

    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    // Anything we clone and submit ourselves is marked submitted
    return is_cloned ? DM_MAPIO_SUBMITTED : DM_MAPIO_REMAPPED;
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

    msg_header.msg_name = 0;
    msg_header.msg_namelen = 0;
    msg_header.msg_control = NULL;
    msg_header.msg_controllen = 0;
    msg_header.msg_flags = MSG_WAITALL | MSG_NOSIGNAL;

    while (!device->shutting_down) {
        // 1. Receive metadata message
        vec.iov_base = &metadata;
        vec.iov_len = sizeof(struct metadata_msg);

        received = kernel_recvmsg(sock, &msg_header, &vec, vec.iov_len, vec.iov_len, msg_header.msg_flags);
        if (received <= 0) {
            printk(KERN_ERR "Error reading from socket");
            break;
        }
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
            page = mempool_alloc(device->page_mempool, GFP_KERNEL);
        //     page = alloc_page(GFP_KERNEL);
            if (page == NULL) {
                printk(KERN_ERR "Error allocating page");
                break;
            }
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

            // Keep retrying send until the whole message is sent
            while (vec.iov_len > 0) {
                sent = kernel_sendmsg(sock, &msg_header, &vec, 1, vec.iov_len);
                if (sent <= 0) {
                    printk(KERN_ERR "Error sending message, aborting send");
                    break;
                } else {
                    vec.iov_base += sent;
                    vec.iov_len -= sent;
                }
            }
            // printk(KERN_INFO "Acked fsync for write index: %llu", metadata.write_index);
        }

        // 6. Submit bio
        spin_lock(&device->index_lock);
        if (!kfifo_is_empty(&device->queued_ops) || (requires_fsync(received_bio) && device->disk_unacked_ops > 0)) {
            // printk(KERN_INFO "Replica write %llu blocked on prev fsync, is fsync: %d", metadata.write_index, requires_fsync(received_bio));
            kfifo_in(&device->queued_ops, &received_bio, sizeof(struct bio *));
        } else {
            // printk(KERN_INFO "Replica write %llu submitted to disk, is fsync: %d", metadata.write_index, requires_fsync(received_bio));
            // Add write to submit queue and actually submit it outside spinlock to avoid deadlock from end_io acquiring the index_lock
            kfifo_in(&device->submit_queue, &received_bio, sizeof(struct bio *));
            device->disk_unacked_ops++;
        }
        spin_unlock(&device->index_lock);

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
    spin_lock(&thread_params->device->connected_sockets_lock);
    list_add(&sock_list->list, &thread_params->device->connected_sockets);
    spin_unlock(&thread_params->device->connected_sockets_lock);

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
    tls_args.ta_peername = "127.0.0.1"; // TODO: Replace with dynamic address
    tls_args.ta_keyring = 812650863;    // TODO: Replace with read from file
    tls_args.ta_my_cert = 311286881;
    tls_args.ta_my_privkey = 58895732;
    error = tls_client_hello_x509(&tls_args, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Client error starting TLS handshake: %d", error);
    }
    else {
        // Wait until TLS handshake is done
        printk(KERN_INFO "Client waiting for TLS handshake to complete");
        timeout_remainder = wait_for_completion_timeout(&tls_handshake_completed, ROLLBACCINE_TLS_TIMEOUT);
        if (!timeout_remainder) {
            printk(KERN_ERR "Client TLS handshake timed out");
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

int start_client_to_server(struct server_device *device, ushort port) {
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
    if (in4_pton("127.0.0.1", 10, (u8 *)&thread_params->addr.sin_addr.s_addr, '\n', NULL) == 0) {
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
    tls_args.ta_peername = "127.0.0.1";  // TODO: Replace with dynamic address
    tls_args.ta_keyring = 812650863;     // TODO: Replace with read from file
    tls_args.ta_my_cert = 1033674527;
    tls_args.ta_my_privkey = 327987726;
    error = tls_server_hello_x509(&tls_args, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Server error starting TLS handshake: %d", error);
    }
    else {
        // Wait until TLS handshake is done
        timeout_remainder = wait_for_completion_timeout(&tls_handshake_completed, ROLLBACCINE_TLS_TIMEOUT);
        if (!timeout_remainder) {
            printk(KERN_ERR "Server TLS handshake timed out");
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
        spin_lock(&device->connected_sockets_lock);
        list_add(&new_connected_socket_list->list, &device->connected_sockets);
        spin_unlock(&device->connected_sockets_lock);

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

// Arguments: 0 = underlying device name, like /dev/ram0. 1 = f, 2 = n, 3 = id, 4 = is_leader. 5 = listen port. 6+ = server ports
static int server_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    struct server_device *device;
    struct task_struct *broadcast_thread, *submit_thread;
    ushort port;
    int error;
    int i;

    device = kmalloc(sizeof(struct server_device), GFP_KERNEL);
    if (device == NULL) {
        printk(KERN_ERR "Error creating device");
        return -ENOMEM;
    }

    bioset_init(&device->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);
    device->page_mempool = mempool_create_page_pool(ROLLBACCINE_PAGE_POOL_SIZE, 0);
    if (!device->page_mempool) {
        printk(KERN_ERR "Error creating page_mempool");
        return -ENOMEM;
    }
    device->bio_data_mempool = mempool_create_kmalloc_pool(ROLLBACCINE_BIO_DATA_POOL_SIZE, sizeof(struct bio_data));
    if (!device->bio_data_mempool) {
        printk(KERN_ERR "Error creating bio_data_mempool");
        return -ENOMEM;
    }

    device->shutting_down = false;
    spin_lock_init(&device->connected_sockets_lock);

    init_waitqueue_head(&device->broadcast_queue_wait_queue);
    spin_lock_init(&device->broadcast_queue_lock);
    error = kfifo_alloc(&device->broadcast_queue, ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Error creating bio_kfifo");
        return error;
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
    error = kfifo_alloc(&device->fsyncs_pending_replication, ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Error creating fsyncs_pending_replication");
        return error;
    }
    
    device->disk_unacked_ops = 0;
    error = kfifo_alloc(&device->queued_ops, ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Error creating queued_ops");
        return error;
    }
    init_waitqueue_head(&device->submit_queue_wait_queue);
    error = kfifo_alloc(&device->submit_queue, ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Error creating submit_queue");
        return error;
    }

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

    // Connect to other servers. argv[6], argv[7], etc are all server ports to connect to.
    INIT_LIST_HEAD(&device->client_sockets);
    for (i = 6; i < argc; i++) {
        error = kstrtou16(argv[i], 10, &port);
        if (error < 0) {
            printk(KERN_ERR "Error parsing port");
            return error;
        }
        printk(KERN_INFO "Starting thread to connect to server at port: %u", port);
        start_client_to_server(device, port);
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

    // Enable FUA and PREFLUSH flags
    ti->num_flush_bios = 1;
    ti->flush_supported = 1;

    ti->private = device;

    printk(KERN_INFO "Server constructed");
    return 0;
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


    kfifo_free(&device->broadcast_queue);
    // Note: I'm not sure how to free theses queues which may have outstanding bios. Hopefully nothing breaks horribly
    kfifo_free(&device->fsyncs_pending_replication);
    kfifo_free(&device->queued_ops);
    kfifo_free(&device->submit_queue);
    dm_put_device(ti, device->dev);
    bioset_exit(&device->bs);
    mempool_destroy(device->page_mempool);
    mempool_destroy(device->bio_data_mempool);
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
