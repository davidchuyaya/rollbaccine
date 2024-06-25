/**
 * This file is heavily inspired by https://github.com/sysprog21/kecho/tree/master and https://github.com/LINBIT/drbd.
 * Note: In order to kill threads on shutdown, we create a list of all open sockets that threads could be blocked on, and close them on shutdown.
 *       We also set shutting_down = true so a thread who returns from a blocking operation sees it and exits.
 *       We don't use kthread_stop() because it's blocking, and we need to close the sockets, which wakes the threads up before they see they should stop.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/tcp.h>
#include <linux/kthread.h>
#include <linux/inet.h> // For in4_pton to translate IP addresses from strings
#include <linux/kfifo.h>
#include <net/sock.h>

#define ROLLBACCINE_MAX_CONNECTIONS 10
#define ROLLBACCINE_ENCRYPT_GRANULARITY 4096 // Number of bytes to encrypt, hash, or send at a time
#define ROLLBACCINE_RETRY_TIMEOUT 5000 // Number of milliseconds before client attempts to connect to a server again
#define ROLLBACCINE_INIT_WRITE_INDEX 0
#define ROLLBACCINE_HASH_SIZE 256
#define ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE 1024 // Number of bios that can be outstanding between main threads and network broadcast thread. Must be power of 2, according to kfifo specs
#define ROLLBACCINE_PAGE_POOL_SIZE 1024 // Number of pages to be allocated for the page pool
#define MIN_IOS 64
#define MODULE_NAME "server"

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

struct fsync_list {
    struct bio *bio;
    int waiting_for_write_index; // The write index that this fsync bio is waiting for
    struct list_head list;
};

struct server_device {
    struct dm_dev *dev;
    struct bio_set bs;
    mempool_t *mempool;
    bool is_leader;
    bool shutting_down; // Set to true when user triggers shutdown. All threads check this and abort if true. Used instead of kthread_should_stop(), since the function that flips that boolean to true (kthread_stop()) is blocking, which creates a race condition when we kill the socket & also wait for the thread to stop.
    int f;
    int n;

    struct ballot bal;
    int write_index; // Doesn't need to be atomic because only the broadcast thread will modify this
    int latest_data_write_index; // Last index where data was written (instead of an empty bio for fsync, for example)
    // Max write indices of each replica
    spinlock_t write_index_lock;
    int* write_indices; // Len = n
    int max_quorum_write_index;
    struct list_head pending_fsyncs;
    
    // Communication between main threads and the networking thread
    wait_queue_head_t bio_fifo_wait_queue;
    spinlock_t bio_fifo_lock;
    struct kfifo bio_fifo;

    // Sockets, tracked so we can kill them on exit.
    struct list_head server_sockets;
    struct list_head client_sockets;

    // Connected sockets. Should be a subset of the sockets above. Handy for broadcasting
    // TODO: Need to figure out network handshake so we know who we're talking to.
    spinlock_t connected_sockets_lock;
    struct list_head connected_sockets;
};

struct bio_data {
    enum MsgType type; // Fsync or write
    struct bio *base_bio;
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

// Returns the max int that a quorum agrees to. Note that since the leader itself must have write index >= followers' write index, the quorum size is f (not f+1).
void process_follower_write_index(struct server_device *device, int follower_id, int follower_write_index) {
    int i, j, num_geq_write_indices = 0;
    bool max_index_changed = false;
    struct fsync_list *curr, *next;

    spin_lock(&device->write_index_lock);
    // Special case for f = 1, n = 2, since there's only 1 follower, so we don't need to iterate.
    // Also, we don't need to compare maxes (the latest message should always have a larger write index).
    if (device->f == 1 && device->n == 2) {
        device->max_quorum_write_index = follower_write_index;
        max_index_changed = true;
    }
    // Special case for f = 1, n = 3.
    // What the quorum agrees on = max of what any 1 follower has (plus the leader's write index, which must be higher).
    else if (device->f == 1 && device->n == 3) {
        if (device->max_quorum_write_index < follower_write_index) {
            device->max_quorum_write_index = follower_write_index;
            max_index_changed = true;
        }
    }
    // Otherwise, find the largest write index that a quorum agrees to
    else {
        device->write_indices[follower_id] = follower_write_index;
        for (i = 0; i < device->n; i++) {
            if (device->max_quorum_write_index >= device->write_indices[i]) {
                continue;
            }

            // Count the number of followers with an index >= this index
            num_geq_write_indices = 0;
            for (j = 0; j < device->n; j++) {
                if (device->write_indices[j] >= device->write_indices[i]) {
                    num_geq_write_indices++;
                }
            }
            // If a quorum (including the leader) is reached on this index, store it
            if (num_geq_write_indices >= device->f) {
                device->max_quorum_write_index = device->write_indices[i];
                max_index_changed = true;
            }
        }
    }

    // Loop through all bios waiting on fsync if the max index has changed
    if (max_index_changed) {
        // printk(KERN_INFO "New max quorum write index: %d", device->max_quorum_write_index);
        list_for_each_entry_safe(curr, next, &device->pending_fsyncs, list) {
            if (curr->waiting_for_write_index <= device->max_quorum_write_index) {
                // printk(KERN_INFO "Fsync waiting on write index %d satisfied", curr->waiting_for_write_index);
                submit_bio_noacct(curr->bio);
                list_del(&curr->list);
                kfree(curr);
            }
            else {
                break;
            }
        }
    }
    spin_unlock(&device->write_index_lock);
}

bool requires_fsync(struct bio *bio) {
    return bio->bi_opf & (REQ_PREFLUSH | REQ_FUA);
}

unsigned int remove_fsync_flags(unsigned int bio_opf) {
    return bio_opf & ~REQ_PREFLUSH & ~REQ_FUA;
}

// Because we alloc pages when we receive the bios, we haev to free them when it's done writing
static void free_pages_end_io(struct bio *received_bio) {
    struct server_device *device = (struct server_device*) received_bio->bi_private;
    struct bio_vec bvec;
    struct bvec_iter iter;

    bio_for_each_segment(bvec, received_bio, iter) {
        mempool_free(bvec.bv_page, device->mempool);
        // __free_page(bvec.bv_page); 
    }
    bio_put(received_bio);
}

void broadcast_bio(struct server_device *device, struct bio *bio) {
    int sent;
    struct fsync_list *fsync_list_elem;
    struct bio_data *bio_data = dm_per_bio_data(bio, sizeof(struct bio_data));
    struct msghdr msg_header;
    struct kvec vec;
    struct socket_list *curr, *next;
    struct metadata_msg metadata;
    struct bio_vec bvec, chunked_bvec;
    struct bvec_iter iter;

    metadata.type = bio_data->type;
    metadata.bal = device->bal;
    metadata.write_index = ++device->write_index;
    metadata.num_pages = bio->bi_iter.bi_size / PAGE_SIZE;
    metadata.bi_opf = bio->bi_opf;
    metadata.sector = bio->bi_iter.bi_sector;

    // If thsi write has contents, update the latest data write index
    if (metadata.num_pages > 0) {
        device->latest_data_write_index = metadata.write_index;
    }

    // Add the fsync bio to the queue of pending_fsyncs, or just submit it now if there are already enough acks.
    if (metadata.type == ROLLBACCINE_FSYNC) {
        fsync_list_elem = kmalloc(sizeof(struct fsync_list), GFP_KERNEL);
        if (fsync_list_elem == NULL) {
            printk(KERN_ERR "Error creating fsync_list_elem");
            return;
        }

        spin_lock(&device->write_index_lock);
        // If the write this fsync depends on is already ACK'd, then let it through. Possible if there are multiple fsyncs in a row.
        if (device->latest_data_write_index <= device->max_quorum_write_index) {
            // printk(KERN_INFO "Fsync %llu ALREADY satisfied for latest data write index: %d", metadata.write_index, device->latest_data_write_index);
            kfree(fsync_list_elem);
            submit_bio_noacct(bio_data->base_bio);
            // Immediately return since there's nothing to send; this fsync must've been empty, otherwise latest_data_write_index would be higher
            spin_unlock(&device->write_index_lock);
            return;
        }
        else {
            // printk(KERN_INFO "Fsync %llu will begin waiting for latest data write index: %d", metadata.write_index, device->latest_data_write_index);
            // Otherwise add it to the list of waiting fsyncs
            fsync_list_elem->bio = bio_data->base_bio;
            fsync_list_elem->waiting_for_write_index = device->latest_data_write_index;
            list_add_tail(&fsync_list_elem->list, &device->pending_fsyncs);
        }
        spin_unlock(&device->write_index_lock);
    }

    // Note: If bi_size is not a multiple of PAGE_SIZE, we have to send by sector chunks
    WARN_ON(metadata.num_pages * PAGE_SIZE != bio->bi_iter.bi_size);

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

        bio_for_each_segment(bvec, bio, iter) {
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
        num_bios_gotten = kfifo_out(&device->bio_fifo, &clone, sizeof(struct bio*));
        // printk(KERN_INFO "Checked bios, got %d", num_bios_gotten);
        if (num_bios_gotten == 0) {
            // Wait for new bios
            wait_event_interruptible(device->bio_fifo_wait_queue, !kfifo_is_empty(&device->bio_fifo));
            continue;
        }

        broadcast_bio(device, clone);

        free_pages_end_io(clone);
    }

    return 0;
}

struct bio* deep_bio_clone(struct server_device *device, struct bio *bio_src) {
    struct bio *clone;
    struct bio_data *src_bio_data, *clone_bio_data;
    struct bio_vec bvec;
    struct bvec_iter iter;
    struct page *page;

    // Note: If bi_size is not a multiple of PAGE_SIZE, we have a BIG problem :(
    clone = bio_alloc_bioset(GFP_NOIO, bio_src->bi_iter.bi_size / PAGE_SIZE, &device->bs);
    if (!clone) {
        return NULL;
    }

    clone->bi_private = device;
    clone->bi_opf = bio_src->bi_opf;
    clone->bi_iter.bi_sector = bio_src->bi_iter.bi_sector;

    bio_for_each_segment(bvec, bio_src, iter) {
        page = mempool_alloc(device->mempool, GFP_KERNEL);
        // page = alloc_page(GFP_KERNEL);
        if (!page) {
            bio_put(clone);
            return NULL;
        }
        memcpy(kmap(page), kmap(bvec.bv_page) + bvec.bv_offset, bvec.bv_len);
        kunmap(page);
        kunmap(bvec.bv_page);

        bio_add_page(clone, page, bvec.bv_len, 0);
    }

    // Deep copy the bio data as well
    src_bio_data = dm_per_bio_data(bio_src, sizeof(struct bio_data));
    clone_bio_data = dm_per_bio_data(clone, sizeof(struct bio_data));
    clone_bio_data->type = src_bio_data->type;
    // Point to the original bio, in case this is an fsync and we need to wake it?
    clone_bio_data->base_bio = bio_src;

    return clone;
}

static int server_map(struct dm_target *ti, struct bio *bio) {
    bool is_fsync = false;
    struct server_device *device = ti->private;
    struct bio *clone;
    struct bio_data *bio_data;

    // Copy bio if it's a write
    if (device->is_leader && bio_data_dir(bio) == WRITE) {
        bio_data = dm_per_bio_data(bio, sizeof(struct bio_data));
        if (requires_fsync(bio)) {
            // printk(KERN_INFO "Fsync detected");
            bio_data->type = ROLLBACCINE_FSYNC;
            bio->bi_opf = remove_fsync_flags(bio->bi_opf); // Don't need actual fsync if we have replication
            is_fsync = true;
        }
        else {
            bio_data->type = ROLLBACCINE_WRITE;
        }

        // Create the clone
        clone = deep_bio_clone(device, bio);
        if (!clone) {
            printk(KERN_ERR "Could not create clone");
            return DM_MAPIO_REMAPPED;
        }

        // Add clone to networking queue. There may be multiple writers, so lock
        kfifo_in_spinlocked(&device->bio_fifo, &clone, sizeof(struct bio*), &device->bio_fifo_lock);
        wake_up_interruptible(&device->bio_fifo_wait_queue);
    }

    bio_set_dev(bio, device->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    // If this is an fsync, then say we submitted it so it doesn't propagate further (and effectively blocks)
    return is_fsync ? DM_MAPIO_SUBMITTED : DM_MAPIO_REMAPPED;
}

static void kill_thread(struct socket *sock) {
    // Shut down the socket, causing the thread to unblock (if it was blocked on a socket)
    if (sock != NULL) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
    }
}

// Function used by all listening sockets to block and listen to messages
void blocking_read(struct server_device *device, struct socket *sock) {
    struct metadata_msg metadata;
    struct bio* received_bio;
    struct page* page;
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
        // printk(KERN_INFO "Received metadata sector: %llu, num pages: %llu", metadata.sector, metadata.num_pages);

        // Received ack for fsync
        if (metadata.type == FOLLOWER_ACK && device->is_leader) {
            // printk(KERN_INFO "Received fsync ack for write index: %llu", metadata.write_index);
            process_follower_write_index(device, metadata.bal.id, metadata.write_index);
            continue;
        }

        received_bio = bio_alloc_bioset(GFP_NOIO, metadata.num_pages, &device->bs);
        received_bio->bi_private = device;
        bio_set_dev(received_bio, device->dev->bdev);
        received_bio->bi_opf = metadata.bi_opf;
        received_bio->bi_iter.bi_sector = metadata.sector;
        received_bio->bi_end_io = free_pages_end_io;

        // 2. Expect hash next
        // 3. Receive pages of bio
        for (i = 0; i < metadata.num_pages; i++) {
            page = mempool_alloc(device->mempool, GFP_KERNEL);
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
            bio_add_page(received_bio, page, PAGE_SIZE, 0);
        }

        // 4. Verify against hash
        // 5. Submit bio
        submit_bio_noacct(received_bio);
        // printk(KERN_INFO "Submitted bio");

        // 6. If the message is an fsync, reply.
        if (metadata.type == ROLLBACCINE_FSYNC) {
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
    }

    printk(KERN_INFO "Shutting down, exiting blocking read");
    kernel_sock_shutdown(sock, SHUT_RDWR);
    // TODO: Releasing the socket is problematic because it makes future calls to shutdown() crash, which may happen if the connection dies, the socket is freed, and later the destructor tries to shut it down.
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

    blocking_read(thread_params->device, thread_params->sock);

    cleanup:
    kfree(thread_params);
    return 0;
}

static int start_client_to_server(struct server_device *device, ushort port) {
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
static int start_server(struct server_device *device, ushort port) {
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
    struct task_struct *broadcast_thread;
    ushort port;
    int error;
    int i;

    device = kmalloc(sizeof(struct server_device), GFP_KERNEL);
    if (device == NULL) {
        printk(KERN_ERR "Error creating device");
        return -ENOMEM;
    }

    bioset_init(&device->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);
    device->mempool = mempool_create_page_pool(ROLLBACCINE_PAGE_POOL_SIZE, 0);

    device->shutting_down = false;
    spin_lock_init(&device->connected_sockets_lock);

    init_waitqueue_head(&device->bio_fifo_wait_queue);
    spin_lock_init(&device->bio_fifo_lock);
    error = kfifo_alloc(&device->bio_fifo, ROLLBACCINE_KFIFO_CIRC_BUFFER_SIZE, GFP_KERNEL);
    if (error < 0) {
        printk(KERN_ERR "Error creating kfifo");
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
    device->latest_data_write_index = ROLLBACCINE_INIT_WRITE_INDEX;
    device->max_quorum_write_index = ROLLBACCINE_INIT_WRITE_INDEX;
    spin_lock_init(&device->write_index_lock);
    device->write_indices = kzalloc(sizeof(int) * device->n, GFP_KERNEL);
    INIT_LIST_HEAD(&device->pending_fsyncs);

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

    // Enable FUA and PREFLUSH flags
    ti->num_flush_bios = 1;
    ti->flush_supported = 1;

    ti->per_io_data_size = sizeof(struct bio_data);
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

    kfifo_free(&device->bio_fifo);
    dm_put_device(ti, device->dev);
    bioset_exit(&device->bs);
    mempool_destroy(device->mempool);
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