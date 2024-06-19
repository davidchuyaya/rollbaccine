/**
 * This file is heavily inspired by https://github.com/sysprog21/kecho/tree/master.
 * Given a server port, this module will create 2 servers, 1 for the metadata and 1 for the actual bio blocks, at port and port+1 respectively.
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
#include <net/sock.h>

#define ROLLBACCINE_MAX_CONNECTIONS 10
#define ROLLBACCINE_ENCRYPT_GRANULARITY 4096 // Number of bytes to encrypt, hash, or send at a time
#define ROLLBACCINE_RETRY_TIMEOUT 5000 // Number of milliseconds before client attempts to connect to a server again
#define ROLLBACCINE_INIT_WRITE_INDEX 0
#define ROLLBACCINE_HASH_SIZE 256
#define MODULE_NAME "server"

enum ConnectionType { METADATA, BIO };
enum MsgType { ROLLBACCINE_FSYNC, ROLLBACCINE_WRITE };

struct ballot {
    int id;
    int num;
};

struct msg {
    enum MsgType type;
    struct ballot bal;
    unsigned int write_index;
    unsigned int num_pages;

    // Metadata about the bio
    sector_t sector;
    // TODO: Figure out how to send variable number of hashes
    // char hash[ROLLBACCINE_HASH_SIZE];
};

// Allow us to keep track of threads' sockets so we can shut them down and free them on exit.
struct socket_list {
    struct socket *sock;
    struct list_head list;
};

struct server_device {
    struct dm_dev *dev;
    bool shutting_down; // Set to true when user triggers shutdown. All threads check this and abort if true. Used instead of kthread_should_stop(), since the function that flips that boolean to true (kthread_stop()) is blocking, which creates a race condition when we kill the socket & also wait for the thread to stop.

    struct ballot bal;
    atomic_t write_index;

    // Sockets, tracked so we can kill them on exit.
    // 1. We start the metadata server, which adds threads to server_metadata_sockets.
    // 2. We start the bio server, which adds accepted threads to server_bio_sockets.
    // 3. We start client threads to connect to other servers, which adds client threads to client_sockets.
    struct list_head server_metadata_sockets;
    struct list_head server_bio_sockets;
    struct list_head client_sockets;

    // Connected sockets. Should be a subset of the sockets above. Handy for broadcasting
    // TODO: Move them into a struct containing metadata + bio sockets for each connection. Need to figure out network handshake so we know who we're talking to.
    // TODO: Create a circular buffer of pending messages, batch send on a separate thread
    spinlock_t connected_sockets_lock;
    struct list_head connected_metadata_sockets;
    struct list_head connected_bio_sockets;

	// Received metadata and bios
	spinlock_t received_metadata_lock;
	struct list_head received_metadata;
	spinlock_t received_bios_lock;
	struct list_head received_bios;
};

// Thread params: Parameters passed into threads. Should be freed by the thread when it exits.

struct client_thread_params {
    struct socket *sock;
    struct sockaddr_in addr;
    struct server_device *device;
    enum ConnectionType conn_type;
};

struct accepted_thread_params {
    struct socket *sock;
    struct server_device *device;
    enum ConnectionType conn_type;
};

struct listen_thread_params {
    struct socket *sock;
    struct server_device *device;
    enum ConnectionType conn_type;
};

void broadcast(struct server_device *device, unsigned char* buffer, enum ConnectionType conn_type) {
	int sent;
    struct msghdr msg_header;
    struct kvec vec;
    struct socket_list *curr, *next;
	struct list_head *sockets = conn_type == METADATA ? &device->connected_metadata_sockets : &device->connected_bio_sockets;
	size_t buffer_size = conn_type == METADATA ? sizeof(struct msg) : ROLLBACCINE_ENCRYPT_GRANULARITY;

    msg_header.msg_name = NULL;
    msg_header.msg_namelen = 0;
    msg_header.msg_control = NULL;
    msg_header.msg_controllen = 0;
    msg_header.msg_flags = 0;

    spin_lock(&device->connected_sockets_lock);
    list_for_each_entry_safe(curr, next, sockets, list) {
        vec.iov_base = buffer;
        vec.iov_len = buffer_size;

        // Keep retrying send until the whole message is sent
        while (vec.iov_len > 0) {
            sent = kernel_sendmsg(curr->sock, &msg_header, &vec, 1, vec.iov_len);
            if (sent <= 0) {
                printk(KERN_ERR "Error sending message, aborting send");
                // TODO: Should remove the socket from the list and shut down the connection?
                break;
            } else {
                vec.iov_base += sent;
                vec.iov_len -= sent;
            }
		}
	}
    printk(KERN_INFO "Sent %s message", conn_type == METADATA ? "metadata" : "bio");
    spin_unlock(&device->connected_sockets_lock);
}

void broadcast_bio(struct server_device *device, struct bio *bio) {
    // TODO 1. Copy the bio
    // 2. Return
    // 3. Asynchronously send over the network

    // Temporary hack: Just send the message synchronously
    // unsigned char *buffer;

    // buffer = kzalloc(ROLLBACCINE_ENCRYPT_GRANULARITY, GFP_KERNEL);
    // if (buffer == NULL) {
    //     printk(KERN_ERR "Error allocating buffer");
    //     return;
    // }
}

void broadcast_bio_metadata(struct server_device *device, struct bio *bio) {
	struct msg message;
	message.type = ROLLBACCINE_WRITE;
	message.bal = device->bal;
	message.write_index = atomic_inc_return(&device->write_index);
	message.num_pages = (bio->bi_iter.bi_size / PAGE_SIZE) + 1;
	message.sector = bio->bi_iter.bi_sector;

	broadcast(device, (unsigned char *)&message, METADATA);
	// TODO: Prepare listener for receiving metadata
}

static int server_map(struct dm_target *ti, struct bio *bio) {
    struct server_device *device = ti->private;

    // Copy bio if it's a write
    if (bio_has_data(bio) && bio_data_dir(bio) == WRITE) {
		broadcast_bio_metadata(device, bio);
        broadcast_bio(device, bio);
    }
    // TODO: Detect fsyncs

    bio_set_dev(bio, device->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    return DM_MAPIO_REMAPPED;
}

static void kill_thread(struct socket *sock) {
    // Shut down the socket, causing the thread to unblock (if it was blocked on a socket)
    if (sock != NULL) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
    }
}

// Function used by all listening sockets to block and listen to messages
void blocking_read(struct server_device *device, struct socket *sock, enum ConnectionType conn_type) {
    unsigned char* buffer;
	struct msg* message;
    struct msghdr msg_header;
    struct kvec vec;
    size_t buffer_size;
	int received;

    if (conn_type == METADATA) {
        buffer_size = sizeof(struct msg);
    } else {
        buffer_size = ROLLBACCINE_ENCRYPT_GRANULARITY;
    }

    buffer = kzalloc(buffer_size, GFP_KERNEL);
    if (buffer == NULL) {
        printk(KERN_ERR "Error allocating buffer");
        return;
    }

    msg_header.msg_name = 0;
    msg_header.msg_namelen = 0;
    msg_header.msg_control = NULL;
    msg_header.msg_controllen = 0;
    msg_header.msg_flags = 0;

    while (!device->shutting_down) {
        vec.iov_base = buffer;
        vec.iov_len = buffer_size;

        // Keep reading until we've received a full message
        while (!device->shutting_down && vec.iov_len > 0) {
            received = kernel_recvmsg(sock, &msg_header, &vec, vec.iov_len, vec.iov_len, msg_header.msg_flags);
            if (received <= 0) {
                printk(KERN_ERR "Error reading from socket");
                goto cleanup;
            }

            vec.iov_base += received;
            vec.iov_len -= received;
		}

		// A full message has been received
		if (conn_type == METADATA) {
			message = (struct msg *)buffer;
			printk(KERN_INFO "Message sector: %llu", message->sector);
		}
		else {
			printk(KERN_INFO "Received data block");
		}
    }

	cleanup:
    printk(KERN_INFO "Shutting down, exiting blocking read");
    kfree(buffer);
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
    if (thread_params->conn_type == METADATA) {
        list_add(&sock_list->list, &thread_params->device->connected_metadata_sockets);
    } else {
        list_add(&sock_list->list, &thread_params->device->connected_bio_sockets);
    }
    spin_unlock(&thread_params->device->connected_sockets_lock);

    blocking_read(thread_params->device, thread_params->sock, thread_params->conn_type);

    cleanup:
    kfree(thread_params);
    return 0;
}

static int start_client_to_server(struct server_device *device, ushort port, enum ConnectionType conn_type) {
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
    thread_params->conn_type = conn_type;

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

    blocking_read(thread_params->device, thread_params->sock, thread_params->conn_type);

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

        // Add to list of connected sockets based on the connection type
        new_connected_socket_list = kmalloc(sizeof(struct socket_list), GFP_KERNEL);
        if (new_connected_socket_list == NULL) {
            printk(KERN_ERR "Error creating socket_list");
            break;
        }
        new_connected_socket_list->sock = new_sock;
        spin_lock(&device->connected_sockets_lock);
        if (thread_params->conn_type == METADATA) {
            list_add(&new_connected_socket_list->list, &device->connected_metadata_sockets);
        } else {
            list_add(&new_connected_socket_list->list, &device->connected_bio_sockets);
        }
        spin_unlock(&device->connected_sockets_lock);

        // Add to list of server sockets based on the connection type
        new_server_socket_list = kmalloc(sizeof(struct socket_list), GFP_KERNEL);
        if (new_server_socket_list == NULL) {
            printk(KERN_ERR "Error creating socket_list");
            break;
        }
        new_server_socket_list->sock = new_sock;
        // Note: No locks needed here, because only the listener thread writes this list
        if (thread_params->conn_type == METADATA) {
            list_add(&new_server_socket_list->list, &device->server_metadata_sockets);
        } else {
            list_add(&new_server_socket_list->list, &device->server_bio_sockets);
        }

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
static int start_server(struct server_device *device, ushort port, enum ConnectionType conn_type) {
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
    thread_params->conn_type = conn_type;
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

    // Add the newly created socket to our list of sockets, based on the type
    sock_list->sock = thread_params->sock;
    if (conn_type == METADATA) {
        list_add(&sock_list->list, &device->server_metadata_sockets);
    } else {
        list_add(&sock_list->list, &device->server_bio_sockets);
    }

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

// Arguments: 0 = underlying device name, like /dev/ram0. 1 = listen port. 2+ = server ports
static int server_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    struct server_device *device;
    ushort port;
    int error;
    int i;

    device = kmalloc(sizeof(struct server_device), GFP_KERNEL);
    if (device == NULL) {
        printk(KERN_ERR "Error creating device");
        return -ENOMEM;
    }

    device->shutting_down = false;
    spin_lock_init(&device->connected_sockets_lock);

    // Get the device from argv[0] and store it in device->dev
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &device->dev)) {
        printk(KERN_ERR "Error getting device");
        return -ENOMEM;
    }

    // Start server
    error = kstrtou16(argv[1], 10, &port);
    if (error < 0) {
        printk(KERN_ERR "Error parsing port");
        return error;
    }
    printk(KERN_INFO "Starting metadata server at port: %u", port);
    printk(KERN_INFO "Starting bio server at port: %u", port + 1);

    INIT_LIST_HEAD(&device->connected_metadata_sockets);
    INIT_LIST_HEAD(&device->connected_bio_sockets);

    INIT_LIST_HEAD(&device->server_metadata_sockets);
    error = start_server(device, port, METADATA);
    if (error < 0) {
        printk(KERN_ERR "Error starting metadata server");
        return error;
    }

    INIT_LIST_HEAD(&device->server_bio_sockets);
    error = start_server(device, port + 1, BIO);
    if (error < 0) {
        printk(KERN_ERR "Error starting bio server");
        return error;
    }

    // Connect to other servers. argv[2], argv[3], etc are all server ports to connect to.
    INIT_LIST_HEAD(&device->client_sockets);
    for (i = 2; i < argc; i++) {
        error = kstrtou16(argv[i], 10, &port);
        if (error < 0) {
            printk(KERN_ERR "Error parsing port");
            return error;
        }
        printk(KERN_INFO "Starting thread to connect to server at port: %u", port);
        start_client_to_server(device, port, METADATA);
        start_client_to_server(device, port + 1, BIO);
    }

    device->bal.id = 0; // TODO: Generate securely
    device->bal.num = 0;
    atomic_set(&device->write_index, ROLLBACCINE_INIT_WRITE_INDEX);

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
    printk(KERN_INFO "Killing server metadata sockets");
    list_for_each_entry_safe(curr, next, &device->server_metadata_sockets, list) {
        kill_thread(curr->sock);
        kfree(curr);
    }
    printk(KERN_INFO "Killing server bio sockets");
    list_for_each_entry_safe(curr, next, &device->server_bio_sockets, list) {
        kill_thread(curr->sock);
        kfree(curr);
    }
    printk(KERN_INFO "Killing client sockets");
    list_for_each_entry_safe(curr, next, &device->client_sockets, list) {
        kill_thread(curr->sock);
        kfree(curr);
    }

    // Free socket list (sockets should already be freed)
    list_for_each_entry_safe(curr, next, &device->connected_metadata_sockets, list) {
        kfree(curr);
    }
    list_for_each_entry_safe(curr, next, &device->connected_bio_sockets, list) {
        kfree(curr);
    }

    dm_put_device(ti, device->dev);
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