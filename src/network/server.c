/**
 * This file is heavily inspired by https://github.com/sysprog21/kecho/tree/master.
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

#define MAX_CONNECTIONS 10
#define BUFFER_SIZE 4096
#define RETRY_TIMEOUT 5000 // Number of milliseconds before client attempts to connect to a server again
#define MODULE_NAME "server"

// Allow us to keep track of threads' sockets so we can shut them down and free them on exit.
struct thread_list {
    struct socket *sock;
    struct list_head list;
};

struct server_device {
    struct dm_dev *dev;
    bool shutting_down; // Set to true when user triggers shutdown. All threads check this and abort if true. Used instead of kthread_should_stop(), since the function that flips that boolean to true (kthread_stop()) is blocking, which creates a race condition when we kill the socket & also wait for the thread to stop.

    // Server variables
    struct thread_list listener_thread;
    struct list_head accepted_threads;

    // Client variables
    struct list_head client_threads;
};

struct client_thread_params {
    struct socket *sock;
    struct sockaddr_in addr;
    struct server_device *device;
};

struct listen_thread_params {
    struct socket *sock;
    struct server_device *device;
};

static int server_map(struct dm_target *ti, struct bio *bio) {
    // TODO: Change from just passthrough
    struct server_device *device = ti->private;
    bio_set_dev(bio, device->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
    return DM_MAPIO_REMAPPED;
}

static void kill_thread(struct thread_list *thread) {
    // Shut down the socket, causing the thread to unblock (if it was blocked on a socket)
    if (thread->sock != NULL) {
        kernel_sock_shutdown(thread->sock, SHUT_RDWR);
        sock_release(thread->sock);
    }
    // Don't call kthread_stop because it might hang waiting for threads that have already returned
    // if (thread->task != NULL)
        // kthread_stop(thread->task);
}

int connect_to_server(void *args) {
    int error = -1;
    struct client_thread_params *thread_params = (struct client_thread_params *)args;

    // Retry connecting to server until it succeeds
    printk(KERN_INFO "Attempting to connect for the first time");
    while (error != 0 && !thread_params->device->shutting_down) {
        error = kernel_connect(thread_params->sock, (struct sockaddr *)&thread_params->addr, sizeof(thread_params->addr), 0);
        if (error != 0) {
            printk(KERN_ERR "Error connecting to server, retrying...");
            msleep(RETRY_TIMEOUT);
        }
    }

    if (thread_params->device->shutting_down) {
        goto cleanup;
    }

    printk(KERN_INFO "Connected to server");

    // Listen to incoming messages. TODO: Create listening function to accept all messages
    // while (!kthread_should_stop()) {
        
    // }

    // Test sending a message
    unsigned char *buffer;
    struct msghdr msg;
    struct kvec vec;

    buffer = kzalloc(BUFFER_SIZE, GFP_KERNEL);
    if (buffer == NULL) {
        printk(KERN_ERR "Error allocating buffer");
        return -1;
    }
    memcpy(buffer, "Hello, world!", 14);

    vec.iov_base = buffer;
    vec.iov_len = BUFFER_SIZE;
    
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    printk(KERN_INFO "Sending message");
    kernel_sendmsg(thread_params->sock, &msg, &vec, 1, BUFFER_SIZE);
    printk(KERN_INFO "Sent message");

    cleanup:
    kfree(thread_params);
    kfree(buffer);

    return 0;
}

static int start_client_to_server(struct server_device *device, ushort port) {
    struct thread_list *new_thread;
    struct client_thread_params *thread_params;
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
    new_thread = kmalloc(sizeof(struct thread_list), GFP_KERNEL);
    if (new_thread == NULL) {
        printk(KERN_ERR "Error creating new thread socket struct");
        return -1;
    }
    new_thread->sock = thread_params->sock;
    list_add(&new_thread->list, &device->client_threads);

    // start a thread for this connection
    error = kthread_run(connect_to_server, thread_params, "connect to server");
    if (IS_ERR(error)) {
        printk(KERN_ERR "Error creating connect to server thread.");
        return -1;
    }

    return 0;
}

int listen_to_accepted_socket(void *args) {
    unsigned char* buffer;
    struct listen_thread_params *thread_params = (struct listen_thread_params *)args;
    struct msghdr msg;
    struct kvec vec;

    buffer = kzalloc(BUFFER_SIZE, GFP_KERNEL);
    if (buffer == NULL) {
        printk(KERN_ERR "Error allocating buffer");
        return -1;
    }

    vec.iov_base = buffer;
    vec.iov_len = BUFFER_SIZE;
    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    while (!thread_params->device->shutting_down) {
        int len = kernel_recvmsg(thread_params->sock, &msg, &vec, BUFFER_SIZE, BUFFER_SIZE, msg.msg_flags);
        if (len <= 0) {
            printk(KERN_ERR "Error reading from socket");
            break;
        }

        printk(KERN_INFO "Received message: %s", buffer);
    }

    cleanup:
    kfree(thread_params);
    kfree(buffer);
    return 0;
}

// Thread that listens to connecting clients
int listen_for_connections(void* args) {
    struct server_device *device = (struct server_device *)args;
    struct socket *sock;
    struct listen_thread_params* thread_params;
    struct thread_list *new_thread;
    int error;

    while (!device->shutting_down) {
        // blocks until a connection is accepted
        error = kernel_accept(device->listener_thread.sock, &sock, 0);
        if (error < 0) {
            printk(KERN_ERR "Error accepting connection");
            continue;
        }
        printk(KERN_INFO "Accepted connection");

        // Create parameters for the thread
        thread_params = kmalloc(sizeof(struct listen_thread_params), GFP_KERNEL);
        if (thread_params == NULL) {
            printk(KERN_ERR "Error creating listen thread params");
            break;
        }
        thread_params->sock = sock;
        thread_params->device = device;

        // start a thread for this connection
        new_thread = kmalloc(sizeof(struct thread_list), GFP_KERNEL);
        if (new_thread == NULL) {
            printk(KERN_ERR "Error creating new thread socket struct");
            break;
        }
        new_thread->sock = sock;
        list_add(&new_thread->list, &device->accepted_threads);

        error = kthread_run(listen_to_accepted_socket, thread_params, "listen to accepted socket");
        if (IS_ERR(error)) {
            printk(KERN_ERR "Error creating listen to accepted socket thread.");
            break;
        }
    }

    return 0;
}

// Returns error code if it fails
static int start_server(struct server_device *device, ushort port) {
    struct sockaddr_in addr;
    int error;
    int opt = 1;
    sockptr_t kopt = {.kernel = (char*)&opt, .is_kernel = 1};

    error = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &device->listener_thread.sock);
    if (error < 0) {
        printk(KERN_ERR "Error creating server socket");
        return error;
    }

    // TCP nodelay
    error = device->listener_thread.sock->ops->setsockopt(device->listener_thread.sock, SOL_TCP, TCP_NODELAY, kopt, sizeof(opt));
    if (error < 0) {
        printk(KERN_ERR "Error setting TCP_NODELAY");
        return error;
    }

    error = sock_setsockopt(device->listener_thread.sock, SOL_SOCKET, SO_REUSEPORT, kopt, sizeof(opt));
    if (error < 0) {
        printk(KERN_ERR "Error setting SO_REUSEPORT");
        return error;
    }

    // Set sockaddr_in
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    error = kernel_bind(device->listener_thread.sock, (struct sockaddr *)&addr, sizeof(addr));
    if (error < 0) {
        printk(KERN_ERR "Error binding socket");
        return error;
    }

    error = kernel_listen(device->listener_thread.sock, MAX_CONNECTIONS);
    if (error < 0) {
        printk(KERN_ERR "Error listening on socket");
        return error;
    }

    // Listen for connections
    error = kthread_run(listen_for_connections, device, "listener");
    if (IS_ERR(error)) {
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
    printk(KERN_INFO "Starting server at port: %u", port);

    INIT_LIST_HEAD(&device->accepted_threads);
    error = start_server(device, port);
    if (error < 0) {
        printk(KERN_ERR "Error starting server");
        return error;
    }

    // Connect to other servers. argv[2], argv[3], etc are all server ports to connect to.
    INIT_LIST_HEAD(&device->client_threads);
    for (i = 2; i < argc; i++) {
        error = kstrtou16(argv[i], 10, &port);
        if (error < 0) {
            printk(KERN_ERR "Error parsing port");
            return error;
        }
        printk(KERN_INFO "Starting thread to connect to server at port: %u", port);
        start_client_to_server(device, port); // This func will add threads to client_tasks and client_sockets
    }

    ti->private = device;

    printk(KERN_INFO "Server constructed");
    return 0;
}

static void server_destructor(struct dm_target *ti) {
    struct thread_list *curr, *next;
    struct server_device *device = ti->private;
    if (device == NULL)
        return;

    // Warning: Changing this boolean should technically be atomic. I don't think it's a big deal tho, since by the time shutting_down is true, we don't care what the protocol does. •Ideally* it shuts down gracefully.
    device->shutting_down = true;

    // Kill the listener thread
    printk(KERN_INFO "Killing listener thread");
    kill_thread(&device->listener_thread);

    // Kill accepted threads
    printk(KERN_INFO "Killing accepted threads");
    list_for_each_entry_safe(curr, next, &device->accepted_threads, list) {
        kill_thread(curr);
        kfree(curr);
    }

    // Kill the client threads
    printk(KERN_INFO "Killing client threads");
    list_for_each_entry_safe(curr, next, &device->client_threads, list) {
        kill_thread(curr);
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