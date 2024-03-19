/**
 * This file is mostly copied from https://github.com/sysprog21/kecho/tree/master
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/tcp.h>
#include <linux/kthread.h>
#include <net/sock.h>

#define SERVER_PORT 12345
#define MAX_CONNECTIONS 10
#define BUFFER_SIZE 4096
#define MODULE_NAME "server"

struct socket *listen_socket;
struct workqueue_struct *listener_wq;
struct task_struct *listener_task;
struct list_head accepted_threads;

struct accepted_thread_struct {
    struct socket *accepted_sock;
    struct list_head list; // store all thread structs in a list so we can free them later
    struct work_struct work;
};

static void accepted_thread(struct work_struct *work) {
    struct accepted_thread_struct* ats = container_of(work, struct accepted_thread_struct, work);
    unsigned char* buffer;
    struct msghdr msg;
    struct kvec iov;

    // Create buffer for listening
    buffer = kzalloc(BUFFER_SIZE, GFP_KERNEL);
    if (buffer == NULL) {
        printk(KERN_ERR "Error allocating buffer\n");
        return;
    }

    iov.iov_len = BUFFER_SIZE - 1;
    iov.iov_base = buffer;
    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    while (!kthread_should_stop()) {
        int len = kernel_recvmsg(ats->accepted_sock, &msg, &iov, BUFFER_SIZE - 1, BUFFER_SIZE - 1, msg.msg_flags);
        if (len <= 0) {
            printk(KERN_ERR "Error reading from socket\n");
            break;
        }

        printk(KERN_INFO "Received message: %s\n", buffer);
    }

    kfree(buffer);
}

// Thread that listens to connecting clients
int listener_thread(void *arg) {
    struct socket *sock;
    struct accepted_thread_struct *ats;
    int error;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&accepted_threads);

    while (!kthread_should_stop()) {
        // blocks until a connection is accepted
        error = kernel_accept(listen_socket, &sock, 0);
        if (error < 0) {
            printk(KERN_ERR "Error accepting connection\n");
            continue;
        }

        // start a thread for this connection. Create a struct containing the socket for this thread
        ats = kmalloc(sizeof(struct accepted_thread_struct), GFP_KERNEL);
        if (ats == NULL) {
            printk(KERN_ERR "Error creating work struct\n");
            kernel_sock_shutdown(sock, SHUT_RDWR);
            sock_release(sock);
            continue;
        }
        ats->accepted_sock = sock;
        // the worker executes the accepted_thread function
        INIT_WORK(&ats->work, accepted_thread);
        queue_work(listener_wq, &ats->work);
    }

    // free all structs. Documentation for this function here: https://archive.kernel.org/oldlinux/htmldocs/kernel-api/API-list-for-each-entry-safe.html
    struct accepted_thread_struct *curr, *next;
    list_for_each_entry_safe(curr, next, &accepted_threads, list) {
        kernel_sock_shutdown(curr->accepted_sock, SHUT_RDWR);
        sock_release(curr->accepted_sock);
        kfree(curr);
    }
    return 0;
}

static void close_server(void) {
    if (listen_socket != NULL) {
        kernel_sock_shutdown(listen_socket, SHUT_RDWR);
        sock_release(listen_socket);
        listen_socket = NULL;
    }
}

// Returns error code if it fails
static int start_server(void) {
    struct sockaddr_in addr;
    int error;
    int opt = 1;

    error = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_socket);
    if (error < 0) {
        printk(KERN_ERR "Error creating socket\n");
        return error;
    }

    // TCP nodelay
    error = kernel_setsockopt(listen_socket, SOL_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));
    if (error < 0) {
        printk(KERN_ERR "Error setting TCP_NODELAY\n");
        sock_release(listen_socket);
        return error;
    }

    error = kernel_setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
    if (error < 0) {
        printk(KERN_ERR "Error setting SO_REUSEADDR\n");
        sock_release(listen_socket);
        return error;
    }

    // Set sockaddr_in
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(SERVER_PORT);

    error = kernel_bind(listen_socket, (struct sockaddr *)&addr, sizeof(addr));
    if (error < 0) {
        printk(KERN_ERR "Error binding socket\n");
        sock_release(listen_socket);
        return error;
    }

    error = kernel_listen(listen_socket, MAX_CONNECTIONS);
    if (error < 0) {
        printk(KERN_ERR "Error listening on socket\n");
        sock_release(listen_socket);
        return error;
    }

    return 0;
}

static int server_init_module(void) {
    int error = start_server();
    if (error < 0) {
        printk(KERN_ERR "Error starting server\n");
        return error;
    }

    // WQ_UNBOUND means that the workqueue is not bound to any specific CPU. Good for not stalling other kernel tasks, bad for cache locality. See the discussion here: https://github.com/sysprog21/kecho/tree/master?tab=readme-ov-file#usage
    listener_wq = alloc_workqueue(MODULE_NAME, WQ_UNBOUND, 0);
    listener_task = kthread_run(listener_thread, NULL, MODULE_NAME);
    if (IS_ERR(listener_task)) {
        printk(KERN_ERR "Error creating listener thread\n");
        close_server();
    }

    printk(KERN_INFO "Server module loaded\n");
    return 0;
}

static void server_exit_module(void) {
    send_sig(SIGTERM, listener_task, 1);
    kthread_stop(listener_task);
    close_server();
    destroy_workqueue(listener_wq);

    printk(KERN_INFO "Server module unloaded\n");
}

module_init(server_init_module);
module_exit(server_exit_module);
MODULE_LICENSE("GPL");