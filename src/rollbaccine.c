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
#include <linux/rwlock.h>
#include <net/sock.h>

#define ROLLBACCINE_MAX_CONNECTIONS 20
#define ROLLBACCINE_INIT_WRITE_INDEX 0
#define ROLLBACCINE_MAX_BROADCAST_QUEUE_SIZE 1000000
#define SECTORS_PER_PAGE (PAGE_SIZE / SECTOR_SIZE)
#define AES_GCM_IV_SIZE 12
#define AES_GCM_AUTH_SIZE 16
#define AES_GCM_PER_PAGE (PAGE_SIZE / AES_GCM_AUTH_SIZE)
#define KEY_SIZE 16
#define ROLLBACCINE_AVG_HASHES_PER_WRITE 4
#define ROLLBACCINE_METADATA_CHECKSUM_SIZE AES_GCM_AUTH_SIZE * ROLLBACCINE_AVG_HASHES_PER_WRITE
#define ROLLBACCINE_PENDING_BIO_RING_SIZE 10000000 // Max "hole" between writes
#define SHA256_SIZE 32
#define HASHES_PER_PAGE (PAGE_SIZE / SHA256_SIZE)
#define NUM_NICS 4 // Number of sockets we should use for networking to maximize bandwidth
#define ROLLBACCINE_PLUG_NUM_BIOS 256 / 4  // Number of bios to allow between to calls to blk_plug for merging. 256K is the largest write we can send to disk, 4K is the size of individual writes
#define ROLLBACCINE_HASHES_PER_MSG 100
#define MODULE_NAME "rollbaccine"

#define MEMORY_TRACKING  // Check the number of mallocs/frees and see if we're leaking memory
// #define LATENCY_TRACKING

enum MsgType { 
    // Critical path messages
    ROLLBACCINE_WRITE, ROLLBACCINE_FSYNC, ROLLBACCINE_ACK,
    // Initialization/reconfiguration messages
    ROLLBACCINE_P1A, ROLLBACCINE_P1B, ROLLBACCINE_HASH_REQ, ROLLBACCINE_HASH_BEGIN, ROLLBACCINE_DISK_REQ, ROLLBACCINE_DISK_BEGIN, ROLLBACCINE_RECONFIG_COMPLETE, ROLLBACCINE_RECONFIG_COMPLETE_ACK
};
enum EncDecType { ROLLBACCINE_ENCRYPT, ROLLBACCINE_DECRYPT, ROLLBACCINE_VERIFY };
// "Default" respects FUA/PREFLUSH flags, "sync" forces all writes to be FUA, "async" removes all write flags
enum SyncMode { ROLLBACCINE_DEFAULT, ROLLBACCINE_SYNC, ROLLBACCINE_ASYNC };

struct metadata_msg {
    char msg_hash[SHA256_SIZE];

    enum MsgType type;
    uint64_t ballot;
    uint64_t seen_ballot;
    uint64_t sender_id;
    uint64_t sender_socket_id;
    uint64_t recipient_id;
    uint64_t msg_index;
    uint64_t write_index;
    uint64_t num_pages;

    // Metadata about the bio
    uint64_t bi_opf;
    sector_t sector;
    // Hash for each write
    char checksum[ROLLBACCINE_METADATA_CHECKSUM_SIZE];
} __attribute__((packed));

// Flexible array since we don't know how many extra checksums we will include. Be very careful when using sizeof()
struct additional_hash_msg {
    char msg_hash[SHA256_SIZE];
    uint64_t sender_id;
    uint64_t sender_socket_id;
    uint64_t recipient_id;
    uint64_t msg_index;
    char checksum[];
} __attribute__((packed));

// Sent during reconfiguration
struct hash_msg {
    char msg_hash[SHA256_SIZE];
    uint64_t seen_ballot;
    uint64_t sender_id;
    uint64_t sender_socket_id;
    uint64_t recipient_id;
    uint64_t msg_index;

    sector_t start_page;
    char checksums[ROLLBACCINE_HASHES_PER_MSG * AES_GCM_AUTH_SIZE];
} __attribute__((packed));

// Used to return a pair from handshake_ids()
struct multithreaded_handshake_pair {
    uint64_t sender_id;
    uint64_t sender_socket_id;
} __attribute__((packed));

struct socket_data {
    struct mutex socket_mutex; // To make sure no one else is writing to this socket
    struct socket *sock;
    uint64_t last_sent_msg_index; // the index of the last message sent on this socket
    uint64_t waiting_for_msg_index; // the index of the last message received on this socket
    uint64_t sender_id;
    uint64_t sender_socket_id; // unique number for the sending socket. Otherwise an attacker could replay writes across sockets. Defaults to U64_MAX
    struct mutex hash_mutex; // To make sure no one else is using the hash's scratch space
    struct shash_desc *hash_desc; // Hash scratch space for this socket to verify
} ____cacheline_aligned; // Align to cacheline to allow multiple threads to access data without false sharing

// A list of connections to different senders, where each sender is connected through 1 socket per NIC
struct multisocket {
    struct socket_data socket_data[NUM_NICS];
    uint64_t sender_id;
    bool sender_socket_id_taken[NUM_NICS]; // Which sender socket IDs have been taken
    struct mutex sender_socket_ids_lock; // Lock on sender_socket_ids to check if the sender is giving us unique socket IDs
    atomic_t disconnected;
    struct list_head list;
};

// Size = 2 for each field because 1 primary and 1 backup (f = 1).
struct configuration {
    uint64_t ids[2];
    uint64_t ballots[2];
    uint64_t write_indices[2];
} ____cacheline_aligned;

struct fsync_index_list {
    uint64_t server_id; // ID of sender
    int fsync_index;
};

struct rollbaccine_device {
    struct dm_dev *dev;
    struct bio_set bs;
    struct kmem_cache *bio_data_cache;
    struct mutex page_cache_lock;
    struct page *page_cache;
    int page_cache_size;
    sector_t num_sectors;

    uint64_t f;
    enum SyncMode sync_mode;
    bool only_replicate_checksums; // Only replicate checksums
    bool is_leader;
    bool shutting_down;  // Set to true when user triggers shutdown. All threads check this and abort if true. Used instead of kthread_should_stop(), since the function that flips that boolean to true (kthread_stop()) is blocking, which creates a race condition when we kill the socket & also wait for the thread to stop.
    uint64_t id; // Unique to each Rollbaccine instance
    atomic_t seen_ballot; // Starts at 0, increments whenever we get a message with a higher ballot
    atomic_t ballot; // Starts at 0, set equal to seen_ballot once we complete initialization or reconfiguration

    // Reconfiguration
    atomic_t num_verified_sectors;
    int num_prior_confs;
    struct mutex prior_confs_lock; // Must be obtained for any variable below in this section
    struct configuration *prior_confs;
    bool sent_hash_req; // Whether we've sent a hash request (after P1b) yet. After this is set to true, the 3 variables below will never change and can be obtained without a lock
    uint64_t designated_ballot;
    uint64_t designated_write_index;
    uint64_t designated_id;
    struct mutex reconfig_complete_lock;
    uint64_t reconfig_complete_ballot;
    uint64_t reconfig_complete_write_index;
    wait_queue_head_t ballot_mismatch_wait_queue;

    int write_index;
    struct mutex index_lock;  // Must be obtained for any operation modifying write_index

    atomic_long_t *pending_bio_ring; // Ring buffer of bios received but not yet write-able (because some prefix has not arrived)
    atomic_t pending_bio_ring_head; // Position of next bio to submit in pending_bio_ring

    // Logic for fsyncs blocking on replication
    // IMPORTANT: If both replica_fsync_lock and index_lock must be obtained, obtain index_lock first.
    struct mutex replica_fsync_lock;
    struct fsync_index_list *fsync_index_list;
    int min_acked_fsync_index;
    struct list_head fsyncs_pending_replication;  // List of all fsyncs waiting for replication. Ordered by write index.

    // Logic for writes that block on conflicting writes
    struct rb_root outstanding_ops;  // Tree of all outstanding operations, sorted by the sectors they write to
    struct list_head pending_ops;    // List of all operations that conflict with outstanding operations (or other pending operations)

    struct workqueue_struct *broadcast_bio_queue;
    // Workqueue to submit pending bios because bio_endio can't submit work (because it might sleep)
    struct workqueue_struct *submit_bio_queue;
    struct workqueue_struct *leader_write_disk_end_io_queue;
    struct workqueue_struct *leader_read_disk_end_io_queue;
    struct workqueue_struct *replica_disk_end_io_queue;
    struct workqueue_struct *replica_insert_bio_queue;
    struct workqueue_struct *verify_disk_end_io_queue;
    struct workqueue_struct *fetch_disk_end_io_queue;
    struct workqueue_struct *reconfig_write_disk_end_io_queue;
    struct workqueue_struct *read_hash_end_io_queue;
    struct workqueue_struct *write_hash_end_io_queue;

    // Sockets, tracked so we can kill them on exit.
    struct socket *server_socket;
    // Connected sockets, stored as a multisocket. Handy for broadcasting
    struct rw_semaphore connected_sockets_sem;
    struct list_head connected_sockets;
    struct multisocket *counterpart; // Pointer to the primary/backup multisocket in the current configuration.
    uint64_t counterpart_id;         // ID of our primary/backup counterpart
    struct multisocket *designated_node; // Pointer to the multisocket we're recovering from. Will only be set once so no need to lock
    atomic_t next_socket_id; // Used to load balance the socket to send messages on

    // AEAD
    struct crypto_aead *tfm;

    // Hashing
    struct crypto_shash *signed_hash_alg;
    struct crypto_shash *unsigned_hash_alg;

    // Merkle tree for checksums
    int merkle_tree_height;        // Number of layers in merkle tree, including the layer in memory
    uint64_t disk_pages_for_merkle_tree;
    int *disk_pages_above_merkle_tree_layer;  // Note: [0] = 0 since there is no layer above the root, and [1] = 0 since the root is in memory

    char *merkle_tree_root;  // Layer "0" of the merkle tree
    struct mutex merkle_tree_lock;
    struct rb_root *merkle_tree_layers;  // Note: [0] = NULL always, since that layer is represented by merkle_tree_root in memory

    // Replica threads
    struct semaphore replica_submit_bio_sema;
    struct task_struct *replica_submit_bio_thread;
    struct semaphore replica_ack_fsync_sema;
    struct task_struct *replica_ack_fsync_thread;

    // Counters for tracking memory usage
#ifdef MEMORY_TRACKING
    atomic_t num_fsyncs;
    atomic_t num_total_ops;
    atomic_t num_bio_pages_not_freed;
    atomic_t num_bio_data_not_freed;
    atomic_t num_shallow_clones_not_freed;
    atomic_t num_deep_clones_not_freed;
    int num_rb_nodes;
    int num_bio_sector_ranges;
    int num_fsyncs_pending_replication;
    atomic_t num_checksums;
    atomic_t num_bios_in_pending_bio_ring;
    atomic_t submit_bio_queue_size;
    atomic_t replica_disk_end_io_queue_size;
    atomic_t broadcast_queue_size;
    atomic_t num_messages_larger_than_avg;
    // These counters tell us the maximum amount of memory we need to prealloc
    atomic_t max_outstanding_num_bio_pages;
    atomic_t max_outstanding_num_bio_data;
    atomic_t max_outstanding_num_shallow_clones;
    atomic_t max_outstanding_num_deep_clones;
    int max_outstanding_num_rb_nodes;
    int max_outstanding_num_bio_sector_ranges;
    int max_outstanding_fsyncs_pending_replication;
    atomic_t max_bios_in_pending_bio_ring;
    atomic_t max_distance_between_bios_in_pending_bio_ring;
    atomic_t max_submit_bio_queue_size;
    atomic_t max_replica_disk_end_io_queue_size;
    atomic_t max_broadcast_queue_size;
    int last_acked_fsync_index;
    int num_hashes_received_during_recovery;
    atomic_t num_pages_requested_during_recovery;
    atomic_t num_pages_received_during_recovery;
#endif
};

DEFINE_PER_CPU(int, num_ops_on_cpu);

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
    atomic_t ref_counter;               // The number of clones AND number of pending_checksum_ops with references to this bio. Once it hits 0, the bio can be freed
    struct work_struct broadcast_work;  // So this bio can be scheduled as a job
    struct work_struct submit_bio_work; // So this bio can be scheduled for submission after popping off pending ops
    struct rb_node tree_node;           // So this bio can be inserted into a tree
    struct list_head pending_list;      // So this bio can be inserted into pending_ops
    unsigned char *checksum;     // Checksums for each sector or page, if this is a write
    // Reconfiguration
    struct multisocket *requester;      // The node that requested this block of disk from this node (for reconfiguration)
    struct page *reconfig_read_page;
};


struct merkle_bio_data {
    struct rollbaccine_device *device;
    struct bio *bio_src;
    int layer;
    int page_num;
    bool hashed; // True if this page has been loaded into memory and "hash" has been populated
    bool verified;
    bool dirtied;
    
    struct merkle_bio_data *parent;  // Null if the parent is merkle_tree_root
    int parent_page_offset;

    char hash[SHA256_SIZE];      // Read: The hash of this node once loaded
    void *page_addr;
    struct list_head pending_children; // If this is a merkle leaf, then this is a list of pending_checksum_op. Otherwise,this is a list of merkle_bio_data from lower levels

    struct rb_node tree_node; // For merkle_tree_layers
    struct list_head list; // So this bio can be stored in the parent's pending_children
    struct work_struct work;  // So this bio can be queued in read/write_hash_end_io_queue
};

struct pending_checksum_op {
    int parent_page_offset; // Offset into the parent
    int read_checksum_offset; // Read: Within the read_bio, the offset of the checksum
    char checksum[AES_GCM_AUTH_SIZE]; // Write: The hash of the written page
    struct bio_data *read_bio_data;     // NULL if this is a write, since writes can ACK early and don't need to wait here
    struct list_head list; // For the pending_children list in merkle_bio_data
};

// For keeping track of pending fsyncs
struct bio_fsync_list {
    struct bio *bio_src;
    int write_index;
    struct list_head list;
};

// Thread params: Parameters passed into threads. Should be freed by the thread when it exits.

struct client_thread_params {
    struct socket *sock;
    struct sockaddr_in addr;
    struct rollbaccine_device *device;
    uint64_t server_id; // Expected ID of the server
    uint64_t socket_id;
    bool send_p1a;
};

struct accepted_thread_params {
    struct rollbaccine_device *device;
    struct multisocket *multisocket;
    struct socket_data *socket_data;
};

void submit_merkle_bio_task(struct work_struct *work);
void submit_bio_task(struct work_struct *work);
void init_merkle_tree(struct rollbaccine_device *device);

void recursive_remove_merkle_node(struct merkle_bio_data *bio_data, bool recursive);
void write_hash_end_io_task(struct work_struct *work);
void write_hash_end_io(struct bio *bio);
void verify_merkle_node(struct merkle_bio_data *bio_data);
void recursive_evict_merkle_ancestors(struct merkle_bio_data *bio_data, bool recursive);
void recursive_process_merkle_descendants(struct merkle_bio_data *bio_data);
void read_hash_end_io_task(struct work_struct *work);
void read_hash_end_io(struct bio *bio);

void free_merkle_bio(struct merkle_bio_data *bio_data);
struct merkle_bio_data *create_and_submit_merkle_bio(struct rollbaccine_device *device, int layer, int page_num, int page_offset);
void add_merkle_node_request(struct rollbaccine_device *device, struct merkle_bio_data *child, int layer, int parent_page_num);
void add_merkle_leaf_request(struct rollbaccine_device *device, struct pending_checksum_op *pending_checksum_op, int parent_page_num);
void fetch_merkle_nodes(struct rollbaccine_device *device, struct bio_data *bio_data, int data_dir);

bool send_msg(struct kvec vec, struct socket *sock);
bool receive_msg(struct kvec vec, struct socket *sock);
bool send_page(struct bio_vec vec, struct socket *sock);
void disconnect(struct rollbaccine_device *device, struct multisocket *multisocket);
void alert_client_of_liveness_problem(struct rollbaccine_device *device, uint64_t id);
void print_and_update_latency(char *text, cycles_t *prev_time);  // Also updates prev_time
void submit_bio_task(struct work_struct *work);
void add_to_pending_ops_tail(struct rollbaccine_device *device, struct bio_data *bio_data);
// Returns true if the insert was successful, false if there's a conflict
bool try_insert_into_outstanding_ops(struct rollbaccine_device *device, struct bio_data *bio_data, bool check_pending); 
void remove_from_outstanding_ops_and_unblock(struct rollbaccine_device *device, struct bio *shallow_clone);
void page_cache_free(struct rollbaccine_device *device, struct page *page_to_free);
void page_cache_destroy(struct rollbaccine_device *device);
struct page *page_cache_alloc(struct rollbaccine_device *device);
// Returns the old value
int atomic_max(atomic_t *old, int new);
struct bio_data *alloc_bio_data(struct rollbaccine_device * device);
void ack_bio_to_user_without_executing(struct bio * bio);
void process_follower_fsync_index(struct rollbaccine_device * device, int follower_fsync_index, int follower_id);
bool requires_fsync(struct bio * bio);
void free_bio_data(struct bio_data *bio_data);
void try_free_clones(struct bio_data *bio_data);
void begin_critical_path(struct rollbaccine_device *device);
void send_reconfig_complete_ack(struct rollbaccine_device *device);
void handle_reconfig_complete(struct rollbaccine_device *device, struct multisocket *counterpart, struct metadata_msg *metadata);
void send_reconfig_complete(struct rollbaccine_device *device, struct multisocket *counterpart);
void inc_verified_pages(struct rollbaccine_device *device);
void reconfig_write_disk_end_io_task(struct work_struct *work);
void reconfig_write_disk_end_io(struct bio *bio);
bool handle_disk_sector(struct rollbaccine_device *device, struct socket_data *socket_data, sector_t sector); void fetch_disk_end_io_task(struct work_struct *work);
void fetch_disk_end_io(struct bio *bio);
void handle_disk_req(struct rollbaccine_device *device, struct multisocket *multisocket, sector_t sector);
void send_disk_req(struct rollbaccine_device *device, sector_t sector);
void verify_disk_end_io_task(struct work_struct *work);
void verify_disk_end_io(struct bio *bio);
void leader_write_disk_end_io_task(struct work_struct *work);
void leader_write_disk_end_io(struct bio * shallow_clone);
void try_read_bio_task(struct work_struct *work);
void try_read_bio(struct bio_data *bio_data);
void leader_read_disk_end_io(struct bio * shallow_clone);
void replica_disk_end_io_task(struct work_struct *work);
void replica_disk_end_io(struct bio * received_bio);
void network_end_io(struct bio * deep_clone);
int lock_on_next_free_socket(struct rollbaccine_device *device, struct multisocket *multisocket);
void broadcast_bio(struct work_struct *work);
struct bio *shallow_bio_clone(struct rollbaccine_device * device, struct bio * bio_src);
struct bio *deep_bio_clone(struct rollbaccine_device * device, struct bio * bio_src);
bool verify_msg(struct socket_data *socket_data, char *msg, size_t msg_size, char *expected_hash, uint64_t sender_id, uint64_t sender_socket_id, uint64_t intended_recipient_id,
                uint64_t my_id, uint64_t msg_index);
void hash_merkle_page(struct rollbaccine_device *device, struct merkle_bio_data *bio_data);
void hash_metadata(struct socket_data *socket_data, struct metadata_msg *metadata);
void hash_buffer(struct socket_data *socket_data, char *buffer, size_t len, char *out);
// Returns array of checksums for writes, NULL for reads. Sets error = true if there's an error
int enc_or_dec_bio(struct bio_data * bio_data, enum EncDecType type);
int submit_pending_bio_ring_prefix(void *args);
int ack_fsync(void *args);
bool handle_p1a(struct rollbaccine_device *device, struct multisocket *multisocket, struct metadata_msg p1a);
bool handle_p1b(struct rollbaccine_device *device, struct metadata_msg p1b);
bool handle_hash_req(struct rollbaccine_device *device, struct multisocket *multisocket);
bool handle_hash(struct rollbaccine_device *device, struct multisocket *multisocket, struct socket_data *socket_data);
void blocking_read(struct rollbaccine_device *device, struct multisocket *multisocket, struct socket_data *socket_data);
void init_socket_data(struct rollbaccine_device *device, struct socket_data *socket_data, struct socket *sock, uint64_t sender_id, uint64_t sender_socket_id);
struct multisocket *create_connected_socket_list_if_null(struct rollbaccine_device *device, uint64_t sender_id);
void send_handshake_id(struct rollbaccine_device *device, struct socket *sock, uint64_t thread_id);
struct multithreaded_handshake_pair receive_handshake_id(struct rollbaccine_device *device, struct socket *sock);
bool add_sender_socket_id_if_unique(struct rollbaccine_device *device, struct multisocket *multisocket, uint64_t sender_socket_id);
int connect_to_server(void *args);
int start_client_to_server(struct rollbaccine_device *device, uint64_t server_id, char *addr, ushort port, bool send_p1a);
int listen_to_accepted_socket(void *args);
int listen_for_connections(void *args);
int start_server(struct rollbaccine_device *device, ushort port);
int __init rollbaccine_init_module(void);
void rollbaccine_exit_module(void);

inline char *merkle_root_hash_offset(struct rollbaccine_device *device, struct merkle_bio_data *bio_data) {
    int page_num = bio_data->page_num - device->disk_pages_above_merkle_tree_layer[bio_data->layer];
    return device->merkle_tree_root + page_num * SHA256_SIZE;
}

inline size_t additional_hash_msg_size(size_t checksum_size) { return sizeof(struct additional_hash_msg) + checksum_size; }

inline struct additional_hash_msg *alloc_additional_hash_msg(struct rollbaccine_device *device, size_t checksum_size) {
    return kmalloc(additional_hash_msg_size(checksum_size), GFP_KERNEL);
}

inline bool mem_is_zero(void *addr, size_t size) { return memchr_inv(addr, 0, size) == NULL; }

inline size_t bio_checksum_size(int num_sectors) {
    return num_sectors / SECTORS_PER_PAGE * AES_GCM_AUTH_SIZE;
}

inline void alloc_bio_checksum(struct rollbaccine_device *device, struct bio_data *bio_data) {
    int num_sectors = bio_data->end_sector - bio_data->start_sector;
    if (num_sectors != 0) {
#ifdef MEMORY_TRACKING
        atomic_inc(&device->num_checksums);
#endif
        bio_data->checksum = kmalloc(bio_checksum_size(num_sectors), GFP_KERNEL);
    }
}

inline unsigned char *get_bio_checksum(struct bio_data *bio_data, sector_t current_sector) {
    return bio_data->checksum + (current_sector - bio_data->start_sector) / SECTORS_PER_PAGE * AES_GCM_AUTH_SIZE;
}

inline cycles_t get_cycles_if_flag_on(void) {
#ifdef LATENCY_TRACKING
    return get_cycles();
#else
    return 0;
#endif
}

void submit_merkle_bio_task(struct work_struct *work) {
    struct merkle_bio_data *bio_data = container_of(work, struct merkle_bio_data, work);
    submit_bio_noacct(bio_data->bio_src);
}

void init_merkle_tree(struct rollbaccine_device *device) {
    int i, j;
    // Note: Instead of rounding up, we always add 1, since the disk may choose to start at a sector towards the end 
    unsigned long total_checksum_pages = (device->num_sectors + SECTORS_PER_PAGE * AES_GCM_PER_PAGE - 1) / (SECTORS_PER_PAGE * AES_GCM_PER_PAGE);
    unsigned long pages_in_memory = total_checksum_pages;
    unsigned long pages_on_disk = 0;

    device->merkle_tree_height = 1;

    while (pages_on_disk + pages_in_memory < device->disk_pages_for_merkle_tree && pages_in_memory > 1) {
        pages_on_disk += pages_in_memory;
        pages_in_memory = (pages_in_memory + HASHES_PER_PAGE - 1) / HASHES_PER_PAGE;
        device->merkle_tree_height++;
    }

    printk(KERN_INFO "num_sectors: %llu, disk_pages_for_merkle_tree: %llu, pages_on_disk: %lu, pages_in_memory: %lu, height: %d", device->num_sectors, device->disk_pages_for_merkle_tree, pages_on_disk, pages_in_memory, device->merkle_tree_height);

    device->merkle_tree_root = vzalloc(pages_in_memory * PAGE_SIZE);
    if (!device->merkle_tree_root) {
        printk(KERN_ERR "Could not allocate merkle tree root");
        return;
    }

    device->disk_pages_above_merkle_tree_layer = kzalloc(device->merkle_tree_height * sizeof(int), GFP_KERNEL);

    // Note: [0] = 0 since there is no layer above the root, and [1] = 0 since the root is in memory
    pages_in_memory = total_checksum_pages;
    for (i = device->merkle_tree_height - 1; i > 1; i--) {
        pages_in_memory = (pages_in_memory + HASHES_PER_PAGE - 1) / HASHES_PER_PAGE;
        for (j = i; j < device->merkle_tree_height; j++) {
            device->disk_pages_above_merkle_tree_layer[j] += pages_in_memory;
        }
    }

    device->merkle_tree_layers = kzalloc(device->merkle_tree_height * sizeof(struct rb_root), GFP_KERNEL);
    // Note: [0] = NULL always, since that layer is represented by merkle_tree_root in memory
    for (i = 1; i < device->merkle_tree_height; i++) {
        device->merkle_tree_layers[i] = RB_ROOT;
    }
    printk(KERN_INFO "Finished init_merkle_tree");
}


void recursive_remove_merkle_node(struct merkle_bio_data *bio_data, bool recursive) {
    struct rollbaccine_device *device = bio_data->device;

    rb_erase(&bio_data->tree_node, &device->merkle_tree_layers[bio_data->layer]);
    // Remove from parent's pending_children
    if (bio_data->parent != NULL) {
        list_del(&bio_data->list);
        if (recursive) {
            // Check if any ancestor can also be evicted
            recursive_evict_merkle_ancestors(bio_data->parent, recursive);
        }
    }

    free_merkle_bio(bio_data);
}

void write_hash_end_io_task(struct work_struct *work) {
    struct merkle_bio_data *bio_data = container_of(work, struct merkle_bio_data, work);
    struct bio *bio = bio_data->bio_src;
    struct rollbaccine_device *device = bio_data->device;
    sector_t start_sector;

    mutex_lock(&device->merkle_tree_lock);
    if (list_empty(&bio_data->pending_children)) {
        // The hash has been written to disk and there are no more children; remove the data structure and attempt to evict parents
        recursive_remove_merkle_node(bio_data, true);
    }
    else {
        // Read from disk (again)
        start_sector = bio->bi_iter.bi_sector;
        bio_reset(bio, device->dev->bdev, REQ_OP_READ);
        bio->bi_iter.bi_sector = start_sector;
        bio->bi_iter.bi_size = PAGE_SIZE;
        bio->bi_end_io = read_hash_end_io;
        bio->bi_private = bio_data;
        INIT_WORK(&bio_data->work, submit_merkle_bio_task);
        queue_work(device->submit_bio_queue, &bio_data->work);
    }
    mutex_unlock(&device->merkle_tree_lock);
}

void write_hash_end_io(struct bio *bio) {
    struct merkle_bio_data *bio_data = bio->bi_private;
    INIT_WORK(&bio_data->work, write_hash_end_io_task);
    queue_work(bio_data->device->write_hash_end_io_queue, &bio_data->work);
}

// Note: Assumes that merkle_tree_lock is held, and that if the node has a parent, the parent has been verified
void verify_merkle_node(struct merkle_bio_data *bio_data) {
    int res;

    if (bio_data->parent == NULL) {
        // Verify against root
        res = memcmp(bio_data->hash, merkle_root_hash_offset(bio_data->device, bio_data), SHA256_SIZE);
    }
    else {
        res = memcmp(bio_data->hash, bio_data->parent->page_addr + bio_data->parent_page_offset, SHA256_SIZE);
    }

    if (res != 0) {
        printk_ratelimited(KERN_ERR "Hash mismatch, bio_data: %d, layer: %d, we are all zeros: %d", bio_data->page_num, bio_data->layer, mem_is_zero(bio_data->hash, SHA256_SIZE));
        // Note: Should crash the system and enter recovery
    }
}

// Note: Assumes that merkle_tree_lock is held. Caller must check if bio_data is NULL after this funciton returns
void recursive_evict_merkle_ancestors(struct merkle_bio_data *bio_data, bool recursive) {
    struct rollbaccine_device *device = bio_data->device;
    struct bio *bio = bio_data->bio_src;
    sector_t start_sector;

    // Only evict once there are no more dependents
    if (!list_empty(&bio_data->pending_children)) {
        return;
    }

    if (bio_data->dirtied) {
        // Lower levels have been modified. Modify the parent's hash, then flush to disk. Don't remove the data structure yet (to prevent concurrent reads)
        hash_merkle_page(device, bio_data);

        if (bio_data->parent != NULL) {
            // Modify parent's page
            memcpy(bio_data->parent->page_addr + bio_data->parent_page_offset, bio_data->hash, SHA256_SIZE);
            // printk(KERN_INFO "Child %d dirtying parent %d", bio_data->page_num, bio_data->parent->page_num);
            bio_data->parent->dirtied = true;
        } else {
            // Modify in-memory checksum
            // printk(KERN_INFO "Overwriting root hash: %s", bio_data->hash);
            memcpy(merkle_root_hash_offset(device, bio_data), bio_data->hash, SHA256_SIZE);
        }

        // Reset flags so other nodes don't mistake this for an in-memory page
        bio_data->verified = false;
        bio_data->hashed = false;
        bio_data->dirtied = false;
        kunmap(bio_page(bio));

        // Write to disk
        // printk(KERN_INFO "Writing hash to disk: %d, hash: %s", bio_data->page_num, bio_data->hash);
        start_sector = bio->bi_iter.bi_sector;
        bio_reset(bio, device->dev->bdev, REQ_OP_WRITE);
        bio->bi_iter.bi_sector = start_sector;
        bio->bi_iter.bi_size = PAGE_SIZE;
        bio->bi_end_io = write_hash_end_io;
        bio->bi_private = bio_data;
        INIT_WORK(&bio_data->work, submit_merkle_bio_task);
        queue_work(device->submit_bio_queue, &bio_data->work);
    } else {
        // Lower levels have NOT been modified, remove the data structure and check if parents can be freed too
        recursive_remove_merkle_node(bio_data, recursive);
    }
}

void recursive_process_merkle_descendants(struct merkle_bio_data *bio_data) {
    struct rollbaccine_device *device = bio_data->device;
    struct pending_checksum_op *pending_checksum_op, *next_pending_checksum_op;
    struct merkle_bio_data *merkle_child, *next_merkle_child;

    // 1. Verify self
    verify_merkle_node(bio_data);
    bio_data->verified = true;

    // 2. Process children
    if (bio_data->layer == device->merkle_tree_height - 1) {
        // printk(KERN_INFO "Merkle leaf checking children: %d", bio_data->page_num);
        // This is a leaf, children are pending_checksum_ops
        list_for_each_entry_safe(pending_checksum_op, next_pending_checksum_op, &bio_data->pending_children, list) {
            if (pending_checksum_op->read_bio_data != NULL) {
                // printk(KERN_INFO "Pending read start sector: %llu, offset: %d", pending_checksum_op->read_bio_data->start_sector, pending_checksum_op->parent_page_offset);
                // Read
                memcpy(pending_checksum_op->read_bio_data->checksum + pending_checksum_op->read_checksum_offset, bio_data->page_addr + pending_checksum_op->parent_page_offset, AES_GCM_AUTH_SIZE);
                // Schedule the read
                try_read_bio(pending_checksum_op->read_bio_data);
            } else {
                // Write
                // printk(KERN_INFO "Processing pending write to page: %d, offset: %d", bio_data->page_num, pending_checksum_op->parent_page_offset);
                memcpy(bio_data->page_addr + pending_checksum_op->parent_page_offset, pending_checksum_op->checksum, AES_GCM_AUTH_SIZE);
                bio_data->dirtied = true;
            }
            list_del(&pending_checksum_op->list);
            kfree(pending_checksum_op);
        }
    } else {
        // This is a node, children are merkle_bio_data
        // printk(KERN_INFO "Merkle node checking children: %d", bio_data->page_num);
        list_for_each_entry_safe(merkle_child, next_merkle_child, &bio_data->pending_children, list) {
            // Process children once they have been read from disk
            if (merkle_child->hashed) {
                // printk(KERN_INFO "Merkle node %d child hashed: %d", bio_data->page_num, merkle_child->page_num);
                recursive_process_merkle_descendants(merkle_child);

                // 3. See if the child should be evicted (not recursively, since we're already recusively walking down the tree)
                recursive_evict_merkle_ancestors(merkle_child, false);
            }
        }
    }
}

void read_hash_end_io_task(struct work_struct *work) {
    struct merkle_bio_data *bio_data = container_of(work, struct merkle_bio_data, work);
    struct bio *bio = bio_data->bio_src;
    struct rollbaccine_device *device = bio_data->device;

    // printk(KERN_INFO "Read hash end io task: %d", bio_data->page_num);
    bio_data->page_addr = kmap(bio_page(bio));

    // 1. Hash ourselves (unless this page is all zeros, in which case the hash should also be all zeros)
    if (mem_is_zero(bio_data->page_addr, PAGE_SIZE)) {
        // Set the hash to be all 0s manually, in case the last write changed the hash
        memset(bio_data->hash, 0, SHA256_SIZE);
    }
    else {
        hash_merkle_page(device, bio_data);
        // printk(KERN_INFO "Hashed page: %d, hash: %s", bio_data->page_num, bio_data->hash);
    }

    mutex_lock(&device->merkle_tree_lock);
    bio_data->hashed = true;

    // 2. Check if the parent was verified
    if (bio_data->parent != NULL) {
        if (!bio_data->parent->verified) {
            // printk(KERN_INFO "Parent not verified yet, waiting: %d", bio_data->page_num);
            goto unlock_and_exit;
        }
    }

    // 3. Verify self, then check descendants, evicting when necessary
    // printk(KERN_INFO "Recursively processing merkle descendants: %d", bio_data->page_num);
    recursive_process_merkle_descendants(bio_data);

    // 4. Evict ancestors
    // printk(KERN_INFO "Recursively evicting merkle ancestors: %d", bio_data->page_num);
    recursive_evict_merkle_ancestors(bio_data, true);

    unlock_and_exit:
    mutex_unlock(&device->merkle_tree_lock);
}

void read_hash_end_io(struct bio *bio) {
    struct merkle_bio_data *bio_data = bio->bi_private;
    INIT_WORK(&bio_data->work, read_hash_end_io_task);
    queue_work(bio_data->device->read_hash_end_io_queue, &bio_data->work);
}

void free_merkle_bio(struct merkle_bio_data *bio_data) {
    struct bio *bio = bio_data->bio_src;
    struct page *page = bio_page(bio);
    kunmap(page);
    __free_page(page);
    bio_put(bio);
    kfree(bio_data);
}

struct merkle_bio_data *create_and_submit_merkle_bio(struct rollbaccine_device *device, int layer, int page_num, int page_offset) {
    struct merkle_bio_data *bio_data;
    struct page *page;
    struct bio *bio = bio_alloc_bioset(device->dev->bdev, 1, REQ_OP_READ, GFP_NOIO, &device->bs);
    bio->bi_iter.bi_sector = page_num * SECTORS_PER_PAGE;

    page = alloc_page(GFP_KERNEL);
    if (!page) {
        printk(KERN_ERR "Could not allocate page");
        return NULL;
    }
    __bio_add_page(bio, page, PAGE_SIZE, 0);
    bio->bi_end_io = read_hash_end_io;

    bio_data = kzalloc(sizeof(struct merkle_bio_data), GFP_KERNEL);
    bio_data->device = device;
    bio_data->bio_src = bio;
    bio_data->page_num = page_num;
    bio_data->layer = layer;
    // Note: parent should be filled in once the parent bio is created
    bio_data->parent_page_offset = page_offset;
    INIT_LIST_HEAD(&bio_data->pending_children);
    INIT_WORK(&bio_data->work, submit_merkle_bio_task);

    // Submit in queue (so we don't block mutexes)
    queue_work(device->submit_bio_queue, &bio_data->work);

    bio->bi_private = bio_data;

    return bio_data;
}

void add_merkle_node_request(struct rollbaccine_device *device, struct merkle_bio_data *child, int layer, int parent_page_num) {
    struct rb_node **tree_node_location;
    struct rb_node *tree_node;
    struct merkle_bio_data *merkle_node;
    int parent_page_offset;

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
            // printk(KERN_INFO "Found existing merkle node: %d", parent_page_num);
            // Request for this merkle node exists, add to the tail and stop
            list_add_tail(&child->list, &merkle_node->pending_children);
            child->parent = merkle_node;
            return;
        }
    }

    // Page hasn't been requested, add it
    // printk(KERN_INFO "Creating new merkle node: %d", parent_page_num);
    parent_page_offset = (parent_page_num - device->disk_pages_above_merkle_tree_layer[layer]) % HASHES_PER_PAGE * SHA256_SIZE;
    merkle_node = create_and_submit_merkle_bio(device, layer, parent_page_num, parent_page_offset);
    rb_link_node(&merkle_node->tree_node, tree_node, tree_node_location);
    rb_insert_color(&merkle_node->tree_node, &device->merkle_tree_layers[layer]);

    list_add_tail(&child->list, &merkle_node->pending_children);
    child->parent = merkle_node;

    // Iterate through all ancestors to fetch the pages if necessary
    if (layer - 1 > 0) {
        parent_page_num -= device->disk_pages_above_merkle_tree_layer[layer];  // Remove padding
        // printk(KERN_INFO "Recursively requesting new merkle parent: %d", parent_page_num);
        add_merkle_node_request(device, merkle_node, layer - 1, parent_page_num / HASHES_PER_PAGE + device->disk_pages_above_merkle_tree_layer[layer - 1]);
    }
}

void add_merkle_leaf_request(struct rollbaccine_device *device, struct pending_checksum_op *pending_checksum_op, int parent_page_num) {
    int layer = device->merkle_tree_height - 1;
    struct rb_node **tree_node_location = &(device->merkle_tree_layers[layer].rb_node);
    struct rb_node *tree_node;
    struct merkle_bio_data *merkle_leaf;
    struct pending_checksum_op *other_pending_checksum_op;
    int parent_page_offset;

    // See if the parent page has already been requested
    while (*tree_node_location != NULL) {
        merkle_leaf = container_of(*tree_node_location, struct merkle_bio_data, tree_node);
        tree_node = *tree_node_location;

        if (parent_page_num < merkle_leaf->page_num)
            tree_node_location = &tree_node->rb_left;
        else if (parent_page_num > merkle_leaf->page_num)
            tree_node_location = &tree_node->rb_right;
        else {
            // Request for this merkle node exists, add this pending op to its list, looking for conflicts
            // Optimize by maintaining order based on offset and iterating backwards to reduce search time, assuming ops are mostly fetched in order
            // printk(KERN_INFO "Existing pending op, our offset: %d", pending_checksum_op->parent_page_offset);
            list_for_each_entry_reverse(other_pending_checksum_op, &merkle_leaf->pending_children, list) {
                if (other_pending_checksum_op->parent_page_offset < pending_checksum_op->parent_page_offset) {
                    // Iterating backwards in sorted order, found an op with a smaller offset. We should insert before this op
                    // printk(KERN_INFO "Adding to list: %d", pending_checksum_op->parent_page_offset);
                    list_add(&pending_checksum_op->list, &other_pending_checksum_op->list);
                    return;
                }
                else if (other_pending_checksum_op->parent_page_offset == pending_checksum_op->parent_page_offset) {
                    // Conflict, resolve based on <other op type, this op type>
                    if (other_pending_checksum_op->read_bio_data == NULL) {
                        // <Write, write>: Overwrite
                        if (pending_checksum_op->read_bio_data == NULL) {
                            // printk(KERN_INFO "Conflict, we are a write, overwrite the old write: %d", pending_checksum_op->parent_page_offset);
                            list_replace(&other_pending_checksum_op->list, &pending_checksum_op->list);
                            kfree(other_pending_checksum_op);
                        }
                        // <Write, read>: Overwrite
                        else {
                            // printk(KERN_INFO "Conflict, we are a read, fast return: %d", pending_checksum_op->parent_page_offset);
                            // If we're a read, copy the write's hash for verification once the page is read back from disk
                            memcpy(pending_checksum_op->read_bio_data->checksum + pending_checksum_op->read_checksum_offset, other_pending_checksum_op->checksum, AES_GCM_AUTH_SIZE);
                            // This read op has been satisfied, so we don't need the pending_checksum_op anymore
                            atomic_dec(&pending_checksum_op->read_bio_data->ref_counter);
                            kfree(pending_checksum_op);
                        }
                    }
                    else {
                        // <Read, write> or <Read, read>: Add after
                        // printk(KERN_INFO "Conflict, prior op is read %llu, adding self to tail: %d, write: %d", other_pending_checksum_op->read_bio_data->start_sector, pending_checksum_op->parent_page_offset, pending_checksum_op->read_bio_data == NULL);
                        list_add(&pending_checksum_op->list, &other_pending_checksum_op->list);
                    }
                    return;
                }
            }

            // List empty, add to head. This is only possible if the page finished processing all children and is en route to disk
            list_add(&pending_checksum_op->list, &merkle_leaf->pending_children);
            return;
        }
    }

    // Page hasn't been requested, add it
    // printk(KERN_INFO "Creating new merkle leaf: %d", parent_page_num);
    parent_page_offset = (parent_page_num - device->disk_pages_above_merkle_tree_layer[layer]) % HASHES_PER_PAGE * SHA256_SIZE;
    merkle_leaf = create_and_submit_merkle_bio(device, layer, parent_page_num, parent_page_offset);
    rb_link_node(&merkle_leaf->tree_node, tree_node, tree_node_location);
    rb_insert_color(&merkle_leaf->tree_node, &device->merkle_tree_layers[layer]);

    // Add this pending op to the new page
    list_add_tail(&pending_checksum_op->list, &merkle_leaf->pending_children);

    // Iterate through all ancestors to fetch the pages if necessary
    if (layer - 1 > 0) {
        parent_page_num -= device->disk_pages_above_merkle_tree_layer[layer];  // Remove padding
        // printk(KERN_INFO "Requesting new merkle parent: %lu", parent_page_num / HASHES_PER_PAGE);
        add_merkle_node_request(device, merkle_leaf, layer - 1, parent_page_num / HASHES_PER_PAGE + device->disk_pages_above_merkle_tree_layer[layer - 1]);
    }
}

void fetch_merkle_nodes(struct rollbaccine_device *device, struct bio_data *bio_data, int data_dir) {
    struct pending_checksum_op *pending_checksum_op;
    sector_t curr_sector;
    unsigned long parent_page_num, curr_page, num_pages;
    int checksum_offset = 0;

    // Don't need to do anything if the bio is empty
    if (bio_data->start_sector == bio_data->end_sector) {
        return;
    }

    // Fast path if the entire tree is in memory
    if (device->merkle_tree_height == 1) {
        curr_page = bio_data->start_sector / SECTORS_PER_PAGE;
        num_pages = (bio_data->end_sector - bio_data->start_sector) / SECTORS_PER_PAGE;
        // printk(KERN_INFO "Hash fast path, start sector: %llu, is write: %d", bio_data->start_sector, bio_data_dir(bio) == WRITE);
        switch (data_dir) {
            case WRITE:
                memcpy(device->merkle_tree_root + curr_page * AES_GCM_AUTH_SIZE, bio_data->checksum, num_pages * AES_GCM_AUTH_SIZE);
                break;
            case READ:
                memcpy(bio_data->checksum, device->merkle_tree_root + curr_page * AES_GCM_AUTH_SIZE, num_pages * AES_GCM_AUTH_SIZE);
                break;
        }
        return;
    }

    mutex_lock(&device->merkle_tree_lock);
    // printk(KERN_INFO "Started adding pending ops for bio %llu, write: %d", bio_data->start_sector, bio_data_dir(bio) == WRITE);
    // Create a pending_checksum_op for each page in the bio
    for (curr_sector = bio_data->start_sector; curr_sector < bio_data->end_sector; curr_sector += SECTORS_PER_PAGE) {
        // Remove merkle tree padding in calculations
        curr_page = curr_sector / SECTORS_PER_PAGE - device->disk_pages_for_merkle_tree;

        pending_checksum_op = kmalloc(sizeof(struct pending_checksum_op), GFP_KERNEL);
        pending_checksum_op->parent_page_offset = (curr_page % AES_GCM_PER_PAGE) * AES_GCM_AUTH_SIZE;

        switch (data_dir) {
            case WRITE:
                // If this is a write, copy the relevant part of the checksum to write to the parent
                memcpy(pending_checksum_op->checksum, bio_data->checksum + checksum_offset, AES_GCM_AUTH_SIZE);
                break;
            case READ:
                // If this is a read, leave a reference to the bio so it can be notified when the read is ready
                pending_checksum_op->read_bio_data = bio_data;
                atomic_inc(&bio_data->ref_counter);
                // printk(KERN_INFO "Incrementing ref_counter for read bio %llu, parent page offset: %d", bio_data->start_sector, pending_checksum_op->parent_page_offset);
                pending_checksum_op->read_checksum_offset = checksum_offset;
                break;
        }
        
        parent_page_num = curr_page / AES_GCM_PER_PAGE + device->disk_pages_above_merkle_tree_layer[device->merkle_tree_height - 1];

        // Add to pending ops, check if the parent's parent also needs to be fetched
        // printk(KERN_INFO "Requesting parent for sector: %llu, parent: %lu, offset: %d, write: %d", curr_sector, parent_page_num, pending_checksum_op->parent_page_offset, data_dir);
        add_merkle_leaf_request(device, pending_checksum_op, parent_page_num);

        checksum_offset += AES_GCM_AUTH_SIZE;
    }
    // printk(KERN_INFO "Finished adding pending ops for bio %llu, write: %d", bio_data->start_sector, bio_data_dir(bio) == WRITE);
    mutex_unlock(&device->merkle_tree_lock);
}

bool send_msg(struct kvec vec, struct socket *sock) {
    struct msghdr msg_header;
    int sent;

    msg_header.msg_name = NULL;
    msg_header.msg_namelen = 0;
    msg_header.msg_control = NULL;
    msg_header.msg_controllen = 0;
    msg_header.msg_flags = 0;

    // Keep retrying send until the whole message is sent
    while (vec.iov_len > 0) {
        sent = kernel_sendmsg(sock, &msg_header, &vec, 1, vec.iov_len);
        if (sent <= 0) {
            printk_ratelimited(KERN_ERR "Error sending message, aborting");
            return false;
        } else {
            vec.iov_base += sent;
            vec.iov_len -= sent;
        }
    }
    return true;
}

bool receive_msg(struct kvec vec, struct socket *sock) {
    struct msghdr msg_header;
    int received;

    msg_header.msg_name = 0;
    msg_header.msg_namelen = 0;
    msg_header.msg_flags = MSG_WAITALL | MSG_NOSIGNAL;
    msg_header.msg_control = NULL;
    msg_header.msg_controllen = 0;

    received = kernel_recvmsg(sock, &msg_header, &vec, vec.iov_len, vec.iov_len, msg_header.msg_flags);
    if (received <= 0) {
        printk_ratelimited(KERN_ERR "Error receiving message, aborting");
        return false;
    }
    return true;
}

bool send_page(struct bio_vec bvec, struct socket *sock) {
    struct msghdr msg_header;
    int sent;

    msg_header.msg_name = NULL;
    msg_header.msg_namelen = 0;
    msg_header.msg_control = NULL;
    msg_header.msg_controllen = 0;
    msg_header.msg_flags = 0;

    while (bvec.bv_len > 0) {
        iov_iter_bvec(&msg_header.msg_iter, ITER_SOURCE, &bvec, 1, bvec.bv_len);

        sent = sock_sendmsg(sock, &msg_header);
        if (sent <= 0) {
            printk_ratelimited(KERN_ERR "Error broadcasting pages");
            return false;
        } else {
            bvec.bv_offset += sent;
            bvec.bv_len -= sent;
        }
    }
    return true;
}

void disconnect(struct rollbaccine_device *device, struct multisocket *multisocket) {
    int i;
    struct socket_data *socket_data;
    struct bio_data *bio_data;

    if (atomic_cmpxchg(&multisocket->disconnected, 0, 1) == 1) {
        return;
    }

    printk(KERN_INFO "disconnect: Attempting to shut down sockets");
    down_write(&device->connected_sockets_sem);
    // Shut down all sockets. This will trigger all blocking_read threads to exit
    for (i = 0; i < NUM_NICS; i++) {
        socket_data = &multisocket->socket_data[i];
        // Note: We don't release the socket here. The blocking_read threads will organically stop and release the sockets
        kernel_sock_shutdown(socket_data->sock, SHUT_RDWR);
    }
    // Remove this multisocket from connected sockets
    list_del(&multisocket->list);
    up_write(&device->connected_sockets_sem);

    // If this is the replica, zero out the pending bio ring. This is ok because anything this replica ACKed must've already been popped off the ring
    if (!device->shutting_down && !device->is_leader && multisocket == device->counterpart) {
        printk(KERN_INFO "Replica zeroing out pending bio ring");
        for (i = 0; i < ROLLBACCINE_PENDING_BIO_RING_SIZE; i++) {
            bio_data = (struct bio_data*) atomic_long_xchg(&device->pending_bio_ring[i], 0);
            if (bio_data != NULL) {
                free_bio_data(bio_data);
            }
        }
#ifdef MEMORY_TRACKING
        atomic_set(&device->num_bios_in_pending_bio_ring, 0);
#endif
    }
    printk(KERN_INFO "Disconnected from sender");
}

void alert_client_of_liveness_problem(struct rollbaccine_device *device, uint64_t id) {
    // printk_ratelimited(KERN_ERR "Liveness problem detected for id %llu, alerting client", id);
    // TODO: Telling client about liveness problem
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

    if (bio_data->shallow_clone != NULL) {
        submit_bio_noacct(bio_data->shallow_clone);
    }
    else {
        submit_bio_noacct(bio_data->bio_src);
    }

#ifdef MEMORY_TRACKING
    this_cpu_inc(num_ops_on_cpu);
    int curr_queue_size = atomic_dec_return(&device->submit_bio_queue_size);
    atomic_max(&device->max_submit_bio_queue_size, curr_queue_size + 1);
#endif
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

    mutex_lock(&device->index_lock);
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
        atomic_inc(&device->submit_bio_queue_size);
#endif
    }
    mutex_unlock(&device->index_lock);
}

// Put the freed page back in the cache for reuse
void page_cache_free(struct rollbaccine_device *device, struct page *page_to_free) {
    mutex_lock(&device->page_cache_lock);
    if (device->page_cache_size == 0) {
        device->page_cache = page_to_free;
    } else {
        // Point the new page to the current page_cache
        page_private(page_to_free) = (unsigned long)device->page_cache;
        device->page_cache = page_to_free;
    }
    device->page_cache_size++;
    mutex_unlock(&device->page_cache_lock);
}

void page_cache_destroy(struct rollbaccine_device *device) {
    struct page *tmp;

    mutex_lock(&device->page_cache_lock);
    while (device->page_cache_size > 0) {
        tmp = device->page_cache;
        device->page_cache = (struct page *)page_private(device->page_cache);
        __free_page(tmp);
        device->page_cache_size--;
    }
    mutex_unlock(&device->page_cache_lock);
}

// Get a previously allocated page or allocate a new one if necessary. Store pointers to next pages in page_private, like in drbd.
struct page *page_cache_alloc(struct rollbaccine_device *device) {
    struct page *new_page;
    bool need_new_page = false;

    mutex_lock(&device->page_cache_lock);
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
    mutex_unlock(&device->page_cache_lock);

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
int atomic_max(atomic_t *old, int new) {
    int old_val;
    do {
        old_val = atomic_read(old);
    } while (old_val < new &&atomic_cmpxchg(old, old_val, new) != old_val);
    return old_val;
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

void ack_bio_to_user_without_executing(struct bio *bio) {
    bio->bi_status = BLK_STS_OK;
    bio_endio(bio);
}

// Returns the max int that a quorum agrees to. Note that since the leader itself must have fsync index >= followers' fsync index, the quorum size is f (not f+1).
// Assumes that the bio->bi_private field stores the write index
void process_follower_fsync_index(struct rollbaccine_device *device, int follower_fsync_index, int follower_id) {
    bool inserted_index = false;
    struct bio_fsync_list *bio_fsync_data;
    struct fsync_index_list *fsync_index_entry;
    int i;
    int min_fsync_index = INT_MAX;

    mutex_lock(&device->replica_fsync_lock);
    // 1. Insert this follower's fsync index into the fsync index list, if possible
    // 2. If not possible, create an entry and insert the index
    // 3. Calculate the min_fsync_index across respondents
    for (i = 0; i < device->f; i++) {
        fsync_index_entry = &device->fsync_index_list[i];

        if (fsync_index_entry->server_id == follower_id) {
            fsync_index_entry->fsync_index = follower_fsync_index;
            inserted_index = true;
        }
        if (fsync_index_entry->server_id == -1 && !inserted_index) {
            // This server doesn't have an entry, set it
            fsync_index_entry->server_id = follower_id;
            fsync_index_entry->fsync_index = follower_fsync_index;
            inserted_index = true;
        }

        min_fsync_index = min(min_fsync_index, fsync_index_entry->fsync_index);
    }

    // Loop through all blocked fsyncs if the max index has changed
    if (device->min_acked_fsync_index < min_fsync_index) {
        device->min_acked_fsync_index = min_fsync_index;
#ifdef MEMORY_TRACKING
        device->last_acked_fsync_index = follower_fsync_index;
        device->max_outstanding_fsyncs_pending_replication = umax(device->max_outstanding_fsyncs_pending_replication, device->num_fsyncs_pending_replication);
#endif
        while (!list_empty(&device->fsyncs_pending_replication)) {
            bio_fsync_data = list_first_entry(&device->fsyncs_pending_replication, struct bio_fsync_list, list);
            if (bio_fsync_data->write_index <= min_fsync_index) {
                // printk(KERN_INFO "Fsync with write index %d satisfied", bio_data->write_index);
                // Remove from queue
                list_del(&bio_fsync_data->list);
                // Ack the fsync to the user
                ack_bio_to_user_without_executing(bio_fsync_data->bio_src);
                kfree(bio_fsync_data);
    #ifdef MEMORY_TRACKING
                device->num_fsyncs_pending_replication -= 1;
    #endif
            } else {
                break;
            }
        }
    }
    mutex_unlock(&device->replica_fsync_lock);
}

bool requires_fsync(struct bio *bio) { return bio->bi_opf & (REQ_PREFLUSH | REQ_FUA); }

// Because we alloc pages when we receive the bios, we have to free them when it's done writing
void free_bio_data(struct bio_data *bio_data) {
    struct rollbaccine_device *device = bio_data->device;
    struct bio_vec bvec;
    struct bvec_iter iter;
    int num_bio_pages;

    // Free the deep_clone
    if (bio_data->deep_clone != NULL) {
        // Free each page. Reset bio to start first, in case it's pointing to the end
        bio_data->deep_clone->bi_iter.bi_sector = bio_data->start_sector;
        bio_data->deep_clone->bi_iter.bi_size = (bio_data->end_sector - bio_data->start_sector) * SECTOR_SIZE;
        bio_data->deep_clone->bi_iter.bi_idx = 0;
        bio_for_each_segment(bvec, bio_data->deep_clone, iter) {
            page_cache_free(device, bvec.bv_page);
            // __free_page(bvec.bv_page);
#ifdef MEMORY_TRACKING
            int num_deep_clones = atomic_dec_return(&device->num_deep_clones_not_freed);
            atomic_max(&device->max_outstanding_num_deep_clones, num_deep_clones + 1);
            num_bio_pages = atomic_dec_return(&device->num_bio_pages_not_freed);
            atomic_max(&device->max_outstanding_num_bio_pages, num_bio_pages + 1);
#endif
        }
        bio_put(bio_data->deep_clone);
    }

    // Free the shallow_clone
    if (bio_data->shallow_clone != NULL) {
#ifdef MEMORY_TRACKING
        int num_shallow_clones = atomic_dec_return(&device->num_shallow_clones_not_freed);
        atomic_max(&device->max_outstanding_num_shallow_clones, num_shallow_clones + 1);
#endif
        bio_put(bio_data->shallow_clone);
    }

    // Free the checksum
    if (bio_data->checksum != NULL) {
#ifdef MEMORY_TRACKING
        atomic_dec(&device->num_checksums);
#endif
        kfree(bio_data->checksum);
    }

    // Free the bio_data
    kmem_cache_free(device->bio_data_cache, bio_data);
    // kfree(bio_data);
#ifdef MEMORY_TRACKING
    int num_bio_data = atomic_dec_return(&device->num_bio_data_not_freed);
    atomic_max(&device->max_outstanding_num_bio_data, num_bio_data + 1);
#endif
}

// Decrement the reference counter tracking the number of clones. Free both deep & shallow clones when it hits 0.
void try_free_clones(struct bio_data *bio_data) {
    // If ref_counter == 0
    if (atomic_dec_and_test(&bio_data->ref_counter)) {
        free_bio_data(bio_data);
    } else {
        // printk(KERN_INFO "Decrementing clone ref count to %d, write index: %d", atomic_read(&deep_clone_bio_data->ref_counter), deep_clone_bio_data->write_index);
    }
}

void begin_critical_path(struct rollbaccine_device *device) {
    struct bio_fsync_list *bio_fsync_data;
    int i;

    printk(KERN_INFO "Beginning critical path");

    mutex_lock(&device->index_lock);
    // If we're orchestrating this reconfiguration
    if (atomic_read(&device->seen_ballot) == device->id) {
        device->write_index = device->designated_write_index;
    }
    else {
        mutex_lock(&device->reconfig_complete_lock);
        device->write_index = device->reconfig_complete_write_index;
        mutex_unlock(&device->reconfig_complete_lock);
    }
    printk(KERN_INFO "Setting write index to %d", device->write_index);

    if (device->is_leader) {
        printk(KERN_INFO "Flushing all fsyncs");
        // Flush all fsyncs if we are the leader, because we know the backup must have it
        mutex_lock(&device->replica_fsync_lock);
        device->min_acked_fsync_index = device->write_index;
        for (i = 0; i < device->f; i++) {
            device->fsync_index_list[i].server_id = -1;
            device->fsync_index_list[i].fsync_index = 0;
        }
        while (!list_empty(&device->fsyncs_pending_replication)) {
            bio_fsync_data = list_first_entry(&device->fsyncs_pending_replication, struct bio_fsync_list, list);
            list_del(&bio_fsync_data->list);
            ack_bio_to_user_without_executing(bio_fsync_data->bio_src);
            kfree(bio_fsync_data);
        }
#ifdef MEMORY_TRACKING
        device->num_fsyncs_pending_replication = 0;
#endif
        mutex_unlock(&device->replica_fsync_lock);
    }
    else {
        atomic_set(&device->pending_bio_ring_head, device->write_index + 1);
    }
    mutex_unlock(&device->index_lock);

    // Set ballot = seen_ballot
    printk(KERN_INFO "Setting ballot = seen_ballot");
    atomic_set(&device->ballot, atomic_read(&device->seen_ballot));

    // Flush blocking writes
    wake_up_interruptible(&device->ballot_mismatch_wait_queue);

    // TODO: Tell the user that we're ready
}

void send_reconfig_complete_ack(struct rollbaccine_device *device) {
    struct multisocket *counterpart;
    struct metadata_msg metadata;
    struct kvec vec;
    int socket_id;
    struct socket_data *socket_data;
    bool success;

    printk(KERN_INFO "Sending reconfig complete ACK");

    metadata.type = ROLLBACCINE_RECONFIG_COMPLETE_ACK;
    metadata.seen_ballot = atomic_read(&device->seen_ballot);
    metadata.sender_id = device->id;

    vec.iov_base = &metadata;
    vec.iov_len = sizeof(struct metadata_msg);

    down_read(&device->connected_sockets_sem);
    counterpart = device->counterpart;
    socket_id = lock_on_next_free_socket(device, counterpart);
    socket_data = &counterpart->socket_data[socket_id];

    metadata.recipient_id = counterpart->sender_id;
    metadata.sender_socket_id = socket_data->sender_socket_id;
    metadata.msg_index = socket_data->last_sent_msg_index++;
    hash_metadata(socket_data, &metadata);

    success = send_msg(vec, socket_data->sock);
    if (!success) {
        printk(KERN_ERR "Error sending reconfig complete ACK message");
    }

    mutex_unlock(&socket_data->socket_mutex);
    up_read(&device->connected_sockets_sem);
}

void handle_reconfig_complete(struct rollbaccine_device *device, struct multisocket *counterpart, struct metadata_msg *metadata) {
    uint64_t senders_designated_node;
    
    mutex_lock(&device->reconfig_complete_lock);
    printk(KERN_INFO "Received reconfig complete");

    if (device->reconfig_complete_ballot >= metadata->seen_ballot) {
        printk(KERN_INFO "Received duplicate reconfig complete, dropping");
        mutex_unlock(&device->reconfig_complete_lock);
        return;
    }

    device->reconfig_complete_ballot = metadata->seen_ballot;
    device->reconfig_complete_write_index = metadata->write_index;
    mutex_unlock(&device->reconfig_complete_lock);

    // The sender must be our new counterpart. Modify it
    device->counterpart_id = metadata->sender_id;
    device->counterpart = counterpart;

    // If we are also the designated node, immediately ACK
    senders_designated_node = metadata->bi_opf;
    if (senders_designated_node == device->id) {
        printk(KERN_INFO "Immediately ACKing reconfig complete because we are also the designated node");
        send_reconfig_complete_ack(device);
        begin_critical_path(device);
    }
}

void send_reconfig_complete(struct rollbaccine_device *device, struct multisocket *counterpart) {
    struct metadata_msg metadata;
    struct kvec vec;
    int socket_id;
    struct socket_data *socket_data;
    bool success;

    printk(KERN_INFO "Sending reconfig complete message");

    metadata.type = ROLLBACCINE_RECONFIG_COMPLETE;
    metadata.seen_ballot = atomic_read(&device->seen_ballot);
    metadata.sender_id = device->id;
    metadata.recipient_id = counterpart->sender_id;
    metadata.write_index = device->designated_write_index;
    metadata.bi_opf = device->designated_id; // Abuse bi_opf to also send designated_id

    vec.iov_base = &metadata;
    vec.iov_len = sizeof(struct metadata_msg);

    down_read(&device->connected_sockets_sem);
    socket_id = lock_on_next_free_socket(device, counterpart);
    socket_data = &counterpart->socket_data[socket_id];

    metadata.sender_socket_id = socket_data->sender_socket_id;
    metadata.msg_index = socket_data->last_sent_msg_index++;
    hash_metadata(socket_data, &metadata);

    success = send_msg(vec, socket_data->sock);
    if (!success) {
        printk(KERN_ERR "Error sending reconfig complete message");
    }

    mutex_unlock(&socket_data->socket_mutex);
    up_read(&device->connected_sockets_sem);
}

void inc_verified_pages(struct rollbaccine_device *device) {
    uint64_t counterpart_id, reconfig_complete_ballot;
    struct multisocket *counterpart;
    int num_verified_sectors = atomic_add_return(SECTORS_PER_PAGE, &device->num_verified_sectors);

    // Tell the counterpart that we're ready to start!
    if (num_verified_sectors >= device->num_sectors) {
        printk(KERN_INFO "All sectors verified!");

        // If we're orchestrating this reconfiguration
        if (atomic_read(&device->seen_ballot) == device->id) {
            // If counterpart != designated node, then send hashes to counterpart
            counterpart_id = device->counterpart_id;
            counterpart = device->counterpart;
            if (counterpart_id != device->designated_id) {
                printk(KERN_INFO "Counterpart %llu is not designated node %llu, sending hashes to counterpart", counterpart_id, device->designated_id);
                handle_hash_req(device, counterpart);
            }
            
            // Set our write_index and tell our counterpart we're done
            mutex_lock(&device->index_lock);
            device->write_index = device->designated_write_index;
            mutex_unlock(&device->index_lock);
            send_reconfig_complete(device, counterpart);
        }
        // If we're the counterpart to the reconfiguring node
        else {
            // If we already got the RECONFIG_COMPLETE message, then send an ACK
            mutex_lock(&device->reconfig_complete_lock);
            reconfig_complete_ballot = device->reconfig_complete_ballot;
            mutex_unlock(&device->reconfig_complete_lock);

            if (reconfig_complete_ballot == atomic_read(&device->seen_ballot)) {
                send_reconfig_complete_ack(device);
                begin_critical_path(device);
            }
        }
    }
}

void reconfig_write_disk_end_io_task(struct work_struct *work) {
    struct bio_data *bio_data = container_of(work, struct bio_data, submit_bio_work);
    free_bio_data(bio_data);
}
    
void reconfig_write_disk_end_io(struct bio *bio) {
    struct bio_data *bio_data = bio->bi_private;
    INIT_WORK(&bio_data->submit_bio_work, reconfig_write_disk_end_io_task);
    queue_work(bio_data->device->reconfig_write_disk_end_io_queue, &bio_data->submit_bio_work);
}

bool handle_disk_sector(struct rollbaccine_device *device, struct socket_data *socket_data, sector_t sector) {
    struct bio_data *bio_data;
    struct bio *bio;
    struct page *page;
    struct kvec vec;
    unsigned char checksum[AES_GCM_AUTH_SIZE];
    bool success;
    int error;

    // printk(KERN_INFO "Receiving disk sector %llu", sector);
#ifdef MEMORY_TRACKING
    atomic_inc(&device->num_pages_received_during_recovery);
#endif

    bio = bio_alloc_bioset(device->dev->bdev, 1, REQ_OP_WRITE, GFP_NOIO, &device->bs);
    bio->bi_iter.bi_sector = sector;
    bio->bi_end_io = reconfig_write_disk_end_io;

    bio_data = alloc_bio_data(device);
    bio_data->device = device;
    bio_data->bio_src = bio;
    bio_data->deep_clone = bio;
    bio_data->start_sector = sector;
    bio_data->end_sector = sector + SECTORS_PER_PAGE;
    bio_data->checksum = checksum;
    bio->bi_private = bio_data;

    page = page_cache_alloc(device);
#ifdef MEMORY_TRACKING
    atomic_inc(&device->num_bio_pages_not_freed);
#endif
    vec.iov_base = page_address(page);
    vec.iov_len = PAGE_SIZE;

    success = receive_msg(vec, socket_data->sock);
    if (!success) {
        printk(KERN_ERR "Error reading from socket");
        free_bio_data(bio_data);
        return false;
    }
    __bio_add_page(bio, page, PAGE_SIZE, 0);

    // Fill local checksum just for the VERIFY function
    // We can't use DECRYPT here because it decrypts in place, so we end up writing plaintext to disk
    memcpy(checksum, device->merkle_tree_root + sector / SECTORS_PER_PAGE, AES_GCM_AUTH_SIZE);
    error = enc_or_dec_bio(bio_data, ROLLBACCINE_VERIFY);
    bio_data->checksum = NULL;
    if (error != 0) {
        printk(KERN_ERR "Backup received invalid page");
        free_bio_data(bio_data);
        return false;
    }

    inc_verified_pages(device);

    submit_bio_noacct(bio);
    return true;
}

void fetch_disk_end_io_task(struct work_struct *work) {
    struct bio_data *bio_data = container_of(work, struct bio_data, submit_bio_work);
    struct rollbaccine_device *device = bio_data->device;
    struct multisocket *multisocket = bio_data->requester;
    struct metadata_msg metadata;
    struct kvec vec;
    struct socket_data *socket_data;
    struct bio_vec bvec;
    int socket_id;
    bool success;

    // Send the page contents to the one who requested this disk
    // printk(KERN_INFO "Sending %llu to the disk requester", bio_data->start_sector);

    // 1. Send a DISK_BEGIN message
    metadata.type = ROLLBACCINE_DISK_BEGIN;
    metadata.seen_ballot = atomic_read(&device->seen_ballot);
    metadata.sender_id = device->id;
    metadata.recipient_id = multisocket->sender_id;
    metadata.sector = bio_data->start_sector;

    vec.iov_base = &metadata;
    vec.iov_len = sizeof(struct metadata_msg);

    // Lock the socket and use the same one for all hash messages
    down_read(&device->connected_sockets_sem);
    socket_id = lock_on_next_free_socket(device, bio_data->requester);
    socket_data = &multisocket->socket_data[socket_id];

    metadata.sender_socket_id = socket_data->sender_socket_id;
    metadata.msg_index = socket_data->last_sent_msg_index++;
    hash_metadata(socket_data, &metadata);

    success = send_msg(vec, socket_data->sock);
    if (!success)
        goto unlock_and_free;

    // 2. Send the actual disk content
    bvec_set_page(&bvec, bio_data->reconfig_read_page, PAGE_SIZE, 0);
    success = send_page(bvec, socket_data->sock);
    if (!success)
        goto unlock_and_free;

unlock_and_free:
    mutex_unlock(&socket_data->socket_mutex);
    up_read(&device->connected_sockets_sem);

    free_bio_data(bio_data);
}

void fetch_disk_end_io(struct bio *bio) {
    struct bio_data *bio_data = bio->bi_private;
    INIT_WORK(&bio_data->submit_bio_work, fetch_disk_end_io_task);
    queue_work(bio_data->device->fetch_disk_end_io_queue, &bio_data->submit_bio_work);
}

void handle_disk_req(struct rollbaccine_device *device, struct multisocket *multisocket, sector_t sector) {
    struct bio_data *bio_data;
    struct bio *bio;
    struct page *page;

    // Send a bio to disk to read the sector that's requested
    // printk(KERN_INFO "Reading %llu from disk per request", sector);

    bio = bio_alloc_bioset(device->dev->bdev, 1, REQ_OP_READ, GFP_NOIO, &device->bs);
    bio->bi_iter.bi_sector = sector;
    page = page_cache_alloc(device);
    __bio_add_page(bio, page, PAGE_SIZE, 0);
#ifdef MEMORY_TRACKING
    atomic_inc(&device->num_bio_pages_not_freed);
#endif

    bio_data = alloc_bio_data(device);
    bio_data->device = device;
    bio_data->bio_src = bio;
    bio_data->deep_clone = bio;
    bio_data->start_sector = sector;
    bio_data->end_sector = sector + SECTORS_PER_PAGE;
    bio_data->requester = multisocket;
    bio_data->reconfig_read_page = page;
    alloc_bio_checksum(device, bio_data);
    bio->bi_private = bio_data;

    bio_data->shallow_clone = shallow_bio_clone(device, bio);
    bio_data->shallow_clone->bi_end_io = fetch_disk_end_io;
    bio_data->shallow_clone->bi_private = bio_data;

    submit_bio_noacct(bio_data->shallow_clone);
}

void send_disk_req(struct rollbaccine_device *device, sector_t sector) {
    struct metadata_msg metadata;
    struct kvec vec;
    struct socket_data *socket_data;
    int socket_id;
    bool success;

#ifdef MEMORY_TRACKING
    atomic_inc(&device->num_pages_requested_during_recovery);
#endif

    // Request a good page from the designated backup
    metadata.type = ROLLBACCINE_DISK_REQ;
    metadata.seen_ballot = atomic_read(&device->seen_ballot);
    metadata.sender_id = device->id;
    metadata.recipient_id = device->designated_id;
    metadata.sector = sector;

    down_read(&device->connected_sockets_sem);
    socket_id = lock_on_next_free_socket(device, device->designated_node);
    metadata.sender_socket_id = socket_id;
    socket_data = &device->designated_node->socket_data[socket_id];
    metadata.msg_index = socket_data->last_sent_msg_index++;
    hash_metadata(socket_data, &metadata);

    vec.iov_base = &metadata;
    vec.iov_len = sizeof(struct metadata_msg);

    // printk(KERN_INFO "Requesting disk sector %llu from the designated node", sector);
    success = send_msg(vec, socket_data->sock);
    if (!success) {
        printk_ratelimited(KERN_ERR "Lost connection to designated node?");
        alert_client_of_liveness_problem(device, device->designated_id);
    }
    mutex_unlock(&socket_data->socket_mutex);
    up_read(&device->connected_sockets_sem);
}

void verify_disk_end_io_task(struct work_struct *work) {
    struct bio_data *bio_data = container_of(work, struct bio_data, submit_bio_work);
    struct rollbaccine_device *device = bio_data->device;
    
    int error = enc_or_dec_bio(bio_data, ROLLBACCINE_DECRYPT);
    if (error != 0)
        send_disk_req(device, bio_data->start_sector);
    else
        inc_verified_pages(device);

    free_bio_data(bio_data);
}

void verify_disk_end_io(struct bio *bio) {
    struct bio_data *bio_data = bio->bi_private;
    INIT_WORK(&bio_data->submit_bio_work, verify_disk_end_io_task);
    queue_work(bio_data->device->verify_disk_end_io_queue, &bio_data->submit_bio_work);
}

void try_read_bio_task(struct work_struct *work) {
    struct bio_data *bio_data = container_of(work, struct bio_data, submit_bio_work);
    struct rollbaccine_device *device = bio_data->device;
    int error;

    // Decrypt
    error = enc_or_dec_bio(bio_data, ROLLBACCINE_DECRYPT);
    if (error != 0) {
        alert_client_of_liveness_problem(device, device->id);
        // TODO: Panic and crash
    }
    // Unblock pending writes
    remove_from_outstanding_ops_and_unblock(device, bio_data->shallow_clone);
    // Return to user
    bio_endio(bio_data->bio_src);

    free_bio_data(bio_data);
}

void try_read_bio(struct bio_data *bio_data) {
    // Ready to read when there are 0 other references
    // printk(KERN_INFO "Decrementing ref_counter for read bio %llu", bio_data->start_sector);
    if (atomic_dec_and_test(&bio_data->ref_counter)) {
        INIT_WORK(&bio_data->submit_bio_work, try_read_bio_task);
        queue_work(bio_data->device->leader_read_disk_end_io_queue, &bio_data->submit_bio_work);
        // printk(KERN_INFO "Decrypting and freeing read bio %llu", bio_data->start_sector);
    }
}

void leader_read_disk_end_io(struct bio *shallow_clone) {
    struct bio_data *bio_data = shallow_clone->bi_private;
    try_read_bio(bio_data);
}

void leader_write_disk_end_io_task(struct work_struct *work) {
    struct bio_data *bio_data = container_of(work, struct bio_data, submit_bio_work);
    struct rollbaccine_device *device = bio_data->device;
    // printk(KERN_INFO "Leader end_io shallow clone %p bio data write index: %d, deep clone: %p", bio_data->shallow_clone, bio_data->write_index, bio_data->deep_clone);
    // We only added it to the tree if it was non-empty, so only remove if it's non-empty
    if (bio_data->end_sector - bio_data->start_sector > 0) {
        remove_from_outstanding_ops_and_unblock(bio_data->device, bio_data->shallow_clone);
    }
     // Return to the user. If this is an fsync, wait for replication
    if (!(bio_data->is_fsync && device->f > 0)) {
        ack_bio_to_user_without_executing(bio_data->bio_src);
    }
    // Unlike replica_disk_end_io, the clone is sharing data with the clone used for networking, so we have to check if we can free
    try_free_clones(bio_data);
}

void leader_write_disk_end_io(struct bio *shallow_clone) {
    struct bio_data *bio_data = shallow_clone->bi_private;
    INIT_WORK(&bio_data->submit_bio_work, leader_write_disk_end_io_task);
    queue_work(bio_data->device->leader_write_disk_end_io_queue, &bio_data->submit_bio_work);
}

void replica_disk_end_io_task(struct work_struct *work) {
    struct bio_data *bio_data = container_of(work, struct bio_data, submit_bio_work);
    // printk(KERN_INFO "Replica clone ended, freeing: %d", bio_data->write_index);
    remove_from_outstanding_ops_and_unblock(bio_data->device, bio_data->bio_src);
    // Note: Must do memory tracking before free_bio_data, since that frees bio_data
#ifdef MEMORY_TRACKING
    int queue_size = atomic_dec_return(&bio_data->device->replica_disk_end_io_queue_size);
    atomic_max(&bio_data->device->max_replica_disk_end_io_queue_size, queue_size + 1);
#endif
    free_bio_data(bio_data);
}

void replica_disk_end_io(struct bio *received_bio) {
    struct bio_data *bio_data = received_bio->bi_private;
#ifdef MEMORY_TRACKING
    atomic_inc(&bio_data->device->replica_disk_end_io_queue_size);
#endif
    INIT_WORK(&bio_data->submit_bio_work, replica_disk_end_io_task);
    queue_work(bio_data->device->replica_disk_end_io_queue, &bio_data->submit_bio_work);
}

void network_end_io(struct bio *deep_clone) {
    // See if we can free
    // printk(KERN_INFO "Network broadcast %d completed", ((struct bio_data *)(deep_clone->bi_private))->write_index);
    try_free_clones(deep_clone->bi_private);
}

// Decide which socket to use based on which one is not currently in use
int lock_on_next_free_socket(struct rollbaccine_device *device, struct multisocket *multisocket) {
    int socket_id;
    for (socket_id = 0; socket_id < NUM_NICS; socket_id++) {
        if (mutex_trylock(&multisocket->socket_data[socket_id].socket_mutex)) {
            // Found a socket that isn't currently locked, return
            return socket_id;
        }
    }
    // Just round robin queue on a socket
    socket_id = atomic_inc_return(&device->next_socket_id) % NUM_NICS;
    mutex_lock(&multisocket->socket_data[socket_id].socket_mutex);
    return socket_id;
}

void broadcast_bio(struct work_struct *work) {
    struct bio_data *clone_bio_data = container_of(work, struct bio_data, broadcast_work);
    int socket_id;
    struct bio *clone = clone_bio_data->deep_clone;
    unsigned char *checksum = clone_bio_data->checksum;
    size_t checksum_size = bio_checksum_size(clone_bio_data->end_sector - clone_bio_data->start_sector);
    size_t remaining_checksum_size;
    struct rollbaccine_device *device = clone_bio_data->device;
    struct kvec vec;
    struct multisocket *multisocket;
    struct socket_data *socket_data;
    struct metadata_msg metadata;
    struct additional_hash_msg *additional_hash_msg;
    struct bio_vec bvec, chunked_bvec;
    struct bvec_iter iter;
    bool success, should_disconnect = false;
    cycles_t time = get_cycles_if_flag_on();
    cycles_t total_time = get_cycles_if_flag_on();

    metadata.type = clone_bio_data->is_fsync ? ROLLBACCINE_FSYNC : ROLLBACCINE_WRITE;
    metadata.ballot = atomic_read(&device->ballot);
    metadata.sender_id = device->id;
    metadata.write_index = clone_bio_data->write_index;
    metadata.num_pages = clone->bi_iter.bi_size / PAGE_SIZE;
    metadata.bi_opf = clone->bi_opf;
    metadata.sector = clone->bi_iter.bi_sector;
    // Copy checksum into metadata
    memcpy(metadata.checksum, checksum, min(checksum_size, ROLLBACCINE_METADATA_CHECKSUM_SIZE));

    // printk(KERN_INFO "Broadcasting write with write_index: %llu, is fsync: %d, bi_opf: %llu", metadata.write_index, requires_fsync(clone), metadata.bi_opf);
    WARN_ON(metadata.write_index == 0);  // Should be at least one. Means that bio_data was retrieved incorrectly

    // Note: If bi_size is not a multiple of PAGE_SIZE, we have to send by sector chunks
    WARN_ON(metadata.num_pages * PAGE_SIZE != clone->bi_iter.bi_size);

    // Create message for additional hash if they exceed what could be sent with the metadata
    if (checksum_size > ROLLBACCINE_METADATA_CHECKSUM_SIZE) {
        remaining_checksum_size = checksum_size - ROLLBACCINE_METADATA_CHECKSUM_SIZE;
        additional_hash_msg = alloc_additional_hash_msg(device, remaining_checksum_size);
        additional_hash_msg->sender_id = device->id;
        memcpy(additional_hash_msg->checksum, checksum + ROLLBACCINE_METADATA_CHECKSUM_SIZE, remaining_checksum_size);

#ifdef MEMORY_TRACKING
        atomic_inc(&device->num_messages_larger_than_avg);
#endif
    }

    down_read(&device->connected_sockets_sem);
    list_for_each_entry(multisocket, &device->connected_sockets, list) {
        if (atomic_read(&multisocket->disconnected)) {
            continue;
        }
        socket_id = lock_on_next_free_socket(device, multisocket);
        socket_data = &multisocket->socket_data[socket_id];
        
        metadata.sender_socket_id = socket_id;
        // Send the recipient its own ID so it can check that this message was intended for them
        metadata.recipient_id = multisocket->sender_id;
        // Create a hash of the message after incrementing msg_index
        metadata.msg_index = socket_data->last_sent_msg_index++;
        hash_metadata(socket_data, &metadata);

        vec.iov_base = &metadata;
        vec.iov_len = sizeof(struct metadata_msg);
        print_and_update_latency("broadcast_bio: Set up broadcast message", &time);

        // 1. Send metadata
        success = send_msg(vec, socket_data->sock);
        if (!success) {
            // printk_ratelimited(KERN_ERR "Error broadcasting message header, aborting");
            should_disconnect = true;
            goto finish_sending_to_socket;
        }
        print_and_update_latency("broadcast_bio: Send metadata", &time);

        // 2. Send hash if they exceed what could be sent with the metadata
        if (additional_hash_msg != NULL) {
            additional_hash_msg->sender_socket_id = socket_id;
            additional_hash_msg->recipient_id = multisocket->sender_id;
            additional_hash_msg->msg_index = socket_data->last_sent_msg_index++;
            hash_buffer(socket_data, (char*) additional_hash_msg + SHA256_SIZE, additional_hash_msg_size(remaining_checksum_size) - SHA256_SIZE, additional_hash_msg->msg_hash);

            vec.iov_base = additional_hash_msg;
            vec.iov_len = additional_hash_msg_size(remaining_checksum_size);
            success = send_msg(vec, socket_data->sock);
            if (!success) {
                // printk_ratelimited(KERN_ERR "Error broadcasting additional hash message, aborting");
                should_disconnect = true;
                goto finish_sending_to_socket;
            }
            print_and_update_latency("broadcast_bio: Sent remaining checksums", &time);
        }

        // 3. Send bios
        if (!device->only_replicate_checksums) {
            bio_for_each_segment(bvec, clone, iter) {
                bvec_set_page(&chunked_bvec, bvec.bv_page, bvec.bv_len, bvec.bv_offset);
                success = send_page(chunked_bvec, socket_data->sock);
                if (!success) {
                    // printk_ratelimited(KERN_ERR "Error broadcasting pages, aborting");
                    should_disconnect = true;
                    goto finish_sending_to_socket;
                }
            }
            print_and_update_latency("broadcast_bio: Send pages", &time);
        }
        // Label to jump to if socket cannot be written to, so we can iterate the next socket
finish_sending_to_socket:
        mutex_unlock(&socket_data->socket_mutex);
    }
    up_read(&device->connected_sockets_sem);
    // printk(KERN_INFO "Sent metadata message and bios, sector: %llu, num pages: %llu", metadata.sector, metadata.num_pages);

    if (should_disconnect) {
        // printk_ratelimited(KERN_ERR "Disconnecting from misbehaving replica");
        alert_client_of_liveness_problem(device, multisocket->sender_id);
        disconnect(device, multisocket);
    }
    if (additional_hash_msg != NULL) {
        kfree(additional_hash_msg);
    }
    network_end_io(clone);

    int queue_size = atomic_dec_return(&device->broadcast_queue_size);
    atomic_max(&device->max_broadcast_queue_size, queue_size + 1);

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
    bool is_empty = bio_sectors(bio) == 0;
    int error;
    struct rollbaccine_device *device = ti->private;
    struct bio_data *bio_data;
    struct bio_fsync_list *bio_fsync_data;
    cycles_t time = get_cycles_if_flag_on();
    cycles_t total_time = get_cycles_if_flag_on();

    bio_set_dev(bio, device->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector) + device->disk_pages_for_merkle_tree * SECTORS_PER_PAGE;

    // Big problems if the write is smaller than a page
    if (!is_empty && bio_sectors(bio) < SECTORS_PER_PAGE) {
        printk(KERN_ERR "Write size is smaller than smallest write we can handle: %d", bio_sectors(bio));
        return DM_MAPIO_REMAPPED;
    }

    // Split up bios that are too big
    if (bio->bi_iter.bi_size / PAGE_SIZE > BIO_MAX_VECS) {
        dm_accept_partial_bio(bio, BIO_MAX_VECS * SECTORS_PER_PAGE);
    }

#ifdef MEMORY_TRACKING
    atomic_inc(&device->num_total_ops);
#endif

    // Copy bio if it's a write. Permit non-leaders to read as well for ACE testing; can turn off in production.
    // printk(KERN_INFO "Processing bio %p, is_write: %d, is_leader: %d, sector: %llu", bio, bio_data_dir(bio) == WRITE, device->is_leader, bio->bi_iter.bi_sector);
    if (device->is_leader || bio_data_dir(bio) == READ) {
        is_cloned = true;

        bio_data = alloc_bio_data(device);
        bio_data->device = device;
        bio_data->bio_src = bio;
        bio_data->start_sector = bio->bi_iter.bi_sector;
        bio_data->end_sector = bio->bi_iter.bi_sector + bio_sectors(bio);
        alloc_bio_checksum(device, bio_data);
        bio->bi_private = bio_data;
        
        switch (bio_data_dir(bio)) {
            case WRITE:
                // Don't place writes on queue if it's backed up
                if (atomic_inc_return(&device->broadcast_queue_size) > ROLLBACCINE_MAX_BROADCAST_QUEUE_SIZE) {
                    printk_ratelimited(KERN_ERR "Broadcast queue is full, blocking write");
                    return DM_MAPIO_REMAPPED;
                }

                // Don't allow writes through if ballot != seen_ballot. Wait until it's true
                wait_event_interruptible(device->ballot_mismatch_wait_queue, atomic_read(&device->ballot) == atomic_read(&device->seen_ballot));

                switch (device->sync_mode) {
                    case ROLLBACCINE_DEFAULT:
                        break;
                    case ROLLBACCINE_SYNC:
                        // Add sync flags
                        bio->bi_opf |= REQ_FUA;
                        break;
                    case ROLLBACCINE_ASYNC:
                        // Remove sync flags
                        bio->bi_opf &= ~(REQ_PREFLUSH | REQ_FUA);
                        break;
                }

                bio_data->is_fsync = requires_fsync(bio);
                if (bio_data->is_fsync && device->f > 0) {
                    bio_fsync_data = kmalloc(sizeof(struct bio_fsync_list), GFP_KERNEL);
                    bio_fsync_data->bio_src = bio;
#ifdef MEMORY_TRACKING
                    atomic_inc(&device->num_fsyncs);
#endif
                }

                // Create the network clone
                bio_data->deep_clone = deep_bio_clone(device, bio);
                if (!bio_data->deep_clone) {
                    printk(KERN_ERR "Could not create deep clone");
                    return DM_MAPIO_REMAPPED;
                }

                // Encrypt
                error = enc_or_dec_bio(bio_data, ROLLBACCINE_ENCRYPT);
                if (error != 0) {
                    alert_client_of_liveness_problem(device, device->id);
                    // TODO: System panic
                }
                print_and_update_latency("leader_process_write: encryption", &time);

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
                bio_data->deep_clone->bi_private = bio_data;
                bio_data->shallow_clone->bi_private = bio_data;

                // Increment indices, place ops on queue, submit cloned ops to disk
                mutex_lock(&device->index_lock);
                print_and_update_latency("leader_process_write: encryption -> obtained index lock", &time);
                // Increment write index
                bio_data->write_index = ++device->write_index;
                // Chcek for conflicting writes. If the write is empty, we can skip this
                if (!is_empty) {
                    doesnt_conflict_with_other_writes = try_insert_into_outstanding_ops(device, bio_data, true);
                    if (!doesnt_conflict_with_other_writes) {
                        add_to_pending_ops_tail(device, bio_data);
                    }

                    // Can fetch the merkle nodes regardless of conflict
                    fetch_merkle_nodes(device, bio_data, WRITE);
                }
                // printk(KERN_INFO "Inserted write clone %p, write index: %d, conflicts: %d", bio_data->shallow_clone, bio_data->write_index, !doesnt_conflict_with_other_writes);
                if (bio_data->is_fsync && device->f > 0) {
                    // Add original bio to fsyncs blocked on replication
                    mutex_lock(&device->replica_fsync_lock);
                    print_and_update_latency("leader_process_write: index lock -> obtained replica fsync lock", &time);
                    bio_fsync_data->write_index = bio_data->write_index;
                    list_add_tail(&bio_fsync_data->list, &device->fsyncs_pending_replication);
#ifdef MEMORY_TRACKING
                    device->num_fsyncs_pending_replication += 1;
#endif
                    mutex_unlock(&device->replica_fsync_lock);
                }
                mutex_unlock(&device->index_lock);

                // Even though submit order != write index order, any conflicting writes will only be submitted later so any concurrency here is fine
                if (doesnt_conflict_with_other_writes) {
                    submit_bio_noacct(bio_data->shallow_clone);
                    this_cpu_inc(num_ops_on_cpu);
                    print_and_update_latency("leader_process_write: submit", &time);
                }

                INIT_WORK(&bio_data->broadcast_work, broadcast_bio);
                queue_work(device->broadcast_bio_queue, &bio_data->broadcast_work);
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
                atomic_set(&bio_data->ref_counter, 1);

                // Block read if it conflicts with any other outstanding operations
                mutex_lock(&device->index_lock);
                doesnt_conflict_with_other_writes = try_insert_into_outstanding_ops(device, bio_data, true); // Note: It actually doesn't matter for correctness whether reads check the pending list or not
                if (!doesnt_conflict_with_other_writes) {
                    add_to_pending_ops_tail(device, bio_data);
                }
                // printk(KERN_INFO "Inserted read clone %p, conflicts: %d", bio_data->shallow_clone, !doesnt_conflict_with_other_writes);

                // Can fetch the merkle nodes regardless of conflict
                fetch_merkle_nodes(device, bio_data, READ);
                mutex_unlock(&device->index_lock);

                if (doesnt_conflict_with_other_writes) {
                    submit_bio_noacct(bio_data->shallow_clone);
                }
                break;
        }
    }
    else {
        printk(KERN_ERR "Unexpected operation, we are not the leader (leader = %d) and the bio is a write (write = %d)", device->is_leader, bio_data_dir(bio) == WRITE);
        return DM_MAPIO_KILL;
    }
    print_and_update_latency("rollbaccine_map", &total_time);

    // Anything we clone and submit ourselves is marked submitted
    return is_cloned ? DM_MAPIO_SUBMITTED : DM_MAPIO_REMAPPED;
}

bool verify_msg(struct socket_data *socket_data, char *msg, size_t msg_size, char *expected_hash, uint64_t sender_id, uint64_t sender_socket_id, uint64_t intended_recipient_id, uint64_t my_id, uint64_t msg_index) {
    char calculated_hash[SHA256_SIZE];
    bool hash_matches;
    bool sender_matches;
    bool thread_matches;
    bool i_am_recipient;
    bool msg_index_matches;

    // If another thread is writing on this socket, then they will hash as well
    hash_buffer(socket_data, msg, msg_size, calculated_hash);
    hash_matches = memcmp(calculated_hash, expected_hash, SHA256_SIZE) == 0;
    sender_matches = socket_data->sender_id == sender_id;
    thread_matches = socket_data->sender_socket_id == sender_socket_id;
    i_am_recipient = intended_recipient_id == my_id;
    // This is only correct if no other threads are concurrently modifying waiting_for_msg_index. This is true because only 1 thread listens to each socket (and so only 1 thread verifies messages per socket)
    msg_index_matches = socket_data->waiting_for_msg_index == msg_index;

    if (!hash_matches || !sender_matches || !thread_matches || !i_am_recipient || !msg_index_matches) {
        printk(KERN_ERR "Received incorrect message, expected sender: %llu, sender: %llu, expected thread: %llu, thread: %llu, expected recipient: %llu, I am: %llu, expected msg index: %llu, msg index: %llu", socket_data->sender_id, sender_id, socket_data->sender_socket_id, sender_socket_id, intended_recipient_id, my_id, socket_data->waiting_for_msg_index, msg_index);
        return false;
    }
    // Increment the message index
    socket_data->waiting_for_msg_index++;
    return true;
}

void hash_metadata(struct socket_data *socket_data, struct metadata_msg *metadata) {
    hash_buffer(socket_data, (char *)metadata + SHA256_SIZE, sizeof(struct metadata_msg) - SHA256_SIZE, metadata->msg_hash);
}

// Note: Caller must hold socket_data->socket_mutex on the socket_data that owns the hash_desc
void hash_buffer(struct socket_data *socket_data, char *buffer, size_t len, char *out) {
    cycles_t time = get_cycles_if_flag_on();
    mutex_lock(&socket_data->hash_mutex);
    int ret = crypto_shash_digest(socket_data->hash_desc, buffer, len, out);
    mutex_unlock(&socket_data->hash_mutex);
    if (ret) {
        printk(KERN_ERR "Could not hash buffer");
    }
    print_and_update_latency("hash_buffer", &time);
}

void hash_merkle_page(struct rollbaccine_device *device, struct merkle_bio_data *bio_data) {
    struct shash_desc *hash_desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(device->unsigned_hash_alg), GFP_KERNEL);
    hash_desc->tfm = device->unsigned_hash_alg;

    // Requires page_addr to be mapped
    int ret = crypto_shash_digest(hash_desc, bio_data->page_addr, PAGE_SIZE, bio_data->hash);
    if (ret) {
        printk_ratelimited(KERN_ERR "Could not hash buffer");
    }
    kfree(hash_desc);
}

int enc_or_dec_bio(struct bio_data *bio_data, enum EncDecType enc_or_dec) {
    int ret = 0;
    struct bio *bio;
    struct bio_vec bv;
    uint64_t curr_sector;
    struct aead_request *req;
    struct scatterlist sg[4], sg_verify[4];
    struct page *page_verify;
    DECLARE_CRYPTO_WAIT(wait);
    unsigned char *sector_checksum;
    unsigned char sector_iv[AES_GCM_IV_SIZE];
    cycles_t time = get_cycles_if_flag_on();
    cycles_t total_time = get_cycles_if_flag_on();

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
        case ROLLBACCINE_VERIFY:
            bio = bio_data->bio_src;
            // Allocate a free page to store decrypted data into. We'll discard this page since we're just verifying
            page_verify = page_cache_alloc(bio_data->device);
            if (!page_verify) {
                printk(KERN_ERR "Could not allocate page for verification");
                return 1;
            }
            print_and_update_latency("enc_or_dec_bio: VERIFY page_cache_alloc", &time);
            break;
    }
	
    while (bio->bi_iter.bi_size) {
        // printk(KERN_INFO "enc/dec starting");
        curr_sector = bio->bi_iter.bi_sector;
        bv = bio_iter_iovec(bio, bio->bi_iter);

        sector_checksum = get_bio_checksum(bio_data, curr_sector);
        memcpy(sector_iv, &curr_sector, sizeof(uint64_t));

        switch (enc_or_dec) {
            case ROLLBACCINE_ENCRYPT:
                break;
            case ROLLBACCINE_DECRYPT:
                // Skip decryption for any block that has not been written to
                if (mem_is_zero(sector_checksum, AES_GCM_AUTH_SIZE)) {
                    goto enc_or_dec_next_sector;
                }
                break;
            case ROLLBACCINE_VERIFY:
                sg_init_table(sg_verify, 4);
                sg_set_buf(&sg_verify[0], &curr_sector, sizeof(uint64_t));
                sg_set_buf(&sg_verify[1], sector_iv, AES_GCM_IV_SIZE);
                sg_set_page(&sg_verify[2], page_verify, PAGE_SIZE, bv.bv_offset);
                sg_set_buf(&sg_verify[3], sector_checksum, AES_GCM_AUTH_SIZE);
                break;
        }

        // Lazily allocate the AEAD request, because a lot of reads are over blocks that have not been written to (so they will not pass !has_checksum and won't need to alloc)
        if (req == NULL) {
            req = aead_request_alloc(bio_data->device->tfm, GFP_KERNEL);
            if (!req) {
                printk(KERN_ERR "aead request allocation failed");
                return 1;
            }
            print_and_update_latency("enc_or_dec_bio: aead_request_alloc", &time);
        }

        // Set up scatterlist to encrypt/decrypt
        sg_init_table(sg, 4);
        sg_set_buf(&sg[0], &curr_sector, sizeof(uint64_t));
        sg_set_buf(&sg[1], sector_iv, AES_GCM_IV_SIZE);
        sg_set_page(&sg[2], bv.bv_page, PAGE_SIZE, bv.bv_offset);
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
                aead_request_set_crypt(req, sg, sg, PAGE_SIZE, sector_iv);
                ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
                break;
            case ROLLBACCINE_DECRYPT:
                aead_request_set_crypt(req, sg, sg, PAGE_SIZE + AES_GCM_AUTH_SIZE, sector_iv);
                ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
                break;
            case ROLLBACCINE_VERIFY: // Write output to page and discard
                aead_request_set_crypt(req, sg, sg_verify, PAGE_SIZE + AES_GCM_AUTH_SIZE, sector_iv);
                ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
                break;
        }
        print_and_update_latency("enc_or_dec_bio: crypto_aead_encrypt/decrypt", &time);

        if (ret) {
            if (ret == -EBADMSG) {
                printk_ratelimited(KERN_ERR "%llu invalid integrity check", bio_data->device->id);
            } else {
                printk_ratelimited(KERN_ERR "encryption/decryption failed with error code %d", ret);
            }
            goto free_and_return;
        }

        enc_or_dec_next_sector:
        bio_advance_iter(bio, &bio->bi_iter, PAGE_SIZE);
        reinit_completion(&wait.completion);
    }

    free_and_return:
    aead_request_free(req);
    if (enc_or_dec == ROLLBACCINE_VERIFY) {
        page_cache_free(bio_data->device, page_verify);
    }
    // Reset bio to start after iterating for encryption
    bio->bi_iter.bi_sector = bio_data->start_sector;
    bio->bi_iter.bi_size = (bio_data->end_sector - bio_data->start_sector) * SECTOR_SIZE;
    bio->bi_iter.bi_idx = 0;
    print_and_update_latency("enc_or_dec_bio", &total_time);
    return ret;
}

int submit_pending_bio_ring_prefix(void *args) {
    struct rollbaccine_device *device = args;
    struct bio_data *curr_bio_data;
    struct blk_plug plug; // Used to merge bios
    bool is_empty, no_conflict, should_ack_fsync;
    int signal, curr_head, bios_between_plug;
    cycles_t time = get_cycles_if_flag_on();
    cycles_t total_time = get_cycles_if_flag_on();

    while (!device->shutting_down) {
        // Block until someone indicates there's writes to process
        signal = down_interruptible(&device->replica_submit_bio_sema);
        if (signal == -EINTR && device->shutting_down) {
            break;
        }

        should_ack_fsync = false;
        
        print_and_update_latency("submit_pending_bio_ring_prefix: obtained lock", &time);

        // Store local version of head. Ok since this is the only thread modifying it
        curr_head = atomic_read(&device->pending_bio_ring_head) % ROLLBACCINE_PENDING_BIO_RING_SIZE;
        bios_between_plug = 0;
        blk_start_plug(&plug);
        // Pop as much of the bio prefix off the pending bio ring as possible
        while ((curr_bio_data = (struct bio_data*) atomic_long_xchg(&device->pending_bio_ring[curr_head], 0)) != NULL) {
            is_empty = curr_bio_data->end_sector == curr_bio_data->start_sector;
            mutex_lock(&device->index_lock);  // Necessary to modify outstanding_ops
            // Only check for concurrent writes if it's non-empty
            if (!is_empty) {
                if (!device->only_replicate_checksums) {
                    no_conflict = try_insert_into_outstanding_ops(device, curr_bio_data, true);
                    if (!no_conflict) {
                        add_to_pending_ops_tail(device, curr_bio_data);
                    }
                }

                fetch_merkle_nodes(device, curr_bio_data, WRITE);
            }
            else {
                no_conflict = true;
            }
            // Increment global write index
            device->write_index = curr_bio_data->write_index;
            mutex_unlock(&device->index_lock);
#ifdef MEMORY_TRACKING
            atomic_dec(&device->num_bios_in_pending_bio_ring);
#endif
            // Record if we should ack the fsync
            should_ack_fsync |= curr_bio_data->is_fsync;

            if (!device->only_replicate_checksums) {
                if (no_conflict) {
                    // If the bio is empty, don't submit, just free it
                    if (is_empty)
                        free_bio_data(curr_bio_data);
                    else {
                        submit_bio_noacct(curr_bio_data->bio_src);
                        bios_between_plug++;
                        if (bios_between_plug == ROLLBACCINE_PLUG_NUM_BIOS) {
                            blk_finish_plug(&plug);
                            blk_start_plug(&plug);
                            bios_between_plug = 0;
                        }
                    }
                }
            }
            else {
                free_bio_data(curr_bio_data);
            }

            // Increment index and wrap around if necessary
            curr_head = atomic_inc_return(&device->pending_bio_ring_head) % ROLLBACCINE_PENDING_BIO_RING_SIZE;
            print_and_update_latency("submit_pending_bio_ring_prefix: submitted one bio", &time);
        }
        blk_finish_plug(&plug);

        // Ack the latest fsync
        if (should_ack_fsync) {
            up(&device->replica_ack_fsync_sema);
        }

        print_and_update_latency("submit_pending_bio_ring_prefix", &total_time);
    }

    return 0;
}

int ack_fsync(void *args) {
    struct rollbaccine_device *device = args;
    struct metadata_msg metadata;
    struct kvec vec;
    struct multisocket *multisocket;
    struct socket_data *socket_data;
    int last_sent_fsync, socket_id, signal;
    bool success;

    while (!device->shutting_down) {
        // Block until someone indicates there's an fsync to send
        signal = down_interruptible(&device->replica_ack_fsync_sema);
        if (signal == -EINTR && device->shutting_down) {
            break;
        }

        // Because "up" may be called multiple times on this semaphore, we may be sending too many fsyncs back. Check to see if we've already acknowledged the lastest write
        // This also helps us batch fsyncs
        mutex_lock(&device->index_lock);
        if (last_sent_fsync == device->write_index) {
            mutex_unlock(&device->index_lock);
            continue;
        }
        last_sent_fsync = device->write_index;
        mutex_unlock(&device->index_lock);
#ifdef MEMORY_TRACKING
        device->last_acked_fsync_index = last_sent_fsync;
#endif

        down_read(&device->connected_sockets_sem);
        multisocket = device->counterpart;
        socket_id = lock_on_next_free_socket(device, multisocket);
        socket_data = &multisocket->socket_data[socket_id];

        metadata.type = ROLLBACCINE_ACK;
        metadata.ballot = atomic_read(&device->ballot);
        metadata.sender_id = device->id;
        metadata.sender_socket_id = socket_data->sender_socket_id;
        metadata.recipient_id = multisocket->sender_id;
        metadata.msg_index = socket_data->last_sent_msg_index++;
        metadata.write_index = last_sent_fsync;
        hash_metadata(socket_data, &metadata);

        vec.iov_base = &metadata;
        vec.iov_len = sizeof(struct metadata_msg);

        success = send_msg(vec, socket_data->sock);
        if (!success) {
            printk_ratelimited(KERN_ERR "Error sending fsync ack");
        }
        mutex_unlock(&socket_data->socket_mutex);
        up_read(&device->connected_sockets_sem);
    }

    return 0;
}

bool handle_p1a(struct rollbaccine_device *device, struct multisocket *multisocket, struct metadata_msg p1a) {
    struct metadata_msg p1b;
    struct kvec vec;
    struct socket_data *socket_data;
    int socket_id;
    bool success;

    printk(KERN_INFO "Received P1A, replying with P1B");

    p1b.type = ROLLBACCINE_P1B;
    p1b.ballot = atomic_read(&device->ballot);
    p1b.seen_ballot = atomic_read(&device->seen_ballot);
    p1b.sender_id = device->id;
    p1b.recipient_id = multisocket->sender_id;
    
    mutex_lock(&device->index_lock);
    p1b.write_index = device->write_index;
    mutex_unlock(&device->index_lock);

    vec.iov_base = &p1b;
    vec.iov_len = sizeof(struct metadata_msg);

    down_read(&device->connected_sockets_sem);
    socket_id = lock_on_next_free_socket(device, multisocket);
    socket_data = &multisocket->socket_data[socket_id];
    p1b.sender_socket_id = socket_data->sender_socket_id;
    p1b.msg_index = socket_data->last_sent_msg_index++;
    hash_metadata(socket_data, &p1b);

    success = send_msg(vec, socket_data->sock);
    mutex_unlock(&socket_data->socket_mutex);
    up_read(&device->connected_sockets_sem);
    return success;
}

bool handle_p1b(struct rollbaccine_device *device, struct metadata_msg p1b) {
    struct configuration *config;
    int i, j, num_received_in_conf;
    bool quorum_reached = true;
    struct multisocket *highest_multisocket;
    struct socket_data *highest_socket_data;
    int highest_socket_id;
    struct metadata_msg metadata;
    struct kvec vec;
    bool success;

    printk(KERN_INFO "Received P1B from %llu with ballot %llu and write index %llu", p1b.sender_id, p1b.ballot, p1b.write_index);

    mutex_lock(&device->prior_confs_lock);
    // If we've already reached quorum and requested hashes, then we're done
    if (device->sent_hash_req) {
        mutex_unlock(&device->prior_confs_lock);
        return true;
    }
    // Record the ballot and write index of each node. Also, check if we have quorum
    for (i = 0; i < device->num_prior_confs; i++) {
        config = &device->prior_confs[i];
        num_received_in_conf = 0;

        for (j = 0; j < 2; j++) {
            if (config->ids[j] == p1b.sender_id) {
                config->ballots[j] = p1b.ballot;
                config->write_indices[j] = p1b.write_index;
            }
            if (config->ballots[j] != 0) {
                num_received_in_conf++;

                // Update "highest" values
                if (config->ballots[j] > device->designated_ballot || (config->ballots[j] == device->designated_ballot && config->write_indices[j] > device->designated_write_index)) {
                    device->designated_ballot = config->ballots[j];
                    device->designated_write_index = config->write_indices[j];
                    device->designated_id = config->ids[j];
                }
            }
        }

        if (num_received_in_conf == 0)
            quorum_reached = false; 
    }
    if (quorum_reached) {
        printk(KERN_INFO "Reconfiguration quorum reached, highest ballot: %llu, highest write index: %llu, highest id: %llu", device->designated_ballot, device->designated_write_index, device->designated_id);
        device->sent_hash_req = true;
    }
    mutex_unlock(&device->prior_confs_lock);

    // If we have quorum, request hashes from the most up-to-date node
    if (quorum_reached) {
        printk(KERN_INFO "P1B quorum reached, requesting hashes from the designated node: %llu", device->designated_id);

        metadata.type = ROLLBACCINE_HASH_REQ;
        metadata.seen_ballot = atomic_read(&device->seen_ballot);
        metadata.sender_id = device->id;
        metadata.recipient_id = device->designated_id;

        // Find the multisocket of the designated node
        down_read(&device->connected_sockets_sem);
        list_for_each_entry(highest_multisocket, &device->connected_sockets, list) {
            if (highest_multisocket->sender_id == device->designated_id) {
                device->designated_node = highest_multisocket;
                highest_socket_id = lock_on_next_free_socket(device, highest_multisocket);
                metadata.sender_socket_id = highest_socket_id;
                highest_socket_data = &highest_multisocket->socket_data[highest_socket_id];
                metadata.msg_index = highest_socket_data->last_sent_msg_index++;
                hash_metadata(highest_socket_data, &metadata);

                vec.iov_base = &metadata;
                vec.iov_len = sizeof(struct metadata_msg);

                printk(KERN_INFO "Requesting hashes from %llu", device->designated_id);
                success = send_msg(vec, highest_socket_data->sock);

                mutex_unlock(&highest_socket_data->socket_mutex);
                // Early return
                up_read(&device->connected_sockets_sem);
                return success;
            }
        }
        up_read(&device->connected_sockets_sem);
        printk(KERN_ERR "Could not find the multisocket of the designated node %llu", device->designated_id);
    }
    return true;
}

bool handle_hash_req(struct rollbaccine_device *device, struct multisocket *multisocket) {
    struct metadata_msg metadata;
    struct hash_msg *hash_msg;
    struct kvec vec;
    struct socket_data *socket_data;
    int socket_id;
    sector_t hashes_to_send, num_pages, page = 0;
    bool success;

    hash_msg = kmalloc(sizeof(struct hash_msg), GFP_KERNEL);

    printk(KERN_INFO "Sending HASH_BEGIN message");
    metadata.type = ROLLBACCINE_HASH_BEGIN;
    metadata.seen_ballot = atomic_read(&device->seen_ballot);
    metadata.sender_id = device->id;
    metadata.recipient_id = multisocket->sender_id;

    vec.iov_base = &metadata;
    vec.iov_len = sizeof(struct metadata_msg);

    // Lock the socket and use the same one for all hash messages
    down_read(&device->connected_sockets_sem);
    socket_id = lock_on_next_free_socket(device, multisocket);
    socket_data = &multisocket->socket_data[socket_id];

    metadata.sender_socket_id = socket_data->sender_socket_id;
    metadata.msg_index = socket_data->last_sent_msg_index++;
    hash_metadata(socket_data, &metadata);

    success = send_msg(vec, socket_data->sock);
    if (!success)
        goto unlock_and_return;

    // 2. Send all global hashes and checksums
    hash_msg->seen_ballot = atomic_read(&device->seen_ballot);
    hash_msg->sender_id = device->id;
    hash_msg->sender_socket_id = socket_data->sender_socket_id;
    hash_msg->recipient_id = multisocket->sender_id;

    printk(KERN_INFO "Sending all hashes");
    num_pages = device->num_sectors / SECTORS_PER_PAGE;
    while (page < num_pages) {
        hash_msg->msg_index = socket_data->last_sent_msg_index++;
        hash_msg->start_page = page;

        // Copy hashes into the message
        hashes_to_send = min(num_pages - page, ROLLBACCINE_HASHES_PER_MSG);
        memcpy(hash_msg->checksums, device->merkle_tree_root + page, hashes_to_send * AES_GCM_AUTH_SIZE);
        page += hashes_to_send;
        
        hash_buffer(socket_data, (char *)hash_msg + SHA256_SIZE, sizeof(struct hash_msg) - SHA256_SIZE, hash_msg->msg_hash);

        vec.iov_base = hash_msg;
        vec.iov_len = sizeof(struct hash_msg);
        success = send_msg(vec, socket_data->sock);
        if (!success)
            goto unlock_and_return;
    }
    printk(KERN_INFO "Finished sending hashes for %llu sectors", device->num_sectors);

unlock_and_return:
    mutex_unlock(&socket_data->socket_mutex);
    up_read(&device->connected_sockets_sem);
    kfree(hash_msg);
    return success;
}

bool handle_hash(struct rollbaccine_device *device, struct multisocket *multisocket, struct socket_data *socket_data) {
    struct hash_msg *hash_msg;
    struct kvec vec;
    bool success, about_to_complete = false;
    sector_t hashes_to_copy, num_pages, page;
    struct bio_data *bio_data;
    struct bio *bio;
    struct blk_plug plug;
    int bios_between_plug = 0;

    hash_msg = kmalloc(sizeof(struct hash_msg), GFP_KERNEL);

    // 1. Receive all hash messages
    printk(KERN_INFO "Begin receiving hashes");
    num_pages = device->num_sectors / SECTORS_PER_PAGE;
    while (!about_to_complete) {
        vec.iov_base = hash_msg;
        vec.iov_len = sizeof(struct hash_msg);

        success = receive_msg(vec, socket_data->sock);
        if (!success) {
            printk(KERN_ERR "Error reading hash from socket");
            kfree(hash_msg);
            return false;
        }

        // Verify the message
        if (!verify_msg(socket_data, (char*) hash_msg + SHA256_SIZE, sizeof(struct hash_msg) - SHA256_SIZE, hash_msg->msg_hash, hash_msg->sender_id, hash_msg->sender_socket_id, hash_msg->recipient_id, device->id, hash_msg->msg_index)) {
            kfree(hash_msg);
            return false;
        }

        // Ignore any messages with a ballot lower than our seen_ballot
        if (hash_msg->seen_ballot < atomic_read(&device->seen_ballot)) {
            printk(KERN_ERR "Received hash_msg with lower ballot %llu than seen_ballot %d, ignoring", hash_msg->seen_ballot, atomic_read(&device->seen_ballot));
            kfree(hash_msg);
            return false;
        }

        // Copy hashes into the global checksum
        hashes_to_copy = min(num_pages - hash_msg->start_page, ROLLBACCINE_HASHES_PER_MSG);
        memcpy(device->merkle_tree_root + hash_msg->start_page, hash_msg->checksums, hashes_to_copy * AES_GCM_AUTH_SIZE);
        about_to_complete = hash_msg->start_page + hashes_to_copy >= num_pages - 1;

#ifdef MEMORY_TRACKING
        device->num_hashes_received_during_recovery += hashes_to_copy;
#endif
    }
    kfree(hash_msg);
    printk(KERN_INFO "Finished receiving hashes, beginning disk scan");

    // 2. Scan the disk to verify the hashes
    atomic_set(&device->num_verified_sectors, 0);
    blk_start_plug(&plug);
    for (page = 0; page < num_pages; page++) {
        bio = bio_alloc_bioset(device->dev->bdev, 1, REQ_OP_READ, GFP_NOIO, &device->bs);
        bio->bi_iter.bi_sector = page * SECTORS_PER_PAGE;
        __bio_add_page(bio, page_cache_alloc(device), PAGE_SIZE, 0);
#ifdef MEMORY_TRACKING
        atomic_inc(&device->num_bio_pages_not_freed);
#endif

        bio_data = alloc_bio_data(device);
        bio_data->device = device;
        bio_data->bio_src = bio;
        bio_data->deep_clone = bio;
        bio_data->start_sector = page * SECTORS_PER_PAGE;
        bio_data->end_sector = bio_data->start_sector + SECTORS_PER_PAGE;
        alloc_bio_checksum(device, bio_data);
        bio->bi_private = bio_data;

        bio_data->shallow_clone = shallow_bio_clone(device, bio);
        bio_data->shallow_clone->bi_end_io = verify_disk_end_io;
        bio_data->shallow_clone->bi_private = bio_data;

        submit_bio_noacct(bio_data->shallow_clone);

        bios_between_plug++;
        if (bios_between_plug == ROLLBACCINE_PLUG_NUM_BIOS) {
            blk_finish_plug(&plug);
            blk_start_plug(&plug);
            bios_between_plug = 0;
        }
    }
    blk_finish_plug(&plug);
    printk(KERN_INFO "Finished submitting scans to disk");
    return true;
}

// Function used by all listening sockets to block and listen to messages
// IMPORTANT: The socket_data here can ONLY be used to READ, because we're not locking on it, so its last_sent_msg_index can't be changed
void blocking_read(struct rollbaccine_device *device, struct multisocket *multisocket, struct socket_data *socket_data) {
    struct metadata_msg metadata;
    struct bio *received_bio;
    struct bio_data *bio_data;
    struct page *page;
    struct kvec vec;
    uint64_t msg_ballot;
    bool success;
    int i, error, index_offset, bio_distance, old_seen_ballot;
    size_t checksum_size, remaining_checksum_size;
    struct additional_hash_msg *additional_hash_msg;
    long replaced_bio_data;

    while (!device->shutting_down && !atomic_read(&multisocket->disconnected)) {
        // 1. Receive metadata message
        vec.iov_base = &metadata;
        vec.iov_len = sizeof(struct metadata_msg);

        success = receive_msg(vec, socket_data->sock);
        if (!success) {
            printk(KERN_ERR "Error reading metadata from socket");
            goto disconnect_from_sender;
        }

        // printk(KERN_INFO "Received metadata sector: %llu, num pages: %llu, bi_opf: %llu, is fsync: %llu", metadata.sector, metadata.num_pages, metadata.bi_opf, metadata.bi_opf&(REQ_PREFLUSH |
        // REQ_FUA));

        // Verify the message
        if (!verify_msg(socket_data, (char*) &metadata + SHA256_SIZE, sizeof(struct metadata_msg) - SHA256_SIZE, metadata.msg_hash, metadata.sender_id, metadata.sender_socket_id, metadata.recipient_id, device->id, metadata.msg_index)) {
            goto disconnect_from_sender;
        }

        // Ignore any messages with a ballot lower than our seen_ballot and ALSO update our ballot (with atomic_max)
        msg_ballot = max(metadata.ballot, metadata.seen_ballot);
        old_seen_ballot = atomic_max(&device->seen_ballot, msg_ballot);
        if (msg_ballot < old_seen_ballot) {
            printk(KERN_ERR "Received message with lower ballot %llu than seen_ballot %d, ignoring", msg_ballot, old_seen_ballot);
            goto disconnect_from_sender;
        }

        // Handle fsyncs or non-critical path messages.
        // Note that each case ends with "continue" instead of "break" to avoid critical path processing
        switch (metadata.type) {
            case ROLLBACCINE_WRITE:
            case ROLLBACCINE_FSYNC:
                // Handled by the rest of this method
                break;
            case ROLLBACCINE_ACK:
                if (device->is_leader)
                    process_follower_fsync_index(device, metadata.write_index, metadata.sender_id);
                else
                    printk(KERN_ERR "Backup received fsync ACK");
                continue;
            case ROLLBACCINE_P1A:
                success = handle_p1a(device, multisocket, metadata);
                if (!success)
                    goto disconnect_from_sender;
                continue;
            case ROLLBACCINE_P1B:
                success = handle_p1b(device, metadata);
                if (!success)
                    goto disconnect_from_sender;
                continue;
            case ROLLBACCINE_HASH_REQ:
                success = handle_hash_req(device, multisocket);
                if (!success)
                    goto disconnect_from_sender;
                continue;
            case ROLLBACCINE_HASH_BEGIN:
                success = handle_hash(device, multisocket, socket_data);
                if (!success)
                    goto disconnect_from_sender;
                continue;
            case ROLLBACCINE_DISK_REQ:
                handle_disk_req(device, multisocket, metadata.sector);
                continue;
            case ROLLBACCINE_DISK_BEGIN:
                success = handle_disk_sector(device, socket_data, metadata.sector);
                if (!success)
                    goto disconnect_from_sender;
                continue;
            case ROLLBACCINE_RECONFIG_COMPLETE:
                handle_reconfig_complete(device, multisocket, &metadata);
                continue;
            case ROLLBACCINE_RECONFIG_COMPLETE_ACK:
                begin_critical_path(device);
                continue;
        }

        // Critical path processing
        bio_data = alloc_bio_data(device);
        bio_data->device = device;
        bio_data->write_index = metadata.write_index;
        bio_data->start_sector = metadata.sector;
        bio_data->end_sector = metadata.sector + metadata.num_pages * SECTORS_PER_PAGE;
        bio_data->is_fsync = metadata.type == ROLLBACCINE_FSYNC;
        INIT_WORK(&bio_data->submit_bio_work, submit_bio_task);

        // Copy hash
        checksum_size = bio_checksum_size(metadata.num_pages * SECTORS_PER_PAGE);
        alloc_bio_checksum(device, bio_data);
        memcpy(bio_data->checksum, metadata.checksum, min(ROLLBACCINE_METADATA_CHECKSUM_SIZE, checksum_size));

        // 2. Expect hash if it wasn't done sending
        if (checksum_size > ROLLBACCINE_METADATA_CHECKSUM_SIZE) {
            remaining_checksum_size = checksum_size - ROLLBACCINE_METADATA_CHECKSUM_SIZE;
            additional_hash_msg = alloc_additional_hash_msg(device, remaining_checksum_size);

            vec.iov_base = additional_hash_msg;
            vec.iov_len = additional_hash_msg_size(remaining_checksum_size);

            // printk(KERN_INFO "Receiving checksums, size: %lu", vec.iov_len);
            success = receive_msg(vec, socket_data->sock);
            if (!success) {
                printk(KERN_ERR "Error reading checksum");
                free_bio_data(bio_data);
                kfree(additional_hash_msg);
                goto disconnect_from_sender;
            }

            // Verify the message
            if (!verify_msg(socket_data, (char*) additional_hash_msg + SHA256_SIZE, additional_hash_msg_size(remaining_checksum_size) - SHA256_SIZE, additional_hash_msg->msg_hash, additional_hash_msg->sender_id, additional_hash_msg->sender_socket_id, additional_hash_msg->recipient_id, device->id, additional_hash_msg->msg_index)) {
                free_bio_data(bio_data);
                kfree(additional_hash_msg);
                goto disconnect_from_sender;
            }

            // Copy the checksums over
            memcpy(bio_data->checksum + ROLLBACCINE_METADATA_CHECKSUM_SIZE, additional_hash_msg->checksum, remaining_checksum_size);
            // Free the message
            kfree(additional_hash_msg);

#ifdef MEMORY_TRACKING
            atomic_inc(&device->num_messages_larger_than_avg);
#endif
        }

        if (!device->only_replicate_checksums) {
            // 3. Receive pages of bio (over the regular socket now, not TLS)
            received_bio = bio_alloc_bioset(device->dev->bdev, metadata.num_pages, metadata.bi_opf, GFP_NOIO, &device->bs);
            received_bio->bi_iter.bi_sector = metadata.sector;
            received_bio->bi_end_io = replica_disk_end_io;
            bio_data->bio_src = received_bio;
            bio_data->deep_clone = received_bio;
            received_bio->bi_private = bio_data;

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

                success = receive_msg(vec, socket_data->sock);
                if (!success) {
                    printk(KERN_ERR "Error reading from socket");
                    free_bio_data(bio_data);
                    goto disconnect_from_sender;
                }
                // printk(KERN_INFO "Received bio page: %i", i);
                __bio_add_page(received_bio, page, PAGE_SIZE, 0);
            }

            // 4. Verify against hash
            error = enc_or_dec_bio(bio_data, ROLLBACCINE_VERIFY);
            if (error != 0) {
                printk(KERN_ERR "Backup received invalid page");
                free_bio_data(bio_data);
                alert_client_of_liveness_problem(device, multisocket->sender_id);
                goto disconnect_from_sender;
            }
        }

        // 5. Add bio to pending_bio_ring
        bio_distance = bio_data->write_index - atomic_read(&device->pending_bio_ring_head);
        if (bio_distance > ROLLBACCINE_PENDING_BIO_RING_SIZE) {
            printk(KERN_ERR "Pending bio ring overflowing, bio distance: %d", bio_distance);
            free_bio_data(bio_data);
            alert_client_of_liveness_problem(device, multisocket->sender_id);
            goto disconnect_from_sender;
        }
        // Only place the bio if the previous entry there was already processed
        index_offset = bio_data->write_index % ROLLBACCINE_PENDING_BIO_RING_SIZE;
        replaced_bio_data = atomic_long_cmpxchg(&device->pending_bio_ring[index_offset], 0, (long)bio_data);
        if (replaced_bio_data != 0) {
            printk(KERN_ERR "Pending bio ring overflowing, attempted to replace non-NULL element, bio distance: %d", bio_distance);
            free_bio_data(bio_data);
            alert_client_of_liveness_problem(device, multisocket->sender_id);
            goto disconnect_from_sender;
        }
        // Check bio distance again, this time to see if we should wake up the submit thread
        bio_distance = bio_data->write_index - atomic_read(&device->pending_bio_ring_head);
        if (bio_distance == 0) {
            // Wake up the thread that submits bios
            up(&device->replica_submit_bio_sema);
        }

#ifdef MEMORY_TRACKING
        int num_bios = atomic_inc_return(&device->num_bios_in_pending_bio_ring);
        atomic_max(&device->max_bios_in_pending_bio_ring, num_bios);
        atomic_max(&device->max_distance_between_bios_in_pending_bio_ring, bio_distance);
#endif
    }
    goto cleanup;

disconnect_from_sender:
    printk(KERN_ERR "Disconnecting from sender");
    disconnect(device, multisocket);

cleanup:
    // TODO: Can't release the socket in case another thread calls disconnect and tries to shut down the released socket...
    // sock_release(socket_data->sock);
    // kfree(socket_data->hash_desc);
}

void init_socket_data(struct rollbaccine_device *device, struct socket_data *socket_data, struct socket *sock, uint64_t sender_id, uint64_t sender_socket_id) {
    mutex_init(&socket_data->socket_mutex);
    socket_data->sock = sock;
    socket_data->last_sent_msg_index = 0;
    socket_data->waiting_for_msg_index = 0;
    socket_data->sender_id = sender_id;
    socket_data->sender_socket_id = sender_socket_id;
    mutex_init(&socket_data->hash_mutex);
    socket_data->hash_desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(device->signed_hash_alg), GFP_KERNEL);
    if (socket_data->hash_desc == NULL) {
        printk(KERN_ERR "Error allocating hash desc");
        return;
    }
    socket_data->hash_desc->tfm = device->signed_hash_alg;
}

struct multisocket *create_connected_socket_list_if_null(struct rollbaccine_device *device, uint64_t sender_id) {
    struct multisocket *multisocket;
    int i;

    down_write(&device->connected_sockets_sem);
    list_for_each_entry(multisocket, &device->connected_sockets, list) {
        if (multisocket->sender_id == sender_id) {
            // Already exists, nothing to do
            goto unlock_and_return;
        }
    }

    // Malloc if list doesn't exist
    multisocket = kmalloc(sizeof(struct multisocket), GFP_KERNEL);
    if (!multisocket) {
        printk(KERN_ERR "Error creating multisocket");
        goto unlock_and_return;
    }
    multisocket->sender_id = sender_id;
    mutex_init(&multisocket->sender_socket_ids_lock);
    for (i = 0; i < NUM_NICS; i++) {
        multisocket->sender_socket_id_taken[i] = false;
    }
    atomic_set(&multisocket->disconnected, 0);
    list_add(&multisocket->list, &device->connected_sockets);

unlock_and_return:
    up_write(&device->connected_sockets_sem);
    return multisocket;
}

void send_handshake_id(struct rollbaccine_device *device, struct socket *sock, uint64_t socket_id) {
    struct multithreaded_handshake_pair handshake_pair = {device->id, socket_id};
    struct kvec vec = {
        .iov_base = &handshake_pair,
        .iov_len = sizeof(struct multithreaded_handshake_pair)
    };
    // Keep retrying send until the whole message is sent
    printk(KERN_INFO "Sending handshake ID: %llu, CPU: %llu", device->id, socket_id);
    send_msg(vec, sock);
}

struct multithreaded_handshake_pair receive_handshake_id(struct rollbaccine_device *device, struct socket *sock) {
    struct multithreaded_handshake_pair received_handshake_pair;
    struct kvec vec = {
        .iov_base = &received_handshake_pair,
        .iov_len = sizeof(struct multithreaded_handshake_pair)
    };
    printk(KERN_INFO "Receiving handshake");
    receive_msg(vec, sock);
    printk(KERN_INFO "Handshake complete, talking to ID: %llu, CPU: %llu", received_handshake_pair.sender_id, received_handshake_pair.sender_socket_id);
    return received_handshake_pair;
}

bool add_sender_socket_id_if_unique(struct rollbaccine_device *device, struct multisocket *multisocket, uint64_t socket_id) {
    bool is_unique = true;

    mutex_lock(&multisocket->sender_socket_ids_lock);
    if (socket_id >= NUM_NICS || multisocket->sender_socket_id_taken[socket_id]) {
        is_unique = false;
    } else {
        multisocket->sender_socket_id_taken[socket_id] = true;
    }
    mutex_unlock(&multisocket->sender_socket_ids_lock);
    return is_unique;
}

int connect_to_server(void *args) {
    struct client_thread_params *thread_params = (struct client_thread_params *)args;
    struct rollbaccine_device *device = thread_params->device;
    struct multisocket *multisocket;
    struct socket_data *socket_data;
    struct multithreaded_handshake_pair handshake_pair;
    int error = -1;
    // Reconfiguration messaging
    struct metadata_msg metadata;
    struct kvec vec;

    printk(KERN_INFO "Attempting to connect for the first time");
    while (error != 0 && !device->shutting_down) {
        error = kernel_connect(thread_params->sock, (struct sockaddr *)&thread_params->addr, sizeof(thread_params->addr), 0);
        if (error != 0) {
            printk(KERN_ERR "Error connecting to server");
            goto cleanup;
        }
    }

    if (device->shutting_down) {
        goto cleanup;
    }
    printk(KERN_INFO "Connected to server");
    
    // handshake to get id
    send_handshake_id(device, thread_params->sock, thread_params->socket_id); 
    handshake_pair = receive_handshake_id(device, thread_params->sock);
    if (thread_params->server_id != handshake_pair.sender_id) {
        // Note: Since we don't hash handshakes, a man-in-the-middle attacker could spoof the handshake and pass this test.
        // However, because blocking_read DOES check the hash, the attacker would not be able to send any messages, so this would just be a liveness attack equivalent to dropping messages.
        printk(KERN_ERR "Error: Server ID %llu does not match handshake ID %llu, man-in-the-middle attack", thread_params->server_id, handshake_pair.sender_id);
        goto cleanup;
    }
    multisocket = create_connected_socket_list_if_null(device, handshake_pair.sender_id);
    // Check that each socket has a unique ID
    if (!add_sender_socket_id_if_unique(device, multisocket, handshake_pair.sender_socket_id)) {
        printk(KERN_ERR "Error: Sender thread %llu was reused, replay attack", handshake_pair.sender_socket_id);
        goto cleanup;
    }
    socket_data = &multisocket->socket_data[thread_params->socket_id];
    init_socket_data(device, socket_data, thread_params->sock, handshake_pair.sender_id, handshake_pair.sender_socket_id);

    // Logic only to be executed once per endpoint
    if (thread_params->socket_id == 0) {
        // Set counterpart, if this is the first connection to our counterpart
        if (handshake_pair.sender_id == device->counterpart_id) {
            printk(KERN_INFO "Connected to our counterpart, we are the client");
            device->counterpart = multisocket;
        }
        
        // Send P1a to server
        if (thread_params->send_p1a) {
            metadata.type = ROLLBACCINE_P1A;
            metadata.seen_ballot = atomic_read(&device->seen_ballot);
            metadata.sender_id = device->id;
            metadata.sender_socket_id = thread_params->socket_id;
            metadata.recipient_id = handshake_pair.sender_id;
            metadata.msg_index = socket_data->last_sent_msg_index++;
            hash_metadata(socket_data, &metadata);

            vec.iov_base = &metadata;
            vec.iov_len = sizeof(struct metadata_msg);
            printk(KERN_INFO "Sending P1a to server: %llu", handshake_pair.sender_id);
            send_msg(vec, thread_params->sock);
        }
    }

    blocking_read(device, multisocket, socket_data);

cleanup:
    kfree(thread_params);
    return 0;
}

int start_client_to_server(struct rollbaccine_device *device, uint64_t server_id, char *addr, ushort port, bool send_p1a) {
    struct client_thread_params *thread_params;
    struct task_struct *connect_thread;
    int i, error;

    // We don't currently have logic for recovery for merkle trees where some parts are on disk
    if (send_p1a && (device->merkle_tree_height > 1 || device->f != 1)) {
        printk(KERN_ERR "Unsupported: recovery with merkle tree height %d or f %llu", device->merkle_tree_height, device->f);
        return -1;
    }

    // Start a thread on each CPU
    for (i = 0; i < NUM_NICS; i++) {
        thread_params = kmalloc(sizeof(struct client_thread_params), GFP_KERNEL);
        if (thread_params == NULL) {
            printk(KERN_ERR "Error creating client thread params");
            return -1;
        }
        thread_params->device = device;
        thread_params->server_id = server_id;
        thread_params->socket_id = i;
        thread_params->send_p1a = send_p1a;

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

        // start a thread for this connection
        connect_thread = kthread_run(connect_to_server, thread_params, "connect to server");
        if (IS_ERR(connect_thread)) {
            printk(KERN_ERR "Error creating connect to server thread.");
            return -1;
        }
    }

    return 0;
}

int listen_to_accepted_socket(void *args) {
    struct accepted_thread_params *thread_params = (struct accepted_thread_params *)args;
    
    blocking_read(thread_params->device, thread_params->multisocket, thread_params->socket_data);

    kfree(thread_params);
    return 0;
}

// Thread that listens to connecting clients
int listen_for_connections(void *args) {
    struct rollbaccine_device *device = args;
    struct socket *new_sock;
    struct accepted_thread_params *new_thread_params;
    struct multithreaded_handshake_pair handshake_pair;
    struct task_struct *accepted_thread;
    int error;

    while (!device->shutting_down) {
        // Blocks until a connection is accepted
        error = kernel_accept(device->server_socket, &new_sock, 0);
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
        new_thread_params->device = device;

        // handshake
        // TODO: If the client fails during handshake, this will still create the new multisockets...
        handshake_pair = receive_handshake_id(device, new_sock);
        send_handshake_id(device, new_sock, handshake_pair.sender_socket_id);
        new_thread_params->multisocket = create_connected_socket_list_if_null(device, handshake_pair.sender_id);
        if (!add_sender_socket_id_if_unique(device, new_thread_params->multisocket, handshake_pair.sender_socket_id)) {
            printk(KERN_ERR "Error: Sender thread %llu was reused, replay attack", handshake_pair.sender_socket_id);
            continue;
        }
        // Check if this is our first connection to our counterpart
        if (handshake_pair.sender_socket_id == 0) {
            printk(KERN_INFO "Connected to our counterpart, we are the server");
            if (device->counterpart_id == handshake_pair.sender_id) {
                device->counterpart = new_thread_params->multisocket;
            }
        }
        new_thread_params->socket_data = &new_thread_params->multisocket->socket_data[handshake_pair.sender_socket_id];
        init_socket_data(device, new_thread_params->socket_data, new_sock, handshake_pair.sender_id, handshake_pair.sender_socket_id);

        accepted_thread = kthread_run(listen_to_accepted_socket, new_thread_params, "listen to accepted socket");
        if (IS_ERR(accepted_thread)) {
            printk(KERN_ERR "Error creating accepted thread.");
            break;
        }
    }

    kernel_sock_shutdown(device->server_socket, SHUT_RDWR);
    // TODO: Releasing the socket is problematic because it makes future calls to shutdown() crash, which may happen if the connection dies, the socket is freed, and later the destructor tries to shut
    // it down.
    //     sock_release(thread_params->sock);
    return 0;
}

// Returns error code if it fails
int start_server(struct rollbaccine_device *device, ushort port) {
    struct sockaddr_in addr;
    struct task_struct *listener_thread;
    int error;
    int opt = 1;
    sockptr_t kopt = {.kernel = (char *)&opt, .is_kernel = 1};

    error = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &device->server_socket);
    if (error < 0) {
        printk(KERN_ERR "Error creating server socket");
        return error;
    }

    // TCP nodelay
    error = device->server_socket->ops->setsockopt(device->server_socket, SOL_TCP, TCP_NODELAY, kopt, sizeof(opt));
    if (error < 0) {
        printk(KERN_ERR "Error setting TCP_NODELAY");
        return error;
    }

    error = sock_setsockopt(device->server_socket, SOL_SOCKET, SO_REUSEPORT, kopt, sizeof(opt));
    if (error < 0) {
        printk(KERN_ERR "Error setting SO_REUSEPORT");
        return error;
    }

    // Set sockaddr_in
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    error = kernel_bind(device->server_socket, (struct sockaddr *)&addr, sizeof(addr));
    if (error < 0) {
        printk(KERN_ERR "Error binding socket");
        return error;
    }

    error = kernel_listen(device->server_socket, ROLLBACCINE_MAX_CONNECTIONS);
    if (error < 0) {
        printk(KERN_ERR "Error listening on socket");
        return error;
    }

    // Listen for connections
    listener_thread = kthread_run(listen_for_connections, device, "listener");
    if (IS_ERR(listener_thread)) {
        printk(KERN_ERR "Error creating listener thread");
        return -1;
    }

    return 0;
}

static void rollbaccine_io_hints(struct dm_target *ti, struct queue_limits *limits) {
    limits->logical_block_size = max_t(unsigned int, limits->logical_block_size, PAGE_SIZE);
    limits->physical_block_size = max_t(unsigned int, limits->physical_block_size, PAGE_SIZE);
    limits->io_min = max_t(unsigned int, limits->io_min, PAGE_SIZE);
    limits->dma_alignment = limits->logical_block_size - 1;
}

static void rollbaccine_status(struct dm_target *ti, status_type_t type, unsigned int status_flags, char *result, unsigned int maxlen) {
    struct rollbaccine_device *device = ti->private;
    unsigned int sz = 0;  // Required by DMEMIT
    int cpu_id;

    DMEMIT("\n");

    DMEMIT("Latest write index: %d\n", device->write_index);
#ifndef MEMORY_TRACKING
    DMEMIT("Memory tracking is NOT ON! The following statistics will be unreliable.\n");
#endif
    DMEMIT("ballot %d, seen_ballot: %d\n", atomic_read(&device->ballot), atomic_read(&device->seen_ballot));
    DMEMIT("Num pages requested during recovery: %d\n", atomic_read(&device->num_pages_requested_during_recovery));
    DMEMIT("Num pages received during recovery: %d\n", atomic_read(&device->num_pages_received_during_recovery));
    DMEMIT("Hashes received during recovery: %d, total sectors: %llu\n", device->num_hashes_received_during_recovery, device->num_sectors);
    DMEMIT("Num total operations: %d\n", atomic_read(&device->num_total_ops));
    DMEMIT("Num fsyncs: %d\n", atomic_read(&device->num_fsyncs));
    DMEMIT("Num bio pages not freed: %d\n", atomic_read(&device->num_bio_pages_not_freed));
    DMEMIT("Num bio_data not freed: %d\n", atomic_read(&device->num_bio_data_not_freed));
    DMEMIT("Num deep clones not freed: %d\n", atomic_read(&device->num_deep_clones_not_freed));
    DMEMIT("Num shallow clones not freed: %d\n", atomic_read(&device->num_shallow_clones_not_freed));
    DMEMIT("Num rb nodes still in tree: %d\n", device->num_rb_nodes);
    DMEMIT("Num bio sectors still in queue: %d\n", device->num_bio_sector_ranges);
    DMEMIT("Num fsyncs still pending replication: %d\n", device->num_fsyncs_pending_replication);
    DMEMIT("Num checksums not freed: %d\n", atomic_read(&device->num_checksums));
    DMEMIT("Num times broadcast queue blocked on sockets in use: %d\n", atomic_read(&device->next_socket_id));
    DMEMIT("Num bios on submit queue: %d\n", atomic_read(&device->submit_bio_queue_size));
    if (!device->is_leader) {
        DMEMIT("Num bios still in pending bio ring: %d\n", atomic_read(&device->num_bios_in_pending_bio_ring));
        DMEMIT("Num bios on replica disk end io queue: %d\n", atomic_read(&device->replica_disk_end_io_queue_size));
    }
    else {
        DMEMIT("Num bios on broadcast queue: %d\n", atomic_read(&device->broadcast_queue_size));
    }
    DMEMIT("Num messages larger than average: %d\n", atomic_read(&device->num_messages_larger_than_avg));
    DMEMIT("Max outstanding num bio pages: %d\n", atomic_read(&device->max_outstanding_num_bio_pages));
    DMEMIT("Max outstanding num bio_data: %d\n", atomic_read(&device->max_outstanding_num_bio_data));
    DMEMIT("Max outstanding num deep clones: %d\n", atomic_read(&device->max_outstanding_num_deep_clones));
    DMEMIT("Max outstanding num shallow clones: %d\n", atomic_read(&device->max_outstanding_num_shallow_clones));
    DMEMIT("Max size of rb tree for outgoing operations: %d\n", device->max_outstanding_num_rb_nodes);
    DMEMIT("Max number of conflicting operations: %d\n", device->max_outstanding_num_bio_sector_ranges);
    DMEMIT("Max number of fsyncs pending replication: %d\n", device->max_outstanding_fsyncs_pending_replication);
    DMEMIT("Max bios on submit queue: %d\n", atomic_read(&device->max_submit_bio_queue_size));
    DMEMIT("Last ACK'd fsync index: %d\n", device->last_acked_fsync_index);
    if (!device->is_leader) {
        DMEMIT("Max bios in pending bio ring: %d\n", atomic_read(&device->max_bios_in_pending_bio_ring));
        DMEMIT("Max distance between bios in pending bio ring: %d\n", atomic_read(&device->max_distance_between_bios_in_pending_bio_ring));
        DMEMIT("Max bios on replica disk end io queue: %d\n", atomic_read(&device->max_replica_disk_end_io_queue_size));
    }
    else {
        DMEMIT("Max bios on broadcast queue: %d\n", atomic_read(&device->max_broadcast_queue_size));
    }

    for_each_online_cpu(cpu_id) {
        DMEMIT("Number of operations on CPU %d: %d\n", cpu_id, per_cpu(num_ops_on_cpu, cpu_id));
    }
}

/**
 * Arguments:
 * 0 = underlying device name, like /dev/ram0
 * 1 = id (unique per instance, starts at 1)
 * 2 = seen_ballot
 * 3 = is_leader ("true" or "false")
 * 4 = key
 * 5 = f (can be 0 to verify reads only)
 * 6 = Disk pages for merkle tree
 * 7 = sync mode ("default", "sync", "async"). "Default" respects FUA/PREFLUSH flags, "sync" forces all writes to be FUA, "async" removes all write flags.
 * 8 = listen port
 * 9 = only_replicate_checksums ("true" or "false")
 * 10 = is_recovering ("true" or "false")
 * 11 = counterpart id (ID of other node in current config, assuming f=1. If f>1, then the primary's recovery logic won't work.)
 * 
 * The remaining arguments are used for backups or during recovery:
 * 12 = server addr
 * 13 = server port
 * 14 ... (additional server id, addr, port)
 */
static int rollbaccine_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    struct rollbaccine_device *device;
    ushort port, primary_port;
    uint64_t id, seen_ballot;
    int error, conf_arg_start, num_conf_args, conf_index, i, earlier_conf_index, j;
    bool is_recovering, should_not_connect_twice;

    device = kzalloc(sizeof(struct rollbaccine_device), GFP_KERNEL);
    if (device == NULL) {
        printk(KERN_ERR "Error creating device");
        return -ENOMEM;
    }

    bioset_init(&device->bs, 0, 0, BIOSET_NEED_BVECS);
    device->bio_data_cache = kmem_cache_create("bio_data", sizeof(struct bio_data), 0, 0, NULL);
    mutex_init(&device->page_cache_lock);
    device->page_cache = NULL;
    device->page_cache_size = 0;

    device->shutting_down = false;
    init_rwsem(&device->connected_sockets_sem);
    atomic_set(&device->next_socket_id, 0);

    init_waitqueue_head(&device->ballot_mismatch_wait_queue);

    device->broadcast_bio_queue = alloc_workqueue("broadcast bio queue", 0, NUM_NICS);
    if (!device->broadcast_bio_queue) {
        printk(KERN_ERR "Cannot allocate broadcast bio queue");
        return -ENOMEM;
    }

    device->submit_bio_queue = alloc_workqueue("submit bio queue", 0, 0);
    if (!device->submit_bio_queue) {
        printk(KERN_ERR "Cannot allocate submit bio queue");
        return -ENOMEM;
    }

    device->leader_write_disk_end_io_queue = alloc_workqueue("leader write disk end io queue", 0, 0);
    if (!device->leader_write_disk_end_io_queue) {
        printk(KERN_ERR "Cannot allocate leader write disk end io queue");
        return -ENOMEM;
    }

    device->leader_read_disk_end_io_queue = alloc_workqueue("leader read disk end io queue", 0, 0);
    if (!device->leader_read_disk_end_io_queue) {
        printk(KERN_ERR "Cannot allocate leader read disk end io queue");
        return -ENOMEM;
    }

    device->replica_disk_end_io_queue = alloc_workqueue("replica disk end io queue", 0, 0);
    if (!device->replica_disk_end_io_queue) {
        printk(KERN_ERR "Cannot allocate replica disk end io queue");
        return -ENOMEM;
    }

    device->replica_insert_bio_queue = alloc_workqueue("replica insert bio queue", 0, 0);
    if (!device->replica_insert_bio_queue) {
        printk(KERN_ERR "Cannot allocate replica insert bio queue");
        return -ENOMEM;
    }

    device->verify_disk_end_io_queue = alloc_workqueue("verify disk end io queue", 0, 0);
    if (!device->verify_disk_end_io_queue) {
        printk(KERN_ERR "Cannot allocate verify disk end io queue");
        return -ENOMEM;
    }

    device->fetch_disk_end_io_queue = alloc_workqueue("fetch disk end io queue", 0, 0);
    if (!device->fetch_disk_end_io_queue) {
        printk(KERN_ERR "Cannot allocate fetch disk end io queue");
        return -ENOMEM;
    }

    device->reconfig_write_disk_end_io_queue = alloc_workqueue("reconfig write disk end io queue", 0, 0);
    if (!device->reconfig_write_disk_end_io_queue) {
        printk(KERN_ERR "Cannot allocate reconfig write disk end io queue");
        return -ENOMEM;
    }

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
        printk(KERN_ERR "Error getting device");
        return -ENOMEM;
    }

    error = kstrtou64(argv[1], 10, &device->id);
    if (error < 0) {
        printk(KERN_ERR "Error parsing id");
        return error;
    }
    printk(KERN_INFO "id: %llu", device->id);

    error = kstrtou64(argv[2], 10, &seen_ballot);
    if (error < 0) {
        printk(KERN_ERR "Error parsing seen ballot");
        return error;
    }
    printk(KERN_INFO "seen ballot: %llu", seen_ballot);
    atomic_set(&device->seen_ballot, seen_ballot);

    device->write_index = ROLLBACCINE_INIT_WRITE_INDEX;
    mutex_init(&device->index_lock);

    device->pending_bio_ring = vzalloc(sizeof(atomic_long_t) * ROLLBACCINE_PENDING_BIO_RING_SIZE);
    if (!device->pending_bio_ring) {
        printk(KERN_ERR "Error allocating pending_bio_ring");
        return -ENOMEM;
    }
    atomic_set(&device->pending_bio_ring_head, ROLLBACCINE_INIT_WRITE_INDEX + 1);

    mutex_init(&device->replica_fsync_lock);
    INIT_LIST_HEAD(&device->fsyncs_pending_replication);

    device->outstanding_ops = RB_ROOT;
    INIT_LIST_HEAD(&device->pending_ops);

    device->is_leader = strcmp(argv[3], "true") == 0;
    printk(KERN_INFO "is_leader: %d", device->is_leader);

    if (!device->is_leader) {
        sema_init(&device->replica_submit_bio_sema, 0);
        sema_init(&device->replica_ack_fsync_sema, 0);
        device->replica_submit_bio_thread = kthread_run(submit_pending_bio_ring_prefix, device, "submit pending bio ring");
        device->replica_ack_fsync_thread = kthread_run(ack_fsync, device, "ack fsync");
    }

    // Set up hashing
    device->signed_hash_alg = crypto_alloc_shash("hmac(sha256)", 0, 0);
    crypto_shash_setkey(device->signed_hash_alg, argv[4], KEY_SIZE);
    if (IS_ERR(device->signed_hash_alg)) {
        printk(KERN_ERR "Error allocating hmac(sha256) hash");
        return PTR_ERR(device->signed_hash_alg);
    }

    device->unsigned_hash_alg = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(device->unsigned_hash_alg)) {
        printk(KERN_ERR "Error allocating sha256 hash");
        return PTR_ERR(device->unsigned_hash_alg);
    }

    // Set up AEAD
    device->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(device->tfm)) {
        printk(KERN_ERR "Error allocating AEAD");
        return PTR_ERR(device->tfm);
    }
    crypto_aead_setauthsize(device->tfm, AES_GCM_AUTH_SIZE);

    error = crypto_aead_setkey(device->tfm, argv[4], KEY_SIZE);
    if (error < 0) {
        printk(KERN_ERR "Error setting key");
        return error;
    }

    // Get f
    error = kstrtou64(argv[5], 10, &device->f);
    if (error < 0) {
        printk(KERN_ERR "Error parsing f");
        return error;
    }
    printk(KERN_INFO "f: %llu", device->f);
    if (device->is_leader) {
        // Note: Don't need to alloc f+1, since we're always the 1
        device->fsync_index_list = kzalloc(sizeof(struct fsync_index_list) * device->f, GFP_KERNEL);
        if (!device->fsync_index_list) {
            printk(KERN_ERR "Error allocating fsync_index_list");
            return -ENOMEM;
        }

        // Set server IDs to -1 to signal that the slot is empty
        for (i = 0; i < device->f; i++)
            device->fsync_index_list[i].server_id = -1;
    }

    // Set up merkle tree of hashes
    device->num_sectors = ti->len;
    error = kstrtou64(argv[6], 10, &device->disk_pages_for_merkle_tree);
    if (error < 0) {
        printk(KERN_ERR "Error parsing disk_pages_for_merkle_tree");
        return error;
    }

    mutex_init(&device->merkle_tree_lock);
    init_merkle_tree(device);

    // Configure sync mode
    if (strcmp(argv[7], "default") == 0) {
        device->sync_mode = ROLLBACCINE_DEFAULT;
    } else if (strcmp(argv[7], "sync") == 0) {
        device->sync_mode = ROLLBACCINE_SYNC;
    } else if (strcmp(argv[7], "async") == 0) {
        device->sync_mode = ROLLBACCINE_ASYNC;
    } else {
        printk(KERN_ERR "Error parsing sync mode");
        return -EINVAL;
    }
    printk(KERN_INFO "sync mode: %d", device->sync_mode);

    // Start server
    error = kstrtou16(argv[8], 10, &port);
    if (error < 0) {
        printk(KERN_ERR "Error parsing port");
        return error;
    }
    printk(KERN_INFO "Starting server at port: %u", port);

    INIT_LIST_HEAD(&device->connected_sockets);
    error = start_server(device, port);
    if (error < 0) {
        printk(KERN_ERR "Error starting server");
        return error;
    }

    device->only_replicate_checksums = strcmp(argv[9], "true") == 0;
    printk(KERN_INFO "only_replicate_checksums: %d", device->only_replicate_checksums);
    is_recovering = strcmp(argv[10], "true") == 0;

    error = kstrtou64(argv[11], 10, &device->counterpart_id);
    if (error < 0) {
        printk(KERN_ERR "Error parsing counterpart_id");
        return error;
    }
    
    if (!device->is_leader || is_recovering) {
        conf_arg_start = 14;
    }
    else {
        conf_arg_start = 12;
    }

    mutex_init(&device->prior_confs_lock);
    mutex_init(&device->reconfig_complete_lock);

    if (!is_recovering) {
        printk(KERN_INFO "Not recovering, can start execution");
        atomic_set(&device->ballot, seen_ballot);
    }
    // Connect to machines in prior configs if they are provided
    else {
        if (device->f > 1) {
            printk(KERN_ERR "Error: Cannot recover with f > 1");
            return -EINVAL;
        }

        mutex_lock(&device->prior_confs_lock);
        device->num_prior_confs = (argc - conf_arg_start) / 6;
        device->prior_confs = kzalloc(sizeof(struct configuration) * device->num_prior_confs, GFP_KERNEL);
        printk(KERN_INFO "Num prior confs: %d", device->num_prior_confs);

        for (conf_index = 0; conf_index < device->num_prior_confs; conf_index++) {
            for (i = 0; i < 2; i++) {
                error = kstrtou64(argv[conf_arg_start + i * 3 + conf_index * num_conf_args], 10, &id);
                if (error < 0) {
                    printk(KERN_ERR "Error parsing server id");
                    return error;
                }

                // Check if we were already going to connect to this node, or this is ourself
                should_not_connect_twice = false;
                if (id == device->counterpart_id || id == device->id) {
                    should_not_connect_twice = true;
                    goto earlier_confs_checked;
                }
                for (earlier_conf_index = 0; earlier_conf_index <= conf_index; earlier_conf_index++) {
                    for (j = 0; j < 2; j++) {
                        if (device->prior_confs[earlier_conf_index].ids[j] == id) {
                            should_not_connect_twice = true;
                            goto earlier_confs_checked;
                        }
                    }
                }

            earlier_confs_checked:
                device->prior_confs[conf_index].ids[i] = id;
                if (should_not_connect_twice) {
                    printk(KERN_INFO "Not connecting to server %llu in conf %d because we already did", id, conf_index);
                    continue;
                }

                // Otherwise, connect
                error = kstrtou16(argv[conf_arg_start + 2 + i * 3 + conf_index * num_conf_args], 10, &port);
                if (error < 0) {
                    printk(KERN_ERR "Error parsing port");
                    return error;
                }
                printk(KERN_INFO "Starting thread to connect to server %llu at %s:%u in conf %d", device->prior_confs[conf_index].ids[i], argv[conf_arg_start + 1 + i * 3 + conf_index * num_conf_args], port, conf_index);
                start_client_to_server(device, device->prior_confs[conf_index].ids[i], argv[conf_arg_start + 1 + i * 3 + conf_index * num_conf_args], port, true);
            }
        }
        mutex_unlock(&device->prior_confs_lock);
    }

    if (!device->is_leader || is_recovering) {
        error = kstrtou16(argv[13], 10, &primary_port);
        if (error < 0) {
            printk(KERN_ERR "Error parsing counterpart port");
            return error;
        }
        printk(KERN_INFO "Starting thread to connect to primary %llu at %s:%u", device->counterpart_id, argv[12], primary_port);
        start_client_to_server(device, device->counterpart_id, argv[12], primary_port, is_recovering);
    }

#ifdef MEMORY_TRACKING
    atomic_set(&device->num_bio_data_not_freed, 0);
    atomic_set(&device->num_bio_pages_not_freed, 0);
    atomic_set(&device->num_deep_clones_not_freed, 0);
    atomic_set(&device->num_shallow_clones_not_freed, 0);
    device->num_rb_nodes = 0;
    device->num_bio_sector_ranges = 0;
    device->num_fsyncs_pending_replication = 0;
    atomic_set(&device->num_checksums, 0);
    atomic_set(&device->num_bios_in_pending_bio_ring, 0);
    atomic_set(&device->submit_bio_queue_size, 0);
    atomic_set(&device->replica_disk_end_io_queue_size, 0);
    atomic_set(&device->num_messages_larger_than_avg, 0);
    atomic_set(&device->max_outstanding_num_bio_data, 0);
    atomic_set(&device->max_outstanding_num_bio_pages, 0);
    atomic_set(&device->max_outstanding_num_deep_clones, 0);
    atomic_set(&device->max_outstanding_num_shallow_clones, 0);
    device->max_outstanding_num_rb_nodes = 0;
    device->max_outstanding_num_bio_sector_ranges = 0;
    device->max_outstanding_fsyncs_pending_replication = 0;
    atomic_set(&device->max_bios_in_pending_bio_ring, 0);
    atomic_set(&device->max_distance_between_bios_in_pending_bio_ring, 0);
    atomic_set(&device->max_submit_bio_queue_size, 0);
    atomic_set(&device->max_replica_disk_end_io_queue_size, 0);
    device->last_acked_fsync_index = 0;
#endif

    atomic_set(&device->broadcast_queue_size, 0);
    atomic_set(&device->max_broadcast_queue_size, 0);

    // Enable FUA and PREFLUSH flags
    ti->num_flush_bios = 1;
    ti->flush_supported = 1;

    ti->private = device;

    printk(KERN_INFO "Server %llu constructed", device->id);
    return 0;
}

static void rollbaccine_destructor(struct dm_target *ti) {
    struct multisocket *curr_multi, *next_multi;
    struct rollbaccine_device *device = ti->private;
    if (device == NULL) return;

    // Warning: Changing this boolean should technically be atomic. I don't think it's a big deal tho, since by the time shutting_down is true, we don't care what the protocol does. *Ideally* it shuts
    // down gracefully.
    device->shutting_down = true;

    // Kill threads
    if (!device->is_leader) {
        printk(KERN_INFO "Killing replica threads that are blocking on semaphores");
        send_sig(SIGTERM, device->replica_submit_bio_thread, 1);
        send_sig(SIGTERM, device->replica_ack_fsync_thread, 1);
    }

    printk(KERN_INFO "Killing server socket");
    kernel_sock_shutdown(device->server_socket, SHUT_RDWR);

    printk(KERN_INFO "Killing connections to other nodes");
    list_for_each_entry_safe(curr_multi, next_multi, &device->connected_sockets, list) {
        disconnect(device, curr_multi);
    }

    printk(KERN_INFO "Freeing remaining structures");
    kvfree(device->merkle_tree_root);
    crypto_free_aead(device->tfm);
    crypto_free_shash(device->signed_hash_alg);
    // Note: I'm not sure how to free theses queues which may have outstanding bios. Hopefully nothing breaks horribly
    destroy_workqueue(device->submit_bio_queue);
    destroy_workqueue(device->leader_write_disk_end_io_queue);
    destroy_workqueue(device->leader_read_disk_end_io_queue);
    destroy_workqueue(device->replica_disk_end_io_queue);
    destroy_workqueue(device->replica_insert_bio_queue);
    destroy_workqueue(device->verify_disk_end_io_queue);
    destroy_workqueue(device->fetch_disk_end_io_queue);
    destroy_workqueue(device->reconfig_write_disk_end_io_queue);
    destroy_workqueue(device->read_hash_end_io_queue);
    destroy_workqueue(device->write_hash_end_io_queue);
    dm_put_device(ti, device->dev);
    bioset_exit(&device->bs);
    kmem_cache_destroy(device->bio_data_cache);
    page_cache_destroy(device);
    if (device->prior_confs != NULL)
        kfree(device->prior_confs);
    // TODO: Don't free because threads may be attempting to acquire global locks still. Could theoretically gather all threads and wait for them
    // kfree(device);

    printk(KERN_INFO "Server destructed");
}

static struct target_type rollbaccine_target = {
    .name = MODULE_NAME,
    .version = {0, 1, 0},
    .module = THIS_MODULE,
    .ctr = rollbaccine_constructor,
    .dtr = rollbaccine_destructor,
    .map = rollbaccine_map,
    .status = rollbaccine_status,
    .io_hints = rollbaccine_io_hints,
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