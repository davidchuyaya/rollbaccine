#include <linux/module.h> /* Needed by all modules */
#include <linux/init.h>   /* Needed for the macros */
#include <linux/printk.h> /* Needed for pr_info() */
#include <linux/device-mapper.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h> /* SHA-256 Hash*/
#include <linux/bio.h>
#include <linux/scatterlist.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#include <linux/random.h>
#include <crypto/skcipher.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/if_alg.h>
#include <crypto/drbg.h>

#define DM_MSG_PREFIX "encryption"

#define SHA256_LENGTH 256
#define AES_GCM_IV_SIZE 12
#define AES_GCM_AUTH_SIZE 16
#define KEY_SIZE 16

#define RAM_SIZE_GB 1
#define TOTAL_RAM_BYTES 10240
#define TOTAL_SECTORS (TOTAL_RAM_BYTES / SECTOR_SIZE)
#define TOTAL_HASH_MEMORY (TOTAL_SECTORS * AES_GCM_AUTH_SIZE)

#define MIN_IOS 64


// Data attached to each bio
struct encryption_device
{
    struct dm_dev *dev;
    // symmetric key algorithm instance
    struct crypto_aead *tfm;
    // persist key
    char *key;
    // not sure what this is, but it's needed to create a clone of the bio
    struct bio_set bs;
    // list containing mappings from sector to mac
    struct list_head encryption_metadata_list;
    // lock for list
    struct mutex lock;
    // array of hashes of each sector
    char checksums[TOTAL_HASH_MEMORY];

};

// per bio private data
typedef struct encryption_io
{
    // maintain information of original bio before iteration
    struct bio *base_bio;
    // needed for iteration
    struct bio *bio_in;
    struct bvec_iter bi_iter;
    uint64_t sector;
    struct crypto_wait wait;
    struct encryption_device *rbd;

    blk_status_t error;

} convert_context;

// node to maintain encrypted sector and corresponding mac
struct encryption_metadata
{
    struct list_head list;
    uint64_t sector;
    char mac[AES_GCM_AUTH_SIZE];
};

void cleanup(struct encryption_device *rbd)
{
    if (rbd == NULL)
        return;
    if (rbd->tfm)
        crypto_free_aead(rbd->tfm);
    bioset_exit(&rbd->bs);
    kfree(rbd);
}

static void encryption_destructor(struct dm_target *ti)
{
    struct encryption_device *rbd = ti->private;
    printk(KERN_INFO "encryption destructor called\n");
    if (rbd == NULL)
        return;
    dm_put_device(ti, rbd->dev);
    cleanup(rbd);
}

static int encryption_constructor(struct dm_target *ti, unsigned int argc, char **argv)
{
    int ret;
    struct encryption_device *rbd;
    printk(KERN_INFO "encryption constructor called\n");

    // TODO: look into vzalloc
    rbd = kmalloc(sizeof(struct encryption_device), GFP_KERNEL);
    if (rbd == NULL)
    {
        ti->error = "Cannot allocate context";
        ret = -ENOMEM;
        goto out;
    }

    // Check the allocation of the large checksums array
    printk(KERN_INFO "Allocated memory for encryption_device: %zu bytes\n", sizeof(struct encryption_device));


    // Get the device from argv[0] and store it in rbd->dev
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &rbd->dev))
    {
        ti->error = "Device lookup failed";
        ret = -EINVAL;
        goto out;
    }

    // TODO: Change flag to CRYPTO_ALG_ASYNC to only allow for synchronous calls and find out what CRYPTO_ALG_ALLOCATES_MEMORY does
    rbd->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(rbd->tfm))
    {
        ti->error = "Cannot allocate transform";
        ret = -ENOMEM;
        goto out;
    }
    printk(KERN_INFO "transform properly initialized\n");

    // tag size
    crypto_aead_setauthsize(rbd->tfm, AES_GCM_AUTH_SIZE);

    rbd->key = "1234567890123456";
    if (crypto_aead_setkey(rbd->tfm, rbd->key, KEY_SIZE))
    {
        ti->error = "Key could not be set";
        ret = -EAGAIN;
        goto out;
    }
    printk(KERN_INFO "key properly initialized\n");

    bioset_init(&rbd->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);

    // initialize list
    // INIT_LIST_HEAD(&rbd->encryption_metadata_list);

    // initialize lock
    // mutex_init(&rbd->lock);

    // zero out checksums
    //memset(rbd->checksums, 0, TOTAL_HASH_MEMORY);


    // TODO: Look into putting hashes inside of here too and some rounding?
    ti->per_io_data_size = sizeof(struct encryption_io);
    ti->private = rbd;

    return 0;

out:
    cleanup(rbd);
    return ret;
}

static struct encryption_metadata *get_entry(struct list_head *head, uint64_t sector)
{
    struct encryption_metadata *curr_entry;
    struct list_head *ptr;
    for (ptr = head->next; ptr != head; ptr = ptr->next)
    {
        curr_entry = list_entry(ptr, struct encryption_metadata, list);
        if (sector == curr_entry->sector)
        {
            return curr_entry;
        }
    }
    return NULL;
}

static inline unsigned char *checksum_index(struct encryption_io *io, sector_t index) {
    return &io->rbd->checksums[index * AES_GCM_AUTH_SIZE];
}


static int enc_or_dec_bio(struct encryption_io *io, int enc_or_dec)
{
    int ret;
    struct bio_vec bv;
    while (io->bi_iter.bi_size)
    {

        struct aead_request *req;
        struct scatterlist sg[4];
        uint64_t curr_sector = io->bi_iter.bi_sector;
        DECLARE_CRYPTO_WAIT(wait);
        bv = bio_iter_iovec(io->bio_in, io->bi_iter);
        // ret = mutex_lock_interruptible(&io->rbd->lock);
        // if (ret)
        //     goto exit;
        // struct encryption_metadata *entry = get_entry(&io->rbd->encryption_metadata_list, curr_sector);
        // mutex_unlock(&io->rbd->lock);
        switch (enc_or_dec)
        {
        case WRITE:
            // sector has never been written to
            if (*checksum_index(io, curr_sector) == 0)
            {
                printk(KERN_INFO "NEW WRITE: sector id %llu", curr_sector);

                // entry = kmalloc(sizeof(struct encryption_metadata), GFP_KERNEL);
                // entry->sector = curr_sector;
                // ret = mutex_lock_interruptible(&io->rbd->lock);
                // if (ret)
                //     goto exit;
                // list_add(&entry->list, &io->rbd->encryption_metadata_list);
                // mutex_unlock(&io->rbd->lock);
                //printk(KERN_INFO "Added item to list");
            }
            else
            {
                printk(KERN_INFO "WRITE: sector id %llu", curr_sector);
            }
            break;
        case READ:
            // if we ever read from a sector we never encrypted, we just return?
            if (*checksum_index(io, curr_sector) == 0)
            {
                return 0;
            }
            else
            {
                printk(KERN_INFO "READ: sector id %llu", curr_sector);
            }
            break;
        }
        // Testing fields
        // static IV
        char *iv = kmalloc(AES_GCM_IV_SIZE, GFP_KERNEL);
        if (!iv)
        {
            printk(KERN_INFO "could not allocate ivdata");
            ret = -ENOMEM;
            goto exit;
        }
        memcpy(iv, "123456789012", AES_GCM_IV_SIZE);
        sg_init_table(sg, 4);
        sg_set_buf(&sg[0], &curr_sector, sizeof(uint64_t));
        sg_set_buf(&sg[1], iv, AES_GCM_IV_SIZE);
        sg_set_page(&sg[2], bv.bv_page, SECTOR_SIZE, bv.bv_offset);
        sg_set_buf(&sg[3], checksum_index(io, curr_sector), AES_GCM_AUTH_SIZE);

        // /* AEAD request:
        //  *  |----- AAD -------|------ DATA -------|-- AUTH TAG --|
        //  *  | (authenticated) | (auth+encryption) |              |
        //  *  | sector_LE |  IV |  sector in/out    |  tag in/out  |
        //  */
        printk(KERN_INFO "allocating aead request");
        req = aead_request_alloc(io->rbd->tfm, GFP_KERNEL);
        if (!req)
        {
            printk(KERN_INFO "aead request allocation failed");
            aead_request_free(req);
            kfree(iv);
            ret = -ENOMEM;
            goto exit;
        }
        aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
        // sector + iv size
        aead_request_set_ad(req, sizeof(uint64_t) + AES_GCM_IV_SIZE);
        switch (enc_or_dec)
        {
        case WRITE:
            aead_request_set_crypt(req, sg, sg, SECTOR_SIZE, iv);
            ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
            break;
        case READ:
            aead_request_set_crypt(req, sg, sg, SECTOR_SIZE + AES_GCM_AUTH_SIZE, iv);
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
            kfree(iv);
            goto exit;
        }
        bio_advance_iter(io->bio_in, &io->bi_iter, SECTOR_SIZE);
        kfree(iv);
    }
    return 0;
exit:
    return ret;
}

/**
 * How decrypting read works:
 *
 * 1. In map(), we create a clone of the read. At this point in time, the read does not have the actual data (which may be on disk).
 * 2. We submit the clone, triggering bio_end_io(), which calls this function.
 * 3. We release the clone with bio_put(). The data is fetched in the bio_vecs, so we decrypt it now for the read.
 * 4. We call bio_endio() on the original read, which returns the decrypted data to the user.
 */
static void decrypt_at_end_io(struct bio *clone)
{
    struct encryption_io *read_bio = clone->bi_private;

    // the cloned bio is no longer useful
    bio_put(clone);

    // decrypt
    enc_or_dec_bio(read_bio, READ);
    printk(KERN_INFO "decryption properly worked");
    // release the read bio
    bio_endio(read_bio->base_bio);
}

static void encryption_io_init(struct encryption_io *io, struct encryption_device *rbd, struct bio *bio, uint64_t sector)
{
    // TODO: maybe look into adding an iv_offset if neccesarry
    io->sector = sector;
    io->base_bio = bio;
    io->bio_in = bio;
    io->bi_iter = bio->bi_iter;
    io->rbd = rbd;
    io->error = 0;
    return;
}

static int encryption_map(struct dm_target *ti, struct bio *bio)
{
    printk(KERN_INFO "encryption map called\n");
    struct encryption_device *rbd = ti->private;
    struct bio *clone;
    struct encryption_io *io;

    bio_set_dev(bio, rbd->dev->bdev);
    // fetch data specific to bio
    io = dm_per_bio_data(bio, ti->per_io_data_size);
    // initialize fields for bio data that will be useful for encryption
    encryption_io_init(io, rbd, bio, dm_target_offset(ti, bio->bi_iter.bi_sector));
    printk(KERN_INFO "io properly initialized\n");
    if (bio_has_data(bio))
    {
        switch (bio_data_dir(bio))
        {
        case WRITE:
            uint64_t original_sector = io->sector;
            unsigned int original_size = bio->bi_iter.bi_size;
            unsigned int original_idx = bio->bi_iter.bi_idx;

            // Encrypt
            enc_or_dec_bio(io, WRITE);
            printk(KERN_INFO "encryption done properly\n");

            // Reset to the original beginning values of the bio, otherwise nothing will be written
            bio->bi_iter.bi_sector = original_sector;
            bio->bi_iter.bi_size = original_size;
            bio->bi_iter.bi_idx = original_idx;

            return DM_MAPIO_REMAPPED;
        case READ:
            // Create a clone that calls decrypt_at_end_io when the IO returns with actual read data
            clone = bio_clone_fast(bio, GFP_NOWAIT, &rbd->bs);
            if (!clone)
            {
                printk(KERN_INFO "Could not create clone");
                return 1;
            }
            clone->bi_private = io;
            clone->bi_end_io = decrypt_at_end_io;
            bio_set_dev(clone, rbd->dev->bdev);
            clone->bi_opf = bio->bi_opf;
            clone->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

            // Submit the clone, triggering end_io, where the read will actually have data and we can decrypt
            submit_bio_noacct(clone);
            printk(KERN_INFO "read properly initialized\n");

            return DM_MAPIO_SUBMITTED;
        }
    }
    return DM_MAPIO_SUBMITTED;
}

static struct target_type encryption_target = {
    .name = "encryption",
    .version = {0, 1, 0},
    .features = DM_TARGET_INTEGRITY, // TODO: Figure out what this means
    .module = THIS_MODULE,
    .ctr = encryption_constructor,
    .dtr = encryption_destructor,
    .map = encryption_map,
};

int __init dm_encryption_init(void)
{
    int r = dm_register_target(&encryption_target);
    printk(KERN_INFO "encryption module loaded\n");

    if (r < 0)
        DMERR("register failed %d", r);
    return r;
}

void dm_encryption_exit(void)
{
    dm_unregister_target(&encryption_target);
    printk(KERN_INFO "encryption module unloaded\n");
}

module_init(dm_encryption_init);
module_exit(dm_encryption_exit);

MODULE_LICENSE("GPL");
