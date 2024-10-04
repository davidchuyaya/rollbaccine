#include <linux/module.h> /* Needed by all modules */
#include <linux/init.h>   /* Needed for the macros */
#include <linux/printk.h> /* Needed for pr_info() */
#include <linux/device-mapper.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h> /* SHA-256 Hash*/
#include <linux/bio.h>

#define DM_MSG_PREFIX "hash"

#define SHA256_LENGTH 256
#define MIN_IOS 64
// Defined if hash should be used as signature
#define HMAC

// Data attached to each bio
struct hash_device
{
    struct dm_dev *dev;
    struct crypto_shash *alg;
    struct shash_desc *shash; // Space used by shash
    struct bio_set bs;
};

struct bio_data
{
    struct hash_device *rbd;
    struct bio *bio_src;
};

static void cleanup(struct hash_device *rbd);
int __init dm_hash_init(void);
void dm_hash_exit(void);

static void cleanup(struct hash_device *rbd) {
    if (rbd == NULL) return;

    if (rbd->alg)
        crypto_free_shash(rbd->alg);
    bioset_exit(&rbd->bs);

    kfree(rbd->shash);
    kfree(rbd);
}

static int hash_constructor(struct dm_target *ti, unsigned int argc, char **argv)
{
    int ret;
    struct hash_device *rbd;
    printk(KERN_INFO "hash constructor called\n");

    rbd = kmalloc(sizeof(struct hash_device), GFP_KERNEL);
    if (rbd == NULL)
    {
        ti->error = "Cannot allocate context";
        ret = -ENOMEM;
        goto out;
    }

    // Get the device from argv[0] and store it in rbd->dev
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &rbd->dev))
    {
        ti->error = "Device lookup failed";
        ret = -EINVAL;
        goto out;
    }

    // initialize cipher handle (instance) of sha256
#ifdef HMAC
    printk(KERN_INFO "Using HMAC");
    rbd->alg = crypto_alloc_shash("hmac(sha256)", 0, 0);
    crypto_shash_setkey(rbd->alg, "abcdefghijklmnop", 16);
#elif
    rbd->alg = crypto_alloc_shash("sha256", 0, 0);
#endif
    if (IS_ERR(rbd->alg))
    {
        pr_info("can't alloc alg sha256\n");
        ret = PTR_ERR(rbd->alg);
        goto out;
    }

    rbd->shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(rbd->alg), GFP_NOIO);
    if (!rbd->shash) {
        ti->error = "could not allocate shash descriptor";
        ret = -ENOMEM;
        goto out;
    }
    rbd->shash->tfm = rbd->alg;

    bioset_init(&rbd->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);

    ti->private = rbd;

    return 0;

    out:
    cleanup(rbd);
    return ret;
}


static void hash_destructor(struct dm_target *ti)
{
    struct hash_device *rbd;
    printk(KERN_INFO "hash destructor called\n");

    rbd = ti->private;
    if (!rbd)
        return;

    dm_put_device(ti, rbd->dev);
    cleanup(rbd);
}

static void hash_bio(struct bio *bio, struct hash_device *rbd) {
    int ret;
    unsigned char digest[SHA256_LENGTH];
    struct bio_vec bv;

    // printk(KERN_INFO "Hashing bio");

    while (bio->bi_iter.bi_size) {
        bv = bio_iter_iovec(bio, bio->bi_iter);

        ret = crypto_shash_digest(rbd->shash, page_address(bv.bv_page) + bv.bv_offset, SECTOR_SIZE, digest);
        if (ret) {
            printk(KERN_INFO "hash failed");
            // TODO: Don't fail silently
            return;
        }

        printk(KERN_INFO "Hash result: %s", digest);
        bio_advance_iter(bio, &bio->bi_iter, SECTOR_SIZE);
    }
}

static void hash_at_end_io(struct bio *clone) {
    struct bio_data *bio_data = clone->bi_private;
    struct hash_device *rbd = bio_data->rbd;
    struct bio *read_bio = bio_data->bio_src;

    // the cloned bio is no longer useful
    bio_put(clone);

    // hash 
    // hash_bio(read_bio, rbd);

    // release the read bio
    bio_endio(read_bio);

    kfree(bio_data);
}

static int hash_map(struct dm_target *ti, struct bio *bio)
{
    // printk(KERN_INFO "hash map called\n");
    struct hash_device *rbd = ti->private;
    struct bio *clone;
    struct bio_data *bio_data;

    bio_set_dev(bio, rbd->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
    
    if (bio_has_data(bio)) {
        switch (bio_data_dir(bio)) {
            case WRITE:
                sector_t original_sector = bio->bi_iter.bi_sector;
                unsigned int original_size = bio->bi_iter.bi_size;
                unsigned int original_idx = bio->bi_iter.bi_idx;

                // Hash
                hash_bio(bio, rbd);

                // Reset to the original beginning values of the bio, otherwise nothing will be written
                bio->bi_iter.bi_sector = original_sector;
                bio->bi_iter.bi_size = original_size;
                bio->bi_iter.bi_idx = original_idx;
                break;
            case READ:
                bio_data = kmalloc(sizeof(struct bio_data), GFP_KERNEL);
                if (!bio_data) {
                    printk(KERN_INFO "Could not allocate bio_data");
                    return 1;
                }
                bio_data->rbd = rbd;

                // Create a clone that calls hash_at_end_io when the IO returns with actual read data
                clone = bio_alloc_clone(bio->bi_bdev, bio, GFP_NOIO, &rbd->bs);
                if (!clone) {
                    printk(KERN_INFO "Could not create clone");
                    return 1;
                }
                clone->bi_private = bio_data;
                clone->bi_end_io = hash_at_end_io;
                clone->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
                bio_data->bio_src = bio;

                // Submit the clone, triggering end_io, where the read will actually have data and we can hash
                submit_bio_noacct(clone);

                return DM_MAPIO_SUBMITTED;
        }
    }

    return DM_MAPIO_REMAPPED;
}

static struct target_type hash_target = {
    .name = "hash",
    .version = {0, 1, 0},
    .features = DM_TARGET_INTEGRITY, // TODO: Figure out what this means
    .module = THIS_MODULE,
    .ctr = hash_constructor,
    .dtr = hash_destructor,
    .map = hash_map,
};

int __init dm_hash_init(void)
{
    int r = dm_register_target(&hash_target);
    printk(KERN_INFO "hash module loaded\n");

    if (r < 0)
        DMERR("register failed %d", r);

    return r;
}

void dm_hash_exit(void)
{
    dm_unregister_target(&hash_target);
    printk(KERN_INFO "hash module unloaded\n");
}

module_init(dm_hash_init);
module_exit(dm_hash_exit);

MODULE_LICENSE("GPL");