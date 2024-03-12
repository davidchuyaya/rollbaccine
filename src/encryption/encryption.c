#include <linux/module.h> /* Needed by all modules */
#include <linux/init.h>   /* Needed for the macros */
#include <linux/printk.h> /* Needed for pr_info() */
#include <linux/device-mapper.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h> /* SHA-256 Hash*/
#include <linux/bio.h>

#define DM_MSG_PREFIX "encryption"

#define SHA256_LENGTH 256

// Struct that contains that actual synchronous hash
// stored seperately since size of struct needs to include operational state of hash
struct crypt
{
    struct shash_desc shash;
};

// Data attached to each bio
struct encryption_device
{
    struct dm_dev *dev;
    // Synchronous cryptographic hash type
    // documentation: https://elixir.bootlin.com/linux/latest/source/include/crypto/hash.h
    struct crypto_shash *alg;
    struct crypt *encryptor;
};

static int encryption_constructor(struct dm_target *ti, unsigned int argc, char **argv)
{
    printk(KERN_INFO "encryption constructor called\n");

    struct encryption_device *rbd = kmalloc(sizeof(struct encryption_device), GFP_KERNEL);
    if (rbd == NULL)
    {
        ti->error = "Cannot allocate context";
        return -ENOMEM;
    }

    // Get the device from argv[0] and store it in rbd->dev
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &rbd->dev))
    {
        ti->error = "Device lookup failed";
        kfree(rbd);
        return -EINVAL;
    }

    // initialize cipher handle (instance) of sha256
    // look into other params?
    rbd->alg = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(rbd->alg))
    {
        pr_info("can't alloc alg sha256\n");
        return PTR_ERR(rbd->alg);
    }

    struct crypt *sdesc;
    int size;
    // allocate size of struct + size of operational state for algorithm
    size = sizeof(struct crypt) + crypto_shash_descsize(rbd->alg);
    rbd->encryptor = kmalloc(size, GFP_KERNEL);
    if (!rbd->encryptor)
    {
        pr_info("can't alloc encryptor\n");
        return PTR_ERR(sdesc);
    }
    // Setting our algorithm for encryption to sha256
    rbd->encryptor->shash.tfm = rbd->alg;
    // rbd->encryptor->shash.flags = 0x0;
    ti->private = rbd;

    return 0;
}

static void encryption_destructor(struct dm_target *ti)
{
    printk(KERN_INFO "encryption destructor called\n");

    struct encryption_device *rbd = ti->private;
    dm_put_device(ti, rbd->dev);
    crypto_free_shash(rbd->alg);
    kfree(rbd->encryptor);
    kfree(rbd);
}

static int encryption_map(struct dm_target *ti, struct bio *bio)
{
    // printk(KERN_INFO "encryption map called\n");

    struct encryption_device *rbd = ti->private;

    bio_set_dev(bio, rbd->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    int ret;
    unsigned char digest[256];
    if (bio_has_data(bio))
    {
        ret = crypto_shash_digest(&rbd->encryptor->shash, bio_data(bio), SHA256_LENGTH, digest);
        if (ret) {
            // TODO: Error Handling
            pr_err("error ret = %d", ret);
            return -1
        }
        // if (ret == 0)
        // {
        //     int i;
        //     for (i = 0; i < sizeof(digest); i++)
        //         printk(KERN_INFO "%02x", digest[i]);
        // }
    }

    return DM_MAPIO_REMAPPED;
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
