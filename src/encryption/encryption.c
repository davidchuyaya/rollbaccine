#include <linux/module.h> /* Needed by all modules */
#include <linux/init.h>   /* Needed for the macros */
#include <linux/printk.h> /* Needed for pr_info() */
#include <linux/device-mapper.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h> /* SHA-256 Hash*/
#include <linux/bio.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#include <linux/random.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <crypto/if_alg.h>
#include <crypto/drbg.h>

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
    // AES-CBC
    // TODO: alloc on heap
    struct scatterlist sg;
    // transform
    struct crypto_skcipher *skcipher;
    struct skcipher_request *req;
    struct crypto_wait wait;
    char *ivdata;
    char *key;
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

    /* Set up fields needed for checksums */
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

    /* Set up fields needed for Encryption */
    rbd->skcipher->tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    rbd->req = skcipher_request_alloc(rbd->skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(rbd->req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &rbd->wait);

    /* AES 256 with random key */
    rbd->key = kmalloc(128, GFP_KERNEL);
    if (!rbd->key) {
        pr_info("could not allocate key\n");
        goto out;
    }
    get_random_bytes(&rbd->key, 128);
    if (crypto_skcipher_setkey(rbd->skcipher, key, 128)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* IV will be random */
    rbd->ivdata = kmalloc(128, GFP_KERNEL);
    if (!rbd->ivdata) {
        pr_info("could not allocate ivdata\n");
        goto out;
    }
    get_random_bytes(rbd->ivdata, 128);

    ti->private = rbd;

    return 0;

    out:
        if (rbd->skcipher)
            crypto_free_skcipher(skcipher);
        if (rbd->req)
            skcipher_request_free(req);
        if (rbd->ivdata)
            kfree(ivdata);
    return ret;
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
        sg_init_one(&rbd->sg, bio_data(bio), 4096);
        skcipher_request_set_crypt(rbd->req, &rbd->sg, &rbd->sg, 4096, ivdata);
        crypto_init_wait(&rbd->wait);
        // if (ret == 0)
        // {
        //     int i;
        //     for (i = 0; i < sizeof(digest); i++)
        //         printk(KERN_INFO "%02x", digest[i]);
        // }
    }
    
    int rc;
    switch (bio_op(bio)) {
        case REQ_OP_READ:
            printk(KERN_INFO "Read request\n");
            rc = crypto_wait_req(crypto_skcipher_decrypt(rbd->req), &rbd->wait);
            break;
        case REQ_OP_WRITE:
			printk(KERN_INFO "Write request\n");
            rc = crypto_wait_req(crypto_skcipher_encrypt(rbd->req), &rbd->wait);

			break;
    }
    if (rc)
            pr_info(KERN_INFO "skcipher encrypt returned with result %d\n", rc);

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
