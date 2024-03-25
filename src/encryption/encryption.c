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
#define IVLEN 36



struct encrypt_ctx {
    // symmetric key algorithm instance
    struct crypto_skcipher *tfm;
    // TODO (verify logic): make request to hw chip?
    struct skcipher_request *req;

    // generic implementation struct for waiting for crypto op to complete
    struct crypto_wait wait;
};

// Data attached to each bio
struct encryption_device
{
    struct dm_dev *dev;
    // AES-CBC
    struct encrypt_ctx* skcipher_handle;
    // persist key
    char *key;
};


void cleanup(struct encryption_device* rbd)
{
    // if (rbd->key)
        // kfree(rbd->key);
    if (rbd->skcipher_handle->req)
        skcipher_request_free(rbd->skcipher_handle->req);
    if (rbd->skcipher_handle->tfm)
        crypto_free_skcipher(rbd->skcipher_handle->tfm);
    if (rbd->skcipher_handle)
        kfree(rbd->skcipher_handle);
    if (rbd)
        kfree(rbd);
}

static int encryption_constructor(struct dm_target *ti, unsigned int argc, char **argv)
{
    printk(KERN_INFO "encryption constructor called\n");
    int ret;

    struct encryption_device *rbd = kmalloc(sizeof(struct encryption_device), GFP_KERNEL);
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
    // TODO: set ret to code, and go ot label for everything

    /* Set up fields needed for checksums */
    // initialize cipher handle (instance) of sha256
    // look into other params?
    // TODO: Change flag to CRYPTO_ALG_ASYNC to only allow for synchronous calls
    // rbd->encryptor->shash.flags = 0x0;

    /* Initialize Encryption Structs*/
    rbd->skcipher_handle = kmalloc(sizeof(struct encrypt_ctx), GFP_KERNEL);
    if (rbd->skcipher_handle == NULL) {
        ti->error = "Cannot allocate skcipher_handle";
        ret = -ENOMEM;
        goto out;
    }
    printk(KERN_INFO "cipher handle properly initialized\n");

    // // TODO: Change flag to CRYPTO_ALG_ASYNC to only allow for synchronous calls
    rbd->skcipher_handle->tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
    if (IS_ERR(rbd->skcipher_handle->tfm)) {
        ti->error = "Cannot allocate skcipher_handle transform";
        ret = -ENOMEM;
        goto out;
    }
    printk(KERN_INFO "transform properly initialized\n");

    // /* Create a request */
    rbd->skcipher_handle->req = skcipher_request_alloc(rbd->skcipher_handle->tfm, GFP_KERNEL);
    if (!rbd->skcipher_handle->tfm) {
        ti->error = "could not allocate skcipher request";
        ret = -ENOMEM;
        goto out;
    }
    printk(KERN_INFO "encryption algorithm instance and request instance initialized properly\n");
    /* Assign callback to request 

     Once hardware chip finishes encryption, notifies CPU 
     via IRQ handler and executes callback (crypto_req_done)
     once request processsed 
     */

    /* AES 256 with random key */
    // rbd->key = kmalloc(32, GFP_KERNEL);
    // if (rbd->key == NULL) {
    //     ti->error = "Could not allocate key";
    //     ret = -ENOMEM;
    //     goto out;
    // }
    // get_random_bytes(rbd->key, 32);
    rbd->key = "Kzj79WMM/6OFcScUhGhq0m6BUXMK7igsVerFoRVo78A=";
    printk(KERN_INFO "key properly initialized\n");
    if (crypto_skcipher_setkey(rbd->skcipher_handle->tfm, rbd->key, 32)) {
        ti->error = "Key could not be set";
        ret = -EAGAIN;
        goto out;
    }

    ti->private = rbd;

    return 0;

    out:
        cleanup(rbd);
    return ret;
}


static unsigned int skcipher_encdec(struct encrypt_ctx *sk, int enc) {
    int rc;
    switch (enc) {
        case WRITE:
            rc = crypto_wait_req(crypto_skcipher_encrypt(sk->req), &sk->wait);
            break;
        case READ:
            rc = crypto_wait_req(crypto_skcipher_decrypt(sk->req), &sk->wait);
            break;
    }
	if (rc) {
		pr_info(KERN_INFO "skcipher encrypt returned with result %d\n", rc);
    }
    return rc;
}

static void encryption_destructor(struct dm_target *ti)
{
    printk(KERN_INFO "encryption destructor called\n");

    struct encryption_device *rbd = ti->private;
    dm_put_device(ti, rbd->dev);
    cleanup(rbd);
}

static void decrypt_at_end_io(struct bio *bio) {
    char ivdata[IVLEN] = {0};
    struct encryption_device *rbd = bio->bi_private;
    int ret;
    
    bio_put(bio);

    // Iterate through bio and decrypt each block
    while (bio->bi_iter.bi_size) {
        printk(KERN_INFO "decrypting...\n");
        struct bio_vec bv = bio_iter_iovec(bio, bio->bi_iter);
        struct scatterlist sg;

        sg_init_table(&sg, 1);
        sg_set_page(&sg, bv.bv_page, SECTOR_SIZE, bv.bv_offset);

        skcipher_request_set_crypt(rbd->skcipher_handle->req, &sg, &sg, SECTOR_SIZE, ivdata);
        ret = skcipher_encdec(rbd->skcipher_handle, WRITE);
        if (ret) {
            printk(KERN_INFO "decryption failed\n");
            return;
        }
        bio_advance_iter(bio, &bio->bi_iter, SECTOR_SIZE);
    }

    printk(KERN_INFO "decryption complete");
}

static int encryption_map(struct dm_target *ti, struct bio *bio)
{
    //printk(KERN_INFO "encryption map called\n");
    int ret = 0;
    unsigned char digest[256];
    char ivdata[IVLEN] = {0};
    struct encryption_device *rbd = ti->private;

    bio_set_dev(bio, rbd->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
    
    // get_random_bytes(ivdata, IVLEN);
    crypto_init_wait(&rbd->skcipher_handle->wait);
    skcipher_request_set_callback(rbd->skcipher_handle->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &rbd->skcipher_handle->wait);

    if (bio_has_data(bio))
    {
        switch (bio_data_dir(bio)) {
            case WRITE:
                // Iterate through bio and encrypt each block
                while (bio->bi_iter.bi_size) {
                    printk(KERN_INFO "encrypting...\n");
                    struct bio_vec bv = bio_iter_iovec(bio, bio->bi_iter);
                    struct scatterlist sg;

                    sg_init_table(&sg, 1);
                    sg_set_page(&sg, bv.bv_page, SECTOR_SIZE, bv.bv_offset);
                    
                    skcipher_request_set_crypt(rbd->skcipher_handle->req, &sg, &sg, SECTOR_SIZE, ivdata);
                    ret = skcipher_encdec(rbd->skcipher_handle, WRITE);
                    if (ret) {
                        printk(KERN_INFO "encryption failed\n");
                        return 1;
                    }
                    bio_advance_iter(bio, &bio->bi_iter, SECTOR_SIZE);
                }
                printk(KERN_INFO "encryption finished\n");
                break;
            case READ:
                // Create a clone that calls decrypt_at_end_io when the IO returns with actual read data
                struct bio* clone = bio_alloc_clone(rbd->dev->bdev, bio, GFP_NOWAIT);
                if (!clone) {
                    printk(KERN_INFO "decrypt clone failed\n");
                    return 1;
                }
                clone->bi_private = rbd;
                clone->bi_end_io = decrypt_at_end_io;
                clone->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

                dm_submit_bio_remap(bio, clone);
                return DM_MAPIO_REMAPPED;
        }
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
