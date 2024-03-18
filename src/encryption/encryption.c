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


// Struct that contains that actual synchronous hash
// stored seperately since size of struct needs to include operational state of hash
struct crypt
{
    struct shash_desc shash;
};

struct encrypt_ctx {
    // symmetric key algorithm instance
    struct crypto_skcipher *tfm;
    // TODO (verify logic): make request to hw chip?
    struct skcipher_request *req;
    struct scatterlist sg;

    // generic implementation struct for waiting for crypto op to complete
    struct crypto_wait wait;
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
    struct encrypt_ctx* skcipher_handle;
    // persist key
    char *key;
};


void cleanup(struct encryption_device* rbd)
{
    if (rbd->key)
        kfree(rbd->key);
    if (rbd->skcipher_handle->req)
        skcipher_request_free(rbd->skcipher_handle->req);
    if (rbd->skcipher_handle->tfm)
        crypto_free_skcipher(rbd->skcipher_handle->tfm);
    if (rbd->skcipher_handle)
        kfree(rbd->skcipher_handle);
    if (rbd->encryptor)
        kfree(rbd->encryptor);
    if (rbd->alg)
        crypto_free_shash(rbd->alg);
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
    rbd->alg = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(rbd->alg))
    {
        ti->error = "Cannot allocate algorithm sha56";
        ret = -ENOMEM;
        goto out;
    }
    // allocate size of struct + size of operational state for algorithm
    int size = sizeof(struct crypt) + crypto_shash_descsize(rbd->alg);
    rbd->encryptor = kmalloc(size, GFP_KERNEL);
    if (rbd->encryptor == NULL)
    {
        ti->error = "Cannot allocate crypt instance";
        ret = -ENOMEM;
        goto out;
    }
    // Setting our algorithm for encryption to sha256
    rbd->encryptor->shash.tfm = rbd->alg;
    // rbd->encryptor->shash.flags = 0x0;

    /* Initialize Encryption Structs*/
    rbd->skcipher_handle = kmalloc(sizeof(struct encrypt_ctx), GFP_KERNEL);
    if (rbd->skcipher_handle == NULL) {
        ti->error = "Cannot allocate skcipher_handle";
        ret = -ENOMEM;
        goto out;
    }

    rbd->skcipher_handle->tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(rbd->skcipher_handle->tfm)) {
        ti->error = "Cannot allocate skcipher_handle transform";
        ret = -ENOMEM;
        goto out;
    }

    /* Create a request */
    rbd->skcipher_handle->req = skcipher_request_alloc(rbd->skcipher_handle->tfm, GFP_KERNEL);
    if (!rbd->skcipher_handle->tfm) {
        ti->error = "could not allocate skcipher request";
        ret = -ENOMEM;
        goto out;
    }
    /* Assign callback to request 

     Once hardware chip finishes encryption, notifies CPU 
     via IRQ handler and executes callback (crypto_req_done)
     once request processsed 
     */

     // TODO: learn more about callback function being called twice
    skcipher_request_set_callback(rbd->skcipher_handle->req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &rbd->skcipher_handle->wait);

    /* AES 256 with random key */
    rbd->key = kmalloc(32, GFP_KERNEL);
    if (rbd->key == NULL) {
        ti->error = "Could not allocate key";
        ret = -ENOMEM;
        goto out;
    }
    get_random_bytes(&rbd->key, 32);

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
    if (enc) {
        rc = crypto_wait_req(crypto_skcipher_encrypt(sk->req), &sk->wait);
    }
    else {
        rc = crypto_wait_req(crypto_skcipher_decrypt(sk->req), &sk->wait);
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

static int encryption_map(struct dm_target *ti, struct bio *bio)
{
    // printk(KERN_INFO "encryption map called\n");
    int ret = 0;
    unsigned char digest[256];
    char *ivdata;
    struct encryption_device *rbd = ti->private;
    
    ivdata = kmalloc(IVLEN, GFP_KERNEL);
    if (ivdata == NULL) {
        ti->error = "Could not allocate ivdata";
        ret = -ENOMEM;
        goto out;
    }
    get_random_bytes(ivdata, IVLEN);
    if (bio_has_data(bio))
    {
        ret = crypto_shash_digest(&rbd->encryptor->shash, bio_data(bio), SHA256_LENGTH, digest);
        if (ret) {
            // TODO: Error Handling
            goto out;
        }
        sg_init_one(&rbd->skcipher_handle->sg, bio_data(bio), BLOCK_SIZE);
        skcipher_request_set_crypt(rbd->skcipher_handle->req, &rbd->skcipher_handle->sg, &rbd->skcipher_handle->sg, BLOCK_SIZE, ivdata);
        crypto_init_wait(&rbd->skcipher_handle->wait);
        // if (ret == 0)
        // {
        //     int i;
        //     for (i = 0; i < sizeof(digest); i++)
        //         printk(KERN_INFO "%02x", digest[i]);
        // }
    }
    switch (bio_op(bio)) {
        case REQ_OP_READ:
            ret = skcipher_encdec(rbd->skcipher_handle, 1);
            break;
        case REQ_OP_WRITE:
			ret = skcipher_encdec(rbd->skcipher_handle, 1);
            break;
    }
    if (ret)
        goto out;

    return DM_MAPIO_REMAPPED;

    out:
        cleanup(rbd);

    return ret;
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
