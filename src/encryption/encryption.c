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

#define MIN_IOS 64

// Data attached to each bio
struct encryption_device
{
    struct dm_dev *dev;
    // symmetric key algorithm instance
    struct crypto_skcipher *tfm;
    // persist key
    char *key;
    // persist ivdata
    char *ivdata;
    // not sure what this is, but it's needed to create a clone of the bio
    struct bio_set bs;
    // pool for crypto requests
    mempool_t req_pool;
};

// per bio private data
struct encryption_io {
    // maintain information of original bio before iteration
    struct bio *base_bio;
    // needed for iteration
    struct bio *bio_in;
	struct bvec_iter bi_iter;
    // crypto stuff
    sector_t sector;
    struct crypto_wait wait;
    struct skcipher_request *req;
    struct encryption_device *rbd;

    blk_status_t error;
	
} typedef convert_context;

void cleanup(struct encryption_device* rbd)
{
    if (rbd == NULL)
        return;
    if (rbd->ivdata)
        kfree(rbd->ivdata);
    if (rbd->tfm)
        crypto_free_skcipher(rbd->tfm);
    mempool_exit(&rbd->req_pool);
    bioset_exit(&rbd->bs);
    kfree(rbd);
}

static void encryption_destructor(struct dm_target *ti) {
    struct encryption_device *rbd = ti->private;
    printk(KERN_INFO "encryption destructor called\n");
    dm_put_device(ti, rbd->dev);
    cleanup(rbd);
}

static int encryption_constructor(struct dm_target *ti, unsigned int argc, char **argv)
{
    int ret;
    struct encryption_device *rbd;
    printk(KERN_INFO "encryption constructor called\n");

    rbd = kmalloc(sizeof(struct encryption_device), GFP_KERNEL);
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

    // TODO: Change flag to CRYPTO_ALG_ASYNC to only allow for synchronous calls
    rbd->tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
    if (IS_ERR(rbd->tfm)) {
        ti->error = "Cannot allocate skcipher_handle transform";
        ret = -ENOMEM;
        goto out;
    }
    printk(KERN_INFO "transform properly initialized\n");
    
    rbd->key = "12345678901234567890123456789012";
    if (crypto_skcipher_setkey(rbd->tfm, rbd->key, 32)) {
        ti->error = "Key could not be set";
        ret = -EAGAIN;
        goto out;
    }
    printk(KERN_INFO "key properly initialized\n");

    rbd->ivdata = kmalloc(16, GFP_KERNEL);
    if (!rbd->ivdata) {
        ti->error = "could not allocate ivdata";
        ret = -ENOMEM;
        goto out;
    }
    memcpy(rbd->ivdata, "1234567890123456", 16);
    printk(KERN_INFO "ivdata properly initialized\n");

    bioset_init(&rbd->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);

    ti->private = rbd;

    // TODO: Look into putting hashes inside of here too and some rounding?
    ti->per_io_data_size = sizeof(struct encryption_io);

    // TODO: This might be sus lol
    ret = mempool_init_kmalloc_pool(&rbd->req_pool, MIN_IOS, sizeof(struct skcipher_request));
	if (ret) {
		ti->error = "Cannot allocate crypt request mempool";
		goto out;
	}


    return 0;

    out:
        cleanup(rbd);
    return ret;
}


static unsigned int skcipher_encdec(struct encryption_io *io, int enc) {
    int rc;
    switch (enc) {
        case WRITE:
            rc = crypto_wait_req(crypto_skcipher_encrypt(io->req), &io->wait);
            break;
        case READ:
            rc = crypto_wait_req(crypto_skcipher_decrypt(io->req), &io->wait);
            break;
    }
	if (rc) {
		pr_info("skcipher encrypt returned with result %d\n", rc);
    }
    return rc;
}

static int crypt_alloc_req(struct encryption_io *io) {
    // allocate from mempool since we are not in thread-safe context
    if (!io->req) {
		io->req = mempool_alloc(&io->rbd->req_pool, in_interrupt() ? GFP_ATOMIC : GFP_NOIO);
		if (!io->req)
			return -ENOMEM;
	}
    skcipher_request_set_tfm(io->req, io->rbd->tfm);
    // TODO: figure out best place to put this line
    crypto_init_wait(&io->wait);
    skcipher_request_set_callback(io->req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &io->wait);
    return 0;
}



static int enc_or_dec_bio(struct encryption_io *io, int enc_or_dec) {
    int ret;
    struct bio_vec bv;
    struct scatterlist sg;
    while (io->bi_iter.bi_size) {
        ret = crypt_alloc_req(io);
        if (ret) {
            printk(KERN_INFO "skcipher request allocation failed");
            return ret;
        }

        bv = bio_iter_iovec(io->bio_in, io->bi_iter);

        sg_init_table(&sg, 1);
        sg_set_page(&sg, bv.bv_page, SECTOR_SIZE, bv.bv_offset);
        
        skcipher_request_set_crypt(io->req, &sg, &sg, SECTOR_SIZE, io->rbd->ivdata);
        ret = skcipher_encdec(io, enc_or_dec);
        if (ret) {
            printk(KERN_INFO "encryption/decryption failed");
            // TODO: Don't fail silently
            return ret;
        }
        
        bio_advance_iter(io->bio_in, &io->bi_iter, SECTOR_SIZE);
    }
    // TODO: idk if this is right
    mempool_free(io->req, &io->rbd->req_pool);
    //skcipher_request_free(io->req);
    return 0;
}

/**
 * How decrypting read works:
 * 
 * 1. In map(), we create a clone of the read. At this point in time, the read does not have the actual data (which may be on disk).
 * 2. We submit the clone, triggering bio_end_io(), which calls this function.
 * 3. We release the clone with bio_put(). The data is fetched in the bio_vecs, so we decrypt it now for the read.
 * 4. We call bio_endio() on the original read, which returns the decrypted data to the user.
*/
static void decrypt_at_end_io(struct bio *clone) {
    struct encryption_io *read_bio = clone->bi_private;

    // the cloned bio is no longer useful
    bio_put(clone);

    // decrypt
    enc_or_dec_bio(read_bio, READ);
    printk(KERN_INFO "decryption properly worked");
    // release the read bio
    bio_endio(read_bio->base_bio);
}

static void encryption_io_init(struct encryption_io *io, struct encryption_device *rbd, struct bio *bio, sector_t sector) {
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
    if (bio_has_data(bio)) {
        switch (bio_data_dir(bio)) {
            case WRITE:
                sector_t original_sector = io->sector;
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
                if (!clone) {
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
