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
    char *ivdata;

    // not sure what this is, but it's needed to create a clone of the bio
    struct bio_set bs;
    // pointers to original read/write bios so they can be referenced when endio is triggered by their clones
    struct bio *read_bio;
    struct bio *write_bio;
    // memory pool to create write clones from
    mempool_t page_pool;
};

/* Start mempool functions */
static void *encryption_page_alloc(gfp_t gfp_mask, void* data) {
    return alloc_page(gfp_mask);
}

static void encryption_free_page(void *page, void* data) {
    __free_page(page);
}
/* End mempool functions */

void cleanup(struct encryption_device* rbd)
{
    if (rbd == NULL)
        return;

    if (rbd->ivdata)
        kfree(rbd->ivdata);
    if (rbd->skcipher_handle->req)
        skcipher_request_free(rbd->skcipher_handle->req);
    if (rbd->skcipher_handle->tfm)
        crypto_free_skcipher(rbd->skcipher_handle->tfm);
    if (rbd->skcipher_handle)
        kfree(rbd->skcipher_handle);
    bioset_exit(&rbd->bs);
    mempool_exit(&rbd->page_pool);

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

    /* Initialize Encryption Structs*/
    rbd->skcipher_handle = kmalloc(sizeof(struct encrypt_ctx), GFP_KERNEL);
    if (rbd->skcipher_handle == NULL) {
        ti->error = "Cannot allocate skcipher_handle";
        ret = -ENOMEM;
        goto out;
    }
    printk(KERN_INFO "cipher handle properly initialized\n");

    // TODO: Change flag to CRYPTO_ALG_ASYNC to only allow for synchronous calls
    rbd->skcipher_handle->tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
    if (IS_ERR(rbd->skcipher_handle->tfm)) {
        ti->error = "Cannot allocate skcipher_handle transform";
        ret = -ENOMEM;
        goto out;
    }
    printk(KERN_INFO "transform properly initialized\n");

    /* Create a request */
    rbd->skcipher_handle->req = skcipher_request_alloc(rbd->skcipher_handle->tfm, GFP_KERNEL);
    if (!rbd->skcipher_handle->req) {
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
    skcipher_request_set_callback(rbd->skcipher_handle->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &rbd->skcipher_handle->wait);

    rbd->key = "12345678901234567890123456789012";
    if (crypto_skcipher_setkey(rbd->skcipher_handle->tfm, rbd->key, 32)) {
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

    bioset_init(&rbd->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);
    ret = mempool_init(&rbd->page_pool, BIO_MAX_VECS, encryption_page_alloc, encryption_free_page, NULL);
    if (ret) {
        ti->error = "Cannot allocate page mempool";
        goto out;
    }

    ti->private = rbd;
    ti->num_flush_bios = 1;
    ti->limit_swap_bios = true;

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
		pr_info("skcipher encrypt returned with result %d\n", rc);
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

static void decrypt_at_end_io(struct bio *clone) {
    struct encryption_device *rbd = clone->bi_private;
    int ret;

    // the cloned bio is no longer useful
    struct bio *read_bio = rbd->read_bio;
    bio_put(clone);

    // Iterate through bio and decrypt each block
    while (read_bio->bi_iter.bi_size) {
        struct bio_vec bv = bio_iter_iovec(read_bio, read_bio->bi_iter);
        struct scatterlist sg;

        sg_init_table(&sg, 1);
        sg_set_page(&sg, bv.bv_page, SECTOR_SIZE, bv.bv_offset);

        crypto_init_wait(&rbd->skcipher_handle->wait);
        skcipher_request_set_callback(rbd->skcipher_handle->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &rbd->skcipher_handle->wait);
        skcipher_request_set_crypt(rbd->skcipher_handle->req, &sg, &sg, SECTOR_SIZE, rbd->ivdata);
        ret = skcipher_encdec(rbd->skcipher_handle, READ);
        if (ret) {
            printk(KERN_INFO "decryption failed\n");
            return;
        }
        bio_advance_iter(read_bio, &read_bio->bi_iter, SECTOR_SIZE);
    }

    printk(KERN_INFO "decryption complete");
    bio_endio(read_bio);
}

static void encrypt_end_io(struct bio *clone) {
    struct encryption_device *rbd = clone->bi_private;
    struct bio_vec *bv;
    struct bvec_iter_all iter_all;

    bio_for_each_segment_all(bv, clone, iter_all) {
        mempool_free(bv->bv_page, &rbd->page_pool);
    }
    printk(KERN_INFO "encryption end io called, pages freed\n");

    bio_put(clone);
    bio_endio(rbd->write_bio);
}

static int encryption_map(struct dm_target *ti, struct bio *bio)
{
    //printk(KERN_INFO "encryption map called\n");
    int ret = 0;
    unsigned char digest[256];
    struct encryption_device *rbd = ti->private;

    bio_set_dev(bio, rbd->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
    
    struct bio *clone;

    if (bio_has_data(bio)) {
        switch (bio_data_dir(bio)) {
            case WRITE:
                // Create clone
                unsigned int nr_iovecs = (bio->bi_iter.bi_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
                gfp_t gfp_mask = GFP_NOWAIT | __GFP_HIGHMEM;

                clone = bio_alloc_bioset(GFP_NOIO, nr_iovecs, &rbd->bs);
                clone->bi_private = rbd;
                clone->bi_end_io = encrypt_end_io;
                bio_set_dev(clone, rbd->dev->bdev);
                clone->bi_opf = bio->bi_opf;

                unsigned i, len, remaining_size;
                remaining_size = bio->bi_iter.bi_size;
                struct page *page;
                for (i = 0; i < nr_iovecs; i++) {
                    page = mempool_alloc(&rbd->page_pool, gfp_mask);
                    len = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;
                    bio_add_page(clone, page, len, 0);
                    remaining_size -= len;
                }

                // Iterate through bio and encrypt each block into the clone
                sector_t original_sector = bio->bi_iter.bi_sector;

                struct scatterlist sg_in, sg_out;
                while (bio->bi_iter.bi_size) {
                    struct bio_vec bv_in = bio_iter_iovec(bio, bio->bi_iter);
                    struct bio_vec bv_out = bio_iter_iovec(clone, clone->bi_iter);
                    // printk(KERN_INFO "bio page contents: %x %x %x %x %x %x %x %x", ((unsigned char *)bv_in.bv_page)[bv_in.bv_offset], ((unsigned char *)bv_in.bv_page)[bv_in.bv_offset + 1], ((unsigned char *)bv_in.bv_page)[bv_in.bv_offset + 2], ((unsigned char *)bv_in.bv_page)[bv_in.bv_offset + 3], ((unsigned char *)bv_in.bv_page)[bv_in.bv_offset + 4], ((unsigned char *)bv_in.bv_page)[bv_in.bv_offset + 5], ((unsigned char *)bv_in.bv_page)[bv_in.bv_offset + 6], ((unsigned char *)bv_in.bv_page)[bv_in.bv_offset + 7]);
                    
                    sg_init_table(&sg_in, 1);
                    sg_set_page(&sg_in, bv_in.bv_page, SECTOR_SIZE, bv_in.bv_offset);
                    sg_init_table(&sg_out, 1);
                    sg_set_page(&sg_out, bv_out.bv_page, SECTOR_SIZE, bv_out.bv_offset);

                    crypto_init_wait(&rbd->skcipher_handle->wait);
                    skcipher_request_set_callback(rbd->skcipher_handle->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &rbd->skcipher_handle->wait);
                    skcipher_request_set_crypt(rbd->skcipher_handle->req, &sg_in, &sg_out, SECTOR_SIZE, rbd->ivdata);
                    ret = skcipher_encdec(rbd->skcipher_handle, WRITE);
                    if (ret) {
                        printk(KERN_INFO "encryption failed\n");
                        return 1;
                    }

                    // printk(KERN_INFO "encrypted page contents: %x %x %x %x %x %x %x %x", ((unsigned char *)bv_out.bv_page)[bv_out.bv_offset], ((unsigned char *)bv_out.bv_page)[bv_out.bv_offset + 1], ((unsigned char *)bv_out.bv_page)[bv_out.bv_offset + 2], ((unsigned char *)bv_out.bv_page)[bv_out.bv_offset + 3], ((unsigned char *)bv_out.bv_page)[bv_out.bv_offset + 4], ((unsigned char *)bv_out.bv_page)[bv_out.bv_offset + 5], ((unsigned char *)bv_out.bv_page)[bv_out.bv_offset + 6], ((unsigned char *)bv_out.bv_page)[bv_out.bv_offset + 7]);

                    bio_advance_iter(bio, &bio->bi_iter, SECTOR_SIZE);
                    bio_advance_iter(clone, &clone->bi_iter, SECTOR_SIZE);
                }
                printk(KERN_INFO "encryption finished\n");

                rbd->write_bio = bio;
                clone->bi_iter.bi_sector = original_sector;

                submit_bio_noacct(clone);
                return DM_MAPIO_SUBMITTED;
            case READ:
                // Create a clone that calls decrypt_at_end_io when the IO returns with actual read data
                clone = bio_clone_fast(bio, GFP_NOWAIT, &rbd->bs);
                if (!clone) {
                    printk(KERN_INFO "Could not create clone failed\n");
                    return 1;
                }
                clone->bi_private = rbd;
                clone->bi_end_io = decrypt_at_end_io;
                bio_set_dev(clone, rbd->dev->bdev);
                clone->bi_opf = bio->bi_opf;
                clone->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
                rbd->read_bio = bio;

                submit_bio_noacct(clone);
                // printk(KERN_INFO "submitted decryption");

                return DM_MAPIO_SUBMITTED;
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
