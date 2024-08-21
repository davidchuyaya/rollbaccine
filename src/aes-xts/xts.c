#include <linux/module.h>       /* Needed by all modules */
#include <linux/init.h>         /* Needed for the macros */
#include <linux/printk.h>       /* Needed for printk() */
#include <linux/device-mapper.h>/* Needed for device-mapper operations */
#include <linux/crypto.h>       /* Needed for crypto operations */
#include <crypto/internal/hash.h> /* Needed for hashing (SHA-256) */
#include <linux/bio.h>          /* Needed for bio operations */
#include <linux/scatterlist.h>  /* Needed for scatterlist operations */
#include <linux/gfp.h>          /* Needed for memory allocation */
#include <linux/err.h>          /* Needed for error handling */
#include <linux/random.h>       /* Needed for IV generation */
#include <crypto/aead.h>        /* Needed for AEAD operations */
#include <crypto/skcipher.h>

#define DM_MSG_PREFIX "aes-xts"
#define AES_XTS_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define SHA256_LENGTH 256
#define MIN_IOS 64

// Data attached to each bio
struct xts_device {
    struct dm_dev *dev;
    // symmetric key algorithm instance
    struct crypto_skcipher *tfm;  // Symmetric key cipher for AES-XTS
    struct crypto_shash *hmac_tfm;  // HMAC for integrity check
    struct shash_desc *shash; // Space used by shash
    char *key;  // AES-XTS key
    struct bio_set bs;
    // array of hashes of each sector
    char* checksums;
    char *ivdata;
};

// per bio private data
struct bio_data {
    // maintain information of original bio before iteration
    struct bio *base_bio;
    struct bvec_iter bi_iter;
    struct crypto_wait wait;
    struct xts_device *device;
};

void cleanup(struct xts_device *device) {
    if (device == NULL)
        return;
    if (device->ivdata)
        kfree(device->ivdata);
    if (device->checksums)
        kvfree(device->checksums);
    if (device->tfm)
        crypto_free_skcipher(device->tfm);
    if (device->hmac_tfm)
        crypto_free_shash(device->hmac_tfm);
    if (device->shash)
	    kfree(device->shash);
    if (device->key)
        kfree(device->key);
    bioset_exit(&device->bs);
    kfree(device);
}

static void xts_destructor(struct dm_target *ti) {
    struct xts_device *device = ti->private;
    printk(KERN_INFO "xts destructor called\n");
    if (device == NULL)
        return;
    cleanup(device);
    dm_put_device(ti, device->dev);
}

static int xts_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    int ret;
    struct xts_device *device;
    printk(KERN_INFO "xts constructor called\n");

    device = kmalloc(sizeof(struct xts_device), GFP_KERNEL);
    if (device == NULL) {
        ti->error = "Cannot allocate context";
        ret = -ENOMEM;
        goto out;
    }

    // Get the device from argv[0] and store it in device->dev
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &device->dev)) {
        ti->error = "Device lookup failed";
        ret = -EINVAL;
        goto out;
    }

    device->tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
    if (IS_ERR(device->tfm)) {
        ti->error = "Cannot allocate AES-XTS transform";
        ret = -ENOMEM;
        goto out;
    }
    printk(KERN_INFO "transform properly initialized\n");

    device->key = "12345678901234567890123456789012";
    ret = crypto_skcipher_setkey(device->tfm, device->key, AES_XTS_KEY_SIZE);
    if (ret) {
        ti->error = "AES-XTS key could not be set";
        goto out;
    }
    printk(KERN_INFO "key properly initialized\n");

    device->ivdata = kmalloc(16, GFP_KERNEL);
    if (!device->ivdata) {
        ti->error = "could not allocate ivdata";
        ret = -ENOMEM;
        goto out;
    }
    memcpy(device->ivdata, "1234567890123456", 16);

    device->hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(device->hmac_tfm)) {
        ti->error = "Cannot allocate HMAC transform";
        ret = -ENOMEM;
        goto out;
    }

    device->shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(device->hmac_tfm), GFP_NOIO);
    if (!device->shash) {
        ti->error = "could not allocate shash descriptor";
        ret = -ENOMEM;
        goto out;
    }

   

    device->checksums = kvmalloc_array(ti->len, SHA256_LENGTH, GFP_KERNEL | __GFP_ZERO);
    if (!device->checksums) {
        ti->error = "Cannot allocate checksums";
        ret = -ENOMEM;
        goto out;
    }
    printk(KERN_INFO "checksums properly initialized\n");

    bioset_init(&device->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);


    ti->per_io_data_size = sizeof(struct bio_data);
    ti->private = device;

    return 0;

out:
    cleanup(device);
    return ret;
}

static inline unsigned char *checksum_index(struct bio_data *bio_data, sector_t index) {
    return &bio_data->device->checksums[index * SHA256_LENGTH];
}


static int enc_or_dec_bio(struct bio_data *bio_data, int enc_or_dec) {
    int ret;
    struct bio_vec bv;
    struct bio_vec prev_bv;
    uint64_t curr_sector;
    struct skcipher_request *req;
    // char *iv = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
    // if (!iv) {
    //     printk(KERN_ERR "iv allocation failed");
    //     ret = -ENOMEM;
    //     goto exit;
    // }
    req = skcipher_request_alloc(bio_data->device->tfm, GFP_KERNEL);
    if (!req) {
        printk(KERN_ERR "aead request allocation failed");
        ret = -ENOMEM;
        goto exit;
    }
    while (bio_data->bi_iter.bi_size) {
        curr_sector = bio_data->bi_iter.bi_sector;
        bv = bio_iter_iovec(bio_data->base_bio, bio_data->bi_iter);
        prev_bv = bv;
        // memcpy(iv, "1234567890123456", 16);
	    DECLARE_CRYPTO_WAIT(wait);
        // switch (enc_or_dec) {
        //     case READ:
        //         if (*checksum_index(bio_data, curr_sector) == 0) {
        //             skcipher_request_free(req);
        //             kfree(iv);
        //             return 0;
        //         }
        //         break;
        //     default:
        //         break;
        // }
        struct scatterlist sg;
        sg_init_table(&sg, 1);
        sg_set_page(&sg, bv.bv_page, SECTOR_SIZE, bv.bv_offset);
        skcipher_request_set_crypt(req, &sg, &sg, SECTOR_SIZE, bio_data->device->ivdata);
	    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
        printk(KERN_INFO "enc/dec initialized\n");
        switch (enc_or_dec) {
            case WRITE:
                ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
                break;
            case READ:
                ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
                break;
        }

        if (ret) {
            printk(KERN_ERR "xts/decryption failed");
            skcipher_request_free(req);
            // kfree(iv);
            goto exit;
        }
        printk(KERN_INFO "enc/dec finished succesfully\n");

        // HMAC calculation
	    // ret = crypto_shash_digest(bio_data->device->shash, page_address(prev_bv.bv_page) + prev_bv.bv_offset, SECTOR_SIZE, checksum_index(bio_data, curr_sector));
        // if (ret) {
        //     printk(KERN_INFO "hash failed");
        //     // TODO: Don't fail silently
        //     goto exit;
        // }
        // printk(KERN_INFO "hashing finished succesfully\n");

        bio_advance_iter(bio_data->base_bio, &bio_data->bi_iter, SECTOR_SIZE);
    }
    skcipher_request_free(req);
    // kfree(iv);
    return 0;
exit:
    cleanup(bio_data->device);
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
static void decrypt_at_end_io(struct bio *clone) {
    struct bio_data *read_bio = clone->bi_private;
    // the cloned bio is no longer useful
    bio_put(clone);
    // decrypt
    enc_or_dec_bio(read_bio, READ);
    // release the original read bio
    bio_endio(read_bio->base_bio);
}

struct bio* shallow_bio_clone(struct xts_device *device, struct bio *bio_src) {
    struct bio *clone;
    clone = bio_alloc_clone(bio_src->bi_bdev, bio_src, GFP_NOIO, &device->bs);
    if (!clone) {
        printk(KERN_ERR "Could not create clone");
        return NULL;
    }
    clone->bi_iter.bi_sector = bio_src->bi_iter.bi_sector;
    return clone;
}

static int xts_map(struct dm_target *ti, struct bio *bio) {
    struct xts_device *device = ti->private;
    struct bio *clone;
    struct bio_data *bio_data;

    bio_set_dev(bio, device->dev->bdev);
    // fetch data specific to bio
    bio_data = dm_per_bio_data(bio, ti->per_io_data_size);
    // initialize fields for bio data that will be useful for xts
    bio_data->base_bio = bio;
    // save bi_iter since bi_iter will be moved for reads before the read operation is actually done
    bio_data->bi_iter = bio->bi_iter;
    bio_data->device = device;
    if (bio_has_data(bio)) {
	    uint64_t original_sector;
        switch (bio_data_dir(bio)){
            case WRITE:
                original_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
                unsigned int original_size = bio->bi_iter.bi_size;
                unsigned int original_idx = bio->bi_iter.bi_idx;
                // Encrypt
                enc_or_dec_bio(bio_data, WRITE);
                // Reset to the original beginning values of the bio, otherwise nothing will be written
                bio->bi_iter.bi_sector = original_sector;
                bio->bi_iter.bi_size = original_size;
                bio->bi_iter.bi_idx = original_idx;
                return DM_MAPIO_REMAPPED;
            case READ:
                // Create a clone that calls decrypt_at_end_io when the bio_data returns with actual read data
                clone = shallow_bio_clone(device, bio);
                if (!clone) {
                    printk(KERN_ERR "Could not create clone");
                    return 1;
                }
                clone->bi_private = bio_data;
                clone->bi_end_io = decrypt_at_end_io;
                bio_set_dev(clone, device->dev->bdev);
                clone->bi_opf = bio->bi_opf;
                clone->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
                // Submit the clone, triggering end_io, where the read will actually have data and we can decrypt
                submit_bio_noacct(clone);
                return DM_MAPIO_SUBMITTED;
        }
    }
    return DM_MAPIO_SUBMITTED;
}

static struct target_type xts_target = {
    .name = "xts",
    .version = {0, 1, 0},
    .features = DM_TARGET_INTEGRITY, // TODO: Figure out what this means
    .module = THIS_MODULE,
    .ctr = xts_constructor,
    .dtr = xts_destructor,
    .map = xts_map,
};

int __init dm_xts_init(void) {
    int r = dm_register_target(&xts_target);
    printk(KERN_INFO "xts module loaded\n");
    if (r < 0)
        DMERR("register failed %d", r);
    return r;
}

void dm_xts_exit(void) {
    dm_unregister_target(&xts_target);
    printk(KERN_INFO "xts module unloaded\n");
}

module_init(dm_xts_init);
module_exit(dm_xts_exit);

MODULE_LICENSE("GPL");