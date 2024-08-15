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
#include <crypto/aead.h>        /* Needed for AEAD operations */

#define DM_MSG_PREFIX "encryption"

#define SHA256_LENGTH 256
#define AES_GCM_IV_SIZE 12
#define AES_GCM_AUTH_SIZE 16
#define KEY_SIZE 16
#define MIN_IOS 64


// Data attached to each bio
struct encryption_device {
    struct dm_dev *dev;
    // symmetric key algorithm instance
    struct crypto_aead *tfm;
    // persist key
    char *key;
    // not sure what this is, but it's needed to create a clone of the bio
    struct bio_set bs;
    // array of hashes of each sector
    char* checksums;
};

// per bio private data
struct bio_data {
    // maintain information of original bio before iteration
    struct bio *base_bio;
    struct bvec_iter bi_iter;
    struct crypto_wait wait;
    struct encryption_device *device;

};

void cleanup(struct encryption_device *device) {
    if (device == NULL)
        return;
    if (device->checksums)
        kvfree(device->checksums);
    if (device->tfm)
        crypto_free_aead(device->tfm);
    bioset_exit(&device->bs);
    kfree(device);
}

static void encryption_destructor(struct dm_target *ti) {
    struct encryption_device *device = ti->private;
    printk(KERN_INFO "encryption destructor called\n");
    if (device == NULL)
        return;
    dm_put_device(ti, device->dev);
    cleanup(device);
}

static int encryption_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    int ret;
    struct encryption_device *device;
    printk(KERN_INFO "encryption constructor called\n");

    // TODO: look into vzalloc
    device = kmalloc(sizeof(struct encryption_device), GFP_KERNEL);
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

    // TODO: Change flag to CRYPTO_ALG_ASYNC to only allow for synchronous calls and find out what CRYPTO_ALG_ALLOCATES_MEMORY does
    device->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(device->tfm)) {
        ti->error = "Cannot allocate transform";
        ret = -ENOMEM;
        goto out;
    }
    printk(KERN_INFO "transform properly initialized\n");

    // tag size
    crypto_aead_setauthsize(device->tfm, AES_GCM_AUTH_SIZE);

    device->key = "1234567890123456";
    if (crypto_aead_setkey(device->tfm, device->key, KEY_SIZE)) {
        ti->error = "Key could not be set";
        ret = -EAGAIN;
        goto out;
    }
    printk(KERN_INFO "key properly initialized\n");

    bioset_init(&device->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);

    device->checksums = kvmalloc_array(ti->len, AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE, GFP_KERNEL | __GFP_ZERO);
    if (!device->checksums) {
        ti->error = "Cannot allocate checksums";
        ret = -ENOMEM;
        goto out;
    }

    // TODO: Look into putting hashes inside of here too and some rounding?
    ti->per_io_data_size = sizeof(struct bio_data);
    ti->private = device;

    return 0;

out:
    cleanup(device);
    return ret;
}

static inline unsigned char *checksum_index(struct bio_data *bio_data, sector_t index) {
    return &bio_data->device->checksums[index * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE)];
}

static inline unsigned char *iv_index(struct bio_data *bio_data, sector_t index) {
    return &bio_data->device->checksums[index * (AES_GCM_AUTH_SIZE + AES_GCM_IV_SIZE) + AES_GCM_AUTH_SIZE];
}


static int enc_or_dec_bio(struct bio_data *bio_data, int enc_or_dec) {
    int ret;
    struct bio_vec bv;
    uint64_t curr_sector;
    struct aead_request *req;
    req = aead_request_alloc(bio_data->device->tfm, GFP_KERNEL);
    if (!req) {
        printk(KERN_ERR "aead request allocation failed");
        aead_request_free(req);
        ret = -ENOMEM;
        goto exit;
    }
    while (bio_data->bi_iter.bi_size) {
        curr_sector = bio_data->bi_iter.bi_sector;
        DECLARE_CRYPTO_WAIT(wait);
        bv = bio_iter_iovec(bio_data->base_bio, bio_data->bi_iter);
        switch (enc_or_dec) {
            case READ:
                if (*checksum_index(bio_data, curr_sector) == 0) {
                return 0;
            }
                break;
            default:
                break;
        }
        memcpy(iv_index(bio_data, curr_sector), "123456789012", AES_GCM_IV_SIZE);
        struct scatterlist sg[4];
        sg_init_table(sg, 4);
        sg_set_buf(&sg[0], &curr_sector, sizeof(uint64_t));
        sg_set_buf(&sg[1], iv_index(bio_data, curr_sector), AES_GCM_IV_SIZE);
        sg_set_page(&sg[2], bv.bv_page, SECTOR_SIZE, bv.bv_offset);
        sg_set_buf(&sg[3], checksum_index(bio_data, curr_sector), AES_GCM_AUTH_SIZE);

        // /* AEAD request:
        //  *  |----- AAD -------|------ DATA -------|-- AUTH TAG --|
        //  *  | (authenticated) | (auth+encryption) |              |
        //  *  | sector_LE |  IV |  sector in/out    |  tag in/out  |
        //  */


        aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
        // sector + iv size
        aead_request_set_ad(req, sizeof(uint64_t) + AES_GCM_IV_SIZE);
        switch (enc_or_dec) {
            case WRITE:
                aead_request_set_crypt(req, sg, sg, SECTOR_SIZE, iv_index(bio_data, curr_sector));
                ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
                break;
            case READ:
                aead_request_set_crypt(req, sg, sg, SECTOR_SIZE + AES_GCM_AUTH_SIZE, iv_index(bio_data, curr_sector));
                ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
                break;
        }

        if (ret) {
            if (ret == -EBADMSG) {
                printk(KERN_ERR "invalid integrity check - triggering kernel panic");
                panic("Kernel panic: integrity check failed during decryption (bad message)");
            }
            else {
                printk(KERN_ERR "encryption/decryption failed - triggering kernel panic");
                panic("Kernel panic: encryption/decryption operation failed");
            }
            aead_request_free(req);
            goto exit;
        }
        bio_advance_iter(bio_data->base_bio, &bio_data->bi_iter, SECTOR_SIZE);
    }
    aead_request_free(req);
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

struct bio* shallow_bio_clone(struct encryption_device *device, struct bio *bio_src) {
    struct bio *clone;
    clone = bio_alloc_clone(bio_src->bi_bdev, bio_src, GFP_NOIO, &device->bs);
    if (!clone) {
        printk(KERN_INFO "Could not create clone");
        return NULL;
    }

    clone->bi_iter.bi_sector = bio_src->bi_iter.bi_sector;
    return clone;
}

static int encryption_map(struct dm_target *ti, struct bio *bio)
{
    struct encryption_device *device = ti->private;
    struct bio *clone;
    struct bio_data *bio_data;

    bio_set_dev(bio, device->dev->bdev);
    // fetch data specific to bio
    bio_data = dm_per_bio_data(bio, ti->per_io_data_size);
    // initialize fields for bio data that will be useful for encryption
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
                //printk(KERN_INFO "encryption done properly\n");

                // Reset to the original beginning values of the bio, otherwise nothing will be written
                bio->bi_iter.bi_sector = original_sector;
                bio->bi_iter.bi_size = original_size;
                bio->bi_iter.bi_idx = original_idx;

                return DM_MAPIO_REMAPPED;
            case READ:
                // Create a clone that calls decrypt_at_end_io when the bio_data returns with actual read data
                clone = shallow_bio_clone(device, bio);
                if (!clone) {
                    printk(KERN_INFO "Could not create clone");
                    return 1;
                }
                clone->bi_private = bio_data;
                clone->bi_end_io = decrypt_at_end_io;
                bio_set_dev(clone, device->dev->bdev);
                clone->bi_opf = bio->bi_opf;
                clone->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

                // Submit the clone, triggering end_io, where the read will actually have data and we can decrypt
                submit_bio_noacct(clone);
                //printk(KERN_INFO "read properly initialized\n");

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

int __init dm_encryption_init(void) {
    int r = dm_register_target(&encryption_target);
    printk(KERN_INFO "encryption module loaded\n");

    if (r < 0)
        DMERR("register failed %d", r);
    return r;
}

void dm_encryption_exit(void) {
    dm_unregister_target(&encryption_target);
    printk(KERN_INFO "encryption module unloaded\n");
}

module_init(dm_encryption_init);
module_exit(dm_encryption_exit);

MODULE_LICENSE("GPL");