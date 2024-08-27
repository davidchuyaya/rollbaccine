#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/init.h>
#include <linux/module.h>

#define DM_MSG_PREFIX "passthrough"

// Data attached to each bio
struct passthrough_device {
    struct dm_dev *dev;
};

static int passthrough_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    printk(KERN_INFO "passthrough constructor called\n");

    struct passthrough_device *rbd = kmalloc(sizeof(struct passthrough_device), GFP_KERNEL);
    if (rbd == NULL) {
        ti->error = "Cannot allocate context";
        return -ENOMEM;
    }

    // Get the device from argv[0] and store it in rbd->dev
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &rbd->dev)) {
        ti->error = "Device lookup failed";
        kfree(rbd);
        return -EINVAL;
    }

    ti->private = rbd;

    return 0;
}

static void passthrough_destructor(struct dm_target *ti) {
    printk(KERN_INFO "passthrough destructor called\n");

    struct passthrough_device *rbd = ti->private;
    dm_put_device(ti, rbd->dev);
    kfree(rbd);
}

static int passthrough_map(struct dm_target *ti, struct bio *bio) {
    // printk(KERN_INFO "passthrough map called\n");

    struct passthrough_device *rbd = ti->private;

    bio_set_dev(bio, rbd->dev->bdev);
    bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    // Print flags on write
    // if (bio_data_dir(bio) == WRITE) {
    //     printk(KERN_INFO "WRITE to sector: %llu, flags: %u, opf: %u", bio->bi_iter.bi_sector, bio->bi_flags, bio->bi_opf);
    // }
    // printk(KERN_INFO "not WRITE to sector: %llu, flags: %u, opf: %u", bio->bi_iter.bi_sector, bio->bi_flags, bio->bi_opf);

    return DM_MAPIO_REMAPPED;
}

static struct target_type passthrough_target = {
    .name = "passthrough",
    .version = {0, 1, 0},
    .features = DM_TARGET_INTEGRITY,  // TODO: Figure out what this means
    .module = THIS_MODULE,
    .ctr = passthrough_constructor,
    .dtr = passthrough_destructor,
    .map = passthrough_map,
};

int __init dm_passthrough_init(void) {
    int r = dm_register_target(&passthrough_target);
    printk(KERN_INFO "passthrough module loaded\n");

    if (r < 0) DMERR("register failed %d", r);

    return r;
}

void dm_passthrough_exit(void) {
    dm_unregister_target(&passthrough_target);
    printk(KERN_INFO "passthrough module unloaded\n");
}

module_init(dm_passthrough_init);
module_exit(dm_passthrough_exit);

MODULE_LICENSE("GPL");
