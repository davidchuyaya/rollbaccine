#include <linux/module.h>
#include <linux/init.h>
#include <linux/device-mapper.h>
#include <linux/bio.h>

#define DM_MSG_PREFIX "rollbaccine"

// Data attached to each bio
struct rollbaccine_device {
	struct dm_dev *dev;
};

static int rollbaccine_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
	printk(KERN_INFO "Rollbaccine constructor called\n");

	struct rollbaccine_device *rbd = kmalloc(sizeof(struct rollbaccine_device), GFP_KERNEL);
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

static void rollbaccine_destructor(struct dm_target *ti) {
	printk(KERN_INFO "Rollbaccine destructor called\n");

	struct rollbaccine_device *rbd = ti->private;
	dm_put_device(ti, rbd->dev);
	kfree(rbd);
}

static int rollbaccine_map(struct dm_target *ti, struct bio *bio) {
	printk(KERN_INFO "Rollbaccine map called\n");

	struct rollbaccine_device *rbd = ti->private;

	bio_set_dev(bio, rbd->dev->bdev);
	bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

    switch (bio_op(bio)) {
        case REQ_OP_READ:
            printk(KERN_INFO "Read request\n");
            break;
        case REQ_OP_WRITE:
			printk(KERN_INFO "Write request\n");
			break;
		case REQ_OP_FLUSH:
			printk(KERN_INFO "Flush request\n");
			break;
        case REQ_OP_DISCARD:
            printk(KERN_INFO "Discard request\n");
            break;
        default:
            break;
    }
        
	return DM_MAPIO_REMAPPED;
}

static struct target_type rollbaccine_target = {
	.name = "rollbaccine",
	.version = {0, 1, 0},
	.features = DM_TARGET_INTEGRITY, // TODO: Figure out what this means
	.module = THIS_MODULE,
	.ctr = rollbaccine_constructor,
	.dtr = rollbaccine_destructor,
	.map = rollbaccine_map,
};

int __init dm_rollbaccine_init(void) {
    int r = dm_register_target(&rollbaccine_target);
	printk(KERN_INFO "Rollbaccine module loaded\n");

    if (r < 0) DMERR("register failed %d", r);

    return r;
}

void dm_rollbaccine_exit(void) { 
	dm_unregister_target(&rollbaccine_target);
    printk(KERN_INFO "Rollbaccine module unloaded\n");
}

module_init(dm_rollbaccine_init);
module_exit(dm_rollbaccine_exit);

MODULE_LICENSE("GPL");
