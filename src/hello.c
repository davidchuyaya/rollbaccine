#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device-mapper.h>
#include <linux/bio.h>

static int rollbaccine_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
	printk(KERN_INFO "Rollbaccine constructor called\n");
	return 0;
}

static int rollbaccine_map(struct dm_target *ti, struct bio *bio) {
	printk(KERN_INFO "Rollbaccine map called\n");

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
            return DM_MAPIO_KILL;
    }
        
	return DM_MAPIO_REMAPPED;
}

static struct target_type rollbaccine_target = {
	.name = "rollbaccine",
	.version = {0, 1, 0},
	.features = DM_TARGET_NOWAIT, // TODO: Figure out what this means
	.module = THIS_MODULE,
	.ctr = rollbaccine_constructor,
	.map = rollbaccine_map,
};
module_dm(rollbaccine);

MODULE_LICENSE("GPL");
