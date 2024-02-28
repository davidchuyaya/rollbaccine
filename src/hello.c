#include <linux/module.h>
#include <linux/init.h>
#include <linux/device-mapper.h>
#include <linux/bio.h>

#define DM_MSG_PREFIX "rollbaccine"

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
	.features = DM_TARGET_INTEGRITY, // TODO: Figure out what this means
	.module = THIS_MODULE,
	.ctr = rollbaccine_constructor,
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
