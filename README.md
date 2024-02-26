# Rollbaccine
Linux kernel module using 2f+1 state machines to prevent rollback attacks in CVMs.
We will use a device mapper to intercept blocks from the file system to the device driver. Our device mapper will:
1. Encrypt and decrypt all sectors (512 bytes, defined by hardware).
2. Check integrity on all sectors, forcing recovery on failure. The checksums are kept in memory.
3. Replicate all writes to `2f+1` replicas and wait for `f+1` responses before returning from fsync. The leader of this "consensus" is elected through a simple protocol; reconfiguration is performed through CCF.

See how to set up a development environment [here](development/SETUP.md).

### The old implementation
See [disk-tees](https://github.com/davidchuyaya/disk-tees) for the previous implementation using FUSE. There are multiple problems with this approach:
1. All files reside in memory (or swap) since integrity is checked on swap, so rollbacks will cause a panic. This means that recovery is slow even if there are no rollbacks: a restarting system has to fetch all its files from the replicas.
2. [FUSE is slow](https://www.usenix.org/system/files/conference/fast17/fast17-vangoor.pdf), even after optimizations. This is mainly because of the user-kernel page switching (FUSE code runs in user mode).
3. FUSE intercepts file operations. This poses a problem for replication; either we allow multithreaded writes or not. If writes are single threaded, throughput is low. If writes are multithreaded, we have to figure out how this works with replication. We could do something like "only totally order fsyncs and directory operations", but then we'd need to have a lock per file, track the latest write to a file, etc. Metadata blows up.