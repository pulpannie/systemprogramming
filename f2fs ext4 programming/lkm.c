#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

// proc file system entry
// author: Hyokyung
// date: 2020.10.31
#define PROC_DIRNAME "myproc"
#define PROC_FILENAME "myproc"
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file;

// exported symbol from block/blk-core.c
// author: Hyokyung
// date: 2020.10.31
#define MAX_Q 1024
extern struct q_item bio_queue[MAX_Q];
extern int idx_next;

// queue converted to string
// author: Hyokyung
// date: 2020.10.31
char STR_QUEUE[MAX_Q][80];

// write to proc file system entry.
// copy bio_queue to STR_QUEUE as a human-readable form
// author: Hyokyung
// date: 2020.10.31
static ssize_t my_write(struct file *file, const char __user * user_buffer, size_t count, loff_t *ppos)
{
	int idx, i;
	for (idx = idx_next, i = 0; i < MAX_Q; i++){
		sprintf(STR_QUEUE[i],
				"File System : %-5s  ||  Time: %11u  ||  Block No. : %11lld\n",
				bio_queue[idx].fs, bio_queue[idx].time, bio_queue[idx].block_n);
		idx = (idx + 1) % MAX_Q;
	}
	return count;
}

// read from proc file system entry.
// copy STR_QUEUE to user buffer
// author: Jiseong
// date: 2020.11.1
static ssize_t my_read(struct file *filep, char __user * user_buffer, size_t len, loff_t *ppos)
{
	ssize_t cnt = sizeof(STR_QUEUE);
	ssize_t ret;
	
	// ret is amount of data not written
	ret = copy_to_user(user_buffer, STR_QUEUE, cnt);
	printk(KERN_INFO "ppos: %lld", *ppos);
	*ppos += cnt - ret;
	printk(KERN_INFO "ppos: %lld", *ppos);
	if (*ppos > cnt){
		return 0;
	} else {
		return cnt;
	}
}

// open file for read or write
// author: Jiseong
// date: 2020.10.31
static int my_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "SIMPLE MODULE OPEN!\n");
	return 0;
}

// define file operations on proc file system
// author: Jiseong
// date: 2020.11.1
static const struct file_operations myproc_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = my_write,
	.read = my_read,
};


// create proc file system entry
// author: Jiseong
// date: 2020.10.31
static int __init simple_init(void)
{
	printk(KERN_INFO "Simple Module Init! \n");

	proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	proc_file = proc_create(PROC_FILENAME, 0600, proc_dir, &myproc_fops);
	return 0;
}

// delete proc file system entry
// author: Jiseong
// date: 2020.10.31
static void __exit simple_exit(void)
{
	printk(KERN_INFO "Simple Module Exit! \n");

	proc_remove(proc_file);
	proc_remove(proc_dir);
	return;
}

module_init(simple_init);
module_exit(simple_exit);

MODULE_AUTHOR("Hyokyung, Jiseongg");
MODULE_DESCRIPTION("File system profiling module");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");


