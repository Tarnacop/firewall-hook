/**
 * @file firewallExtension.c
 * @author Alexandru Blinda
 * @date December 1, 2017
 * @version 0.1
 * @brief File that declares methods defined in firewallExtension.c file
 * Part of exercise 4 of Operating Systems module.
**/
#ifndef FIREWALLEXTENSION_H
#define FIREWALLEXTENSION_H

#define PROC_ENTRY_FILENAME "firewallExtension"
#define ESUCCESS 0

#define PORT_NUMBER_SIZE 5 /* (65535) max port */
#define PATH_SIZE 4096 /* Max path size in linux is 4096 bytes */
#define MAX_FILE_NAME_SIZE 256 /* Max file name is 256 bytes */
#define CMDLINE_BUFFER_SIZE 267 /* Max file name is 256 + 10 for /proc//exe + 1 for \0*/
#define RULE_BUFFER_SIZE 4103 /* Max path size is 4096 + 1 byte space + 1 byte for ending \0 + 5 max port size for 65535 */

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

/* Prototype files for proc file ops */

static int __init firewall_extension_init(void);
static void __exit firewall_extension_exit(void);
static int procfs_open(struct inode*, struct file*);
static int procfs_release(struct inode*, struct file*);
static ssize_t procfs_read(struct file*, char __user*, size_t, loff_t*);
static ssize_t procfs_write(struct file*, const char __user*, size_t, loff_t*);

/* Declare file operations for this proc file */
static struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .read = procfs_read,
    .write = procfs_write,
    .open = procfs_open,
    .release = procfs_release
};

/* Prototype for firewall extension ops */
static unsigned int firewall_extension_hook(void*, struct sk_buff*, const struct nf_hook_state*);

static struct nf_hook_ops firewall_extension_ops = {
    .hook = firewall_extension_hook,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
    .hooknum = NF_INET_LOCAL_OUT
};

/* Struct for holding the rules */

struct firewall_list_rules {

    char* port_number;
    char* filename;
    /* Kernel list implementation */
    struct list_head list;
};

#endif
