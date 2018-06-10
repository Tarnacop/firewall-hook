/**
 * @file firewallExtension.c
 * @author Alexandru Blinda
 * @date December 1, 2017
 * @version 0.1
 * @brief File that defines methods declared in firewallExtension.h file
 * Part of exercise 4 of Operating Systems module.
**/
#include <linux/init.h> /* Used for the macros __init and __exit */
#include <linux/module.h> /* Contains functions for loading LKMs into kernel */
#include <linux/kernel.h> /* Functions, types, macros for the kernel */
#include <linux/proc_fs.h> /* Linux file support for proc files */
#include <asm/uaccess.h> /* Functions for communicating between user and kernel space */
#include <linux/slab.h> /* kmall and kfree */
#include <linux/list.h> /* Kernel list header */
#include <linux/netfilter.h> /* Needed for netfilter operations */
#include <linux/netfilter_ipv4.h> /* Specifically for ipv4 */
#include <linux/skbuff.h> /* Socket buffer */
#include <linux/compiler.h>
#include <net/tcp.h> /* TCP headers */
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/string.h>

#include "firewallExtension.h"

/* Declare author and other init stuff */
MODULE_AUTHOR ("Alexandru Blinda");
MODULE_DESCRIPTION("Simple kernel driver that extends the firewall rules");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

static int is_device_open;
static struct proc_dir_entry* proc_file;
static struct firewall_list_rules* firewall_rules;
static struct firewall_list_rules* aux_rules;
static int reset_rules;

DECLARE_RWSEM(rules_sem); /* Semaphore to protect list access */

static int __init firewall_extension_init(void) {

    /* Create the /proc file */
    proc_file = proc_create_data(PROC_ENTRY_FILENAME, 0644, NULL, &proc_fops, NULL);

    if(proc_file == NULL) {

        printk(KERN_ALERT "ERROR: Could not initialise /proc/%s\n", PROC_ENTRY_FILENAME);
        return -EFAULT;
    }

    printk(KERN_INFO "/proc/%s created\n", PROC_ENTRY_FILENAME);

    /* Try and regist the firewall hook */
    if(nf_register_hook(&firewall_extension_ops)) {
        printk(KERN_ALERT "%s: Firewall extension could not be registered\n", PROC_ENTRY_FILENAME);
        remove_proc_entry(PROC_ENTRY_FILENAME, NULL); /* Free resources if it is not possible */
        return -EFAULT;
    }

    /* Try and allocate space to store firewall rules */
    firewall_rules = kmalloc(sizeof(struct firewall_list_rules), GFP_KERNEL);
    /* If it failed, free memory and exit */
    if(!firewall_rules) {
        printk(KERN_ALERT "%s: Could not allocate memory for firewall rules\n", PROC_ENTRY_FILENAME);
        nf_unregister_hook(&firewall_extension_ops);
        remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
        return -EFAULT;
    }

    /* Initialise the list head */
    INIT_LIST_HEAD(&(firewall_rules->list));
    is_device_open = 0;
    reset_rules = 0;

    printk(KERN_INFO "%s: Firewall extension module loaded\n", PROC_ENTRY_FILENAME);
    return ESUCCESS;
}

static void __exit firewall_extension_exit(void) {

    /* Free the firewall rules list */
    struct list_head* cursor;
    struct list_head* tmp_head;
    struct firewall_list_rules* tmp;
    list_for_each_safe(cursor, tmp_head, &(firewall_rules->list)){
		 tmp = list_entry(cursor, struct firewall_list_rules, list);
		 list_del(cursor);
		 kfree(tmp);
	}
    kfree(firewall_rules);

     /* Unregister the hook first */
    nf_unregister_hook(&firewall_extension_ops);
    printk(KERN_INFO "Firewall extensions module unloaded\n");

    /* Remove the proc entry from the kernel */
    remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
    printk(KERN_INFO "/proc/%s removed\n", PROC_ENTRY_FILENAME);
}

static int procfs_open(struct inode* inodep, struct file* filep) {

    /* If the device is already opened, return try again */
    if(is_device_open == 1) {
        return -EAGAIN;
    }

    /* Try and allocate memory for auxiliary rules */
    aux_rules = kmalloc(sizeof(struct firewall_list_rules), GFP_KERNEL);
    /* If we could not allocate memory, exit */
    if(!aux_rules) {
        return -EFAULT;
    }
    /* Try and increment the number of processes using this device */
    /* Useful because the os checks for this if we try and remove the driver */
    if(try_module_get(THIS_MODULE) == 0) {
        kfree(aux_rules);
        return -EAGAIN;
    }
    /* Device open ++ */
    is_device_open++;

    printk(KERN_INFO "%s opened\n", PROC_ENTRY_FILENAME);
    /* Initialise auxiliary rules head */
    INIT_LIST_HEAD(&(aux_rules->list));
    return ESUCCESS;
}

static ssize_t procfs_read(struct file* filep, char __user* buffer, size_t length, loff_t* offset) {

    struct firewall_list_rules* tmp = NULL;
    down_read(&rules_sem); /* Lock for reading */
    list_for_each_entry(tmp, &(firewall_rules->list), list) {
        printk(KERN_INFO "Firewall rule: %s %s\n", tmp->port_number, tmp->filename);
    }
    up_read(&rules_sem); /* Unlock reading */
    return ESUCCESS;
}

static ssize_t procfs_write(struct file* filep, const char __user* buffer, size_t length, loff_t* offset) {

    reset_rules = 0; /* Start with reset_rules = 0; */
    /* Check that we do not get buffer overflow. -1 because we want to keep space for \0 */
    if(length > RULE_BUFFER_SIZE - 1) {
        return -EFAULT;
    }

    /* Allocate memory as much as length (+1 to keep space for \0). This is at most RULE_BUFFER_SIZE */
    char* rule_buffer = kmalloc((length + 1) * sizeof(char), GFP_KERNEL);
    /* Could not allocate memory */
    if(!rule_buffer) {
        return -EFAULT;
    }

    /* Copy data from user space */
    /* If it did not succeed, return error */
    if(copy_from_user(rule_buffer, buffer, length)) {
        kfree(rule_buffer);
        return -EFAULT;
    }

    /* We ensure string termination */
    rule_buffer[length] = '\0';

    /* We can assume only well-formed rules are written */
    /* Rule is of form "<port> <program>" */
    int index = 0;
    char* tmp_char = rule_buffer; /* First it will denote the port */
    /* Until we have not hit the space, go */
    while((rule_buffer[index] != ' ') && (rule_buffer[index] != '\0')) {
        index++;
    }

    rule_buffer[index] = '\0'; /* Now we can use string manipulation */

    /* If the port is bigger than the valid port size, free resources and return inval */
    if(strlen(tmp_char) > PORT_NUMBER_SIZE) {
        kfree(rule_buffer);
        return -EINVAL;
    }
    char* port_number = kmalloc((strlen(tmp_char) + 1) * sizeof(char), GFP_KERNEL);
    /* If we could not allocate memory, free resources and return fault */
    if(!port_number) {
        kfree(rule_buffer);
        return -EFAULT;
    }
    /* Copy from aux to container */
    strcpy(port_number, tmp_char);

    index++; /* Start with the first index after the space */
    tmp_char = &rule_buffer[index]; /* Now we know we have a valid string and we can use */
    /* If the path size is bigger than the max path size, free resources and return inval */
    if(strlen(tmp_char) > PATH_SIZE) {
        kfree(rule_buffer);
        kfree(port_number);
        return -EINVAL;
    }
    char* exe_path = kmalloc((strlen(tmp_char) + 1) * sizeof(char), GFP_KERNEL);
    /* If we could not allocate memory, free resources and return fault */
    if(!exe_path) {
        kfree(rule_buffer);
        kfree(port_number);
        return -EFAULT;
    }
    /* Copy from aux to container */
    strcpy(exe_path, tmp_char);

    /* Try and allocate space for our struct */
    struct firewall_list_rules* new_rule = kmalloc(sizeof(struct firewall_list_rules), GFP_KERNEL);
    /* If we could not allocate memory, free and return fault */
    if(!new_rule) {
        kfree(rule_buffer);
        kfree(port_number);
        kfree(exe_path);
        return -EFAULT;
    }
    /* If we did manage to allocate memory, we build the new rule */
    new_rule->port_number = port_number;
    new_rule->filename = exe_path;
    /* Init the list head */
    INIT_LIST_HEAD(&(new_rule->list));
    /* Add the node to the existing list */
    list_add_tail(&(new_rule->list), &(aux_rules->list));

    reset_rules = 1; /* End with reset_rules = 1 if everything worked fine */
    kfree(rule_buffer); /* Free the rule_buffer */
    return length;
}

static int procfs_release(struct inode* inodep, struct file* filep) {

    /* If we need to reset the rules of the firewall */
    if(reset_rules == 1) {

        /* Override the old rules with the new rules */
        struct firewall_list_rules* tmp_rules = firewall_rules;
        down_write(&rules_sem); /* Lock for writing */
        firewall_rules = aux_rules;
        up_write(&rules_sem); /* Unlock */

        /* Free the tmp_rules - old firewall rules */
        struct list_head* cursor;
        struct list_head* tmp_head;
        struct firewall_list_rules* tmp;
        list_for_each_safe(cursor, tmp_head, &(tmp_rules->list)) {
            tmp = list_entry(cursor, struct firewall_list_rules, list);
            list_del(cursor);
            kfree(tmp);
        }
        kfree(tmp_rules);

        reset_rules = 0;
    } else {

        /* Free the aux_rules because we do not need them */
        struct list_head* cursor;
        struct list_head* tmp_head;
        struct firewall_list_rules* tmp;
        list_for_each_safe(cursor, tmp_head, &(aux_rules->list)) {
            tmp = list_entry(cursor, struct firewall_list_rules, list);
            list_del(cursor);
            kfree(tmp);
        }
        kfree(aux_rules);
    }
    /* We are exitting so is_device_open goes to 0 */
    is_device_open--;
    /* The variable in OS also goes down */
    module_put(THIS_MODULE);
    printk(KERN_INFO "%s released\n", PROC_ENTRY_FILENAME);
    return ESUCCESS;
}

static unsigned int firewall_extension_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {

    /* For firewall */
    struct tcphdr* tcp;
    struct tcphdr _tcph;
    struct sock* sk;
    struct mm_struct* mm;

    /* For finding path */
    struct path path;
    pid_t mod_pid;
    struct dentry* proc_dentry;
    struct dentry* parent;

    /* To store information in order to build the filename and everything else */
    char cmdline_file[CMDLINE_BUFFER_SIZE];
    memset(cmdline_file, 0, sizeof(cmdline_file));
    char* full_filename;
    char temp_filename[MAX_FILE_NAME_SIZE + 1]; /* 256 max size + 1 for \0 */
    memset(temp_filename, 0, sizeof(temp_filename));
    char tcp_dest_port[PORT_NUMBER_SIZE + 1]; /* 5 max size + 1 for \0 */
    memset(tcp_dest_port, 0, sizeof(tcp_dest_port));

    /* Take socket */
    sk = skb->sk;
    /* If socket is empty, accept the connection and let the os deal with it */
    if(!sk) {
        return NF_ACCEPT;
    }

    /* If protocol is not tcp, accept the connection and let the os deal with it */
    if(sk->sk_protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    /* Get the TCP header for the packet */
    tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
    /* If we could not get the tcp header, accept and let the os deal with it */
    if (!tcp) {
        return NF_ACCEPT;
    }

    /* If we have a SYN segment of TCP (part of the three-way handshake) */
    if(tcp->syn) {

        /* Test if this tcp connection is for user space */
        if(in_irq() || in_softirq() || !(mm = get_task_mm(current))) {
            return NF_ACCEPT;
        }

        /* Delete data used to free memory */
        mmput(mm);

        struct firewall_list_rules* tmp = NULL;

        /* Allocate space for filename */
        full_filename = kmalloc((PATH_SIZE + 1) * sizeof(char), GFP_KERNEL);
        if(!full_filename) {
            /* Treat like we could not compare it */
            tcp_done(sk);
            return NF_DROP;
        }
        /* Lock for reading to ensure the rules do not change until we check everything */
        int accept = 1;
        down_read(&rules_sem);
        list_for_each_entry(tmp, &(firewall_rules->list), list) {

            memset(full_filename, 0, (PATH_SIZE + 1) * sizeof(char));
            /* Save the destination port of the segment */
            sprintf(tcp_dest_port, "%d", htons(tcp->dest));
            /* If it is equal to the port from our rule */
            if(strcmp(tcp_dest_port, tmp->port_number) == 0) {

                /* Take the process id of the current process making outgoing packets */
                mod_pid = current->pid;

                /* Save the process cmd line in a buffer */
                snprintf(cmdline_file, CMDLINE_BUFFER_SIZE, "/proc/%d/exe", mod_pid);

                /* Take the path for that process */
                if(kern_path(cmdline_file, LOOKUP_FOLLOW, &path)) {
                    printk(KERN_ALERT "ERROR: Could not get dentry for %s!\n", cmdline_file);
                    up_read(&rules_sem); /* Do not forget to unlock before returning */
                    kfree(full_filename);
                    return -EFAULT;
                }

                /* Take the process path */
                proc_dentry = path.dentry;
                /* Save it in our file name */
                strcpy(full_filename, proc_dentry->d_name.name);
                /* Take the parent directory */
                parent = proc_dentry->d_parent;

                /* Go through all the parents until there are no parents left */
                while(parent->d_name.name[0] != '/') {
                    /* Copy the parent name into a temporary array */
                    strcpy(temp_filename, parent->d_name.name);
                    /* Add an ending / */
                    strcat(temp_filename, "/");
                    /* Concatenate it with our actual full_filename */
                    strcat(temp_filename, full_filename);
                    /* Copy the result in the full filename array */
                    strcpy(full_filename, temp_filename);
                    /* Reset the temporary array */
                    memset(temp_filename, 0, sizeof(temp_filename));
                    /* Move to the parent */
                    parent=parent->d_parent;
                }

                /* Once we exit, we need to do it one more time for the last part */
                strcpy(temp_filename, parent->d_name.name);
                strcat(temp_filename, full_filename);
                strcpy(full_filename, temp_filename);
                memset(temp_filename, 0, sizeof(temp_filename));

                /* Delete the path to free memory */
                path_put(&path);

                /* If the rule filename is the same as current process filename, accept the packet */
                if(strcmp(full_filename, tmp->filename) == 0) {

                    up_read(&rules_sem); /* Do not forget to unlock */
                    kfree(full_filename);
                    accept = 1;
                    return NF_ACCEPT;
                }

                /* Terminate connection imediately if it is not our filename */
                accept = 0;
            }
        }
        /* When we exit the reading, unlock */
        up_read(&rules_sem);
        kfree(full_filename);
        if(accept == 0) {

            tcp_done(sk);
            return NF_DROP;
        }
        return NF_ACCEPT;
    }
    return NF_ACCEPT;
}

module_init(firewall_extension_init);
module_exit(firewall_extension_exit);

