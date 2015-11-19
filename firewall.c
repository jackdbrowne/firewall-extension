#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <list.h>

MODULE_AUTHOR ("Eike Ritter <E.Ritter@cs.bham.ac.uk>");
MODULE_DESCRIPTION ("Extensions to the firewall") ;
MODULE_LICENSE("GPL");

#define BUFFERSIZE 256
#define PROC_FILENAME "firewallExtension"

/* make IP4-addresses readable */
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

DEFINE_MUTEX(proc_lock);
static DECLARE_RWSEM(sem);

int proc_open;
struct list_head *firewall_rules;

struct nf_hook_ops *reg;

unsigned int FirewallExtensionHook (const struct nf_hook_ops *ops,
				    struct sk_buff *skb,
				    const struct net_device *in,
				    const struct net_device *out,
				    int (*okfn)(struct sk_buff *)) {

  struct tcphdr *tcp;
  struct tcphdr _tcph;
  struct sock *sk;

  sk = skb->sk;
  if (!sk) {
    printk (KERN_INFO "firewall: netfilter called with empty socket!\n");;
    return NF_ACCEPT;
  }

  if (sk->sk_protocol != IPPROTO_TCP) {
    printk (KERN_INFO "firewall: netfilter called with non-TCP-packet.\n");
    return NF_ACCEPT;
  }

  /* get the tcp-header for the packet */
  tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
  if (!tcp) {
    printk (KERN_INFO "Could not get tcp-header!\n");
    return NF_ACCEPT;
  }
  if (tcp->syn) {
    struct iphdr *ip;
    
    struct path path;
    char filename[BUFFERSIZE];
    char* filepath;
    char filepath_buff[BUFFERSIZE];
    	
    printk (KERN_INFO "firewall: Starting connection \n");
    ip = ip_hdr (skb);
    if (!ip) {
      printk (KERN_INFO "firewall: Cannot get IP header!\n!");
    } else {
      printk (KERN_INFO "firewall: Destination address = %u.%u.%u.%u\n", NIPQUAD(ip->daddr));
    }
    printk (KERN_INFO "firewall: destination port = %d\n", ntohs(tcp->dest)); 

    if (in_irq() || in_softirq()) {
      printk (KERN_INFO "Not in user context - retry packet\n");
      return NF_ACCEPT;
    }

    snprintf(filename, BUFFERSIZE, "/proc/%d/exe", current->pid);
    if (kern_path (filename, LOOKUP_FOLLOW, &path)) {
      printk (KERN_INFO "Could not get dentry for %s!\n", filename);
      return -EFAULT;
    }

    filepath = d_path(&path, &(filepath_buff[0]), BUFFERSIZE);

    down_read(&sem);
    if (contains_rule(firewall_rules, ntohs (tcp->dest), filepath)) {
      up_read(&sem);
      tcp_done (sk); /* terminate connection immediately */
      printk (KERN_INFO "Connection shut down\n");
      return NF_DROP;
    }
    up_read(&sem);
  }
  return NF_ACCEPT;	
}

ssize_t procfs_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset)
{
  char *rules;
  
  struct list_head *tmp, *tmp2;

  rules = kmalloc(count, GFP_KERNEL);
  if (rules == NULL)
    return -ENOMEM;
  if (copy_from_user(rules, buffer, count)) {
    kfree(rules);
    return -EFAULT;
  }

  tmp = firewall_rules;
  tmp2 = set_rules(rules, strlen(rules));
  down_write(&sem);
  firewall_rules = tmp2; 
  up_write(&sem);
  
  destroy_rules(tmp); /* Remove old rules */
  kfree(tmp); /* Free old list head */
  
  kfree(rules);

  return count;
}

long procfs_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
  switch(cmd) {
    case 0 : /* 'L' mode */
      down_read(&sem);
      printk_rules(firewall_rules);
      up_read(&sem);
      return 0;
      break;
    default :
      printk(KERN_INFO "Invalid ioctl command %i\n", cmd);
      return -EINVAL;
  }
}

int procfs_open(struct inode *inode, struct file *file)
{
  mutex_lock (&proc_lock);
  if (proc_open) {
    mutex_unlock (&proc_lock);
    return -EBUSY;
  }
  proc_open++;
  mutex_unlock (&proc_lock);
  try_module_get(THIS_MODULE);
  return 0;
}

int procfs_close(struct inode *inode, struct file *file)
{
  mutex_lock(&proc_lock);
  proc_open--;
  mutex_unlock(&proc_lock);
  module_put(THIS_MODULE);
  return 0;
}

EXPORT_SYMBOL (FirewallExtensionHook);

static struct nf_hook_ops firewall_ops = {
	      .hook     = FirewallExtensionHook,
	      .owner    = THIS_MODULE,
	      .pf       = PF_INET,
	      .priority = NF_IP_PRI_FIRST,
	      .hooknum  = NF_INET_LOCAL_OUT
};

static const struct file_operations proc_ops = {
        .owner          = THIS_MODULE,
        .write          = procfs_write,
        .open           = procfs_open,
        .release        = procfs_close,
        .unlocked_ioctl = procfs_ioctl,
};

int init_module(void)
{
  int errno;

  errno = nf_register_hook (&firewall_ops); /* register the hook */
  if (errno) {
    printk (KERN_INFO "Firewall extension could not be registered!\n");
    // A non 0 return means init_module failed; module can't be loaded.
    return errno;
  } 
  printk(KERN_INFO "Firewall extensions module loaded\n");

  INIT_LIST_HEAD(firewall_rules);
  printk(KERN_INFO "Initialising firewall rules\n");

  printk(KERN_INFO "firewall_rules %p, firewall_rules->next: %p, firewall_rules->prev: %p\n", firewall_rules, firewall_rules->next, firewall_rules->prev);

  printk(KERN_INFO "Adding test rules\n");
  push_rule(firewall_rules, 80, "/usr/lib/firefox/firefox", 25);

  printk(KERN_INFO "firewall_rules %p, firewall_rules->next: %p, firewall_rules->prev: %p\n", firewall_rules, firewall_rules->next, firewall_rules->prev);

  if(proc_create_data(PROC_FILENAME, 0644, NULL, &proc_ops, NULL) == NULL) {
    nf_unregister_hook(&firewall_ops);
    destroy_rules (firewall_rules);
    return -ENOMEM;
  }
  printk(KERN_INFO "/proc/%s created\n", PROC_FILENAME);

  proc_open = 0;
  return 0;
}


void cleanup_module(void)
{
  remove_proc_entry(PROC_FILENAME, NULL);
  printk(KERN_INFO "proc/%s removed\n", PROC_FILENAME);

  down_write(&sem);
  nf_unregister_hook (&firewall_ops); /* restore everything to normal */
  destroy_rules (firewall_rules);
  up_write(&sem);
  printk(KERN_INFO "Removed firewall rules\n");
  printk(KERN_INFO "Firewall extensions module unloaded\n");
}  
