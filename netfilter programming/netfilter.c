#include <asm/uaccess.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/proc_fs.h>
#include <linux/tcp.h>
#include <linux/byteorder/generic.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/string.h>

#define PROC_DIR "group3"
#define RULE_ADD "add"
#define RULE_DEL "del"
#define RULE_SHOW "show"
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file_add;
static struct proc_dir_entry *proc_file_del;
static struct proc_dir_entry *proc_file_show;

int idx, i;

#define ADDBUF_SZ 10  // used in rule_add function
#define DELBUF_SZ 5   // used in rule_del function
#define SERV_ADDR "192.168.56.4" //used in netfilter hook functions


/** rule data structures
 * author: Jiseong
 * date: 2020.12.09
 */
typedef enum {
	RINVAL = -1,
	INBOUND,
	OUTBOUND,
	FORWARD,
	PROXY,
} rule_type;

typedef struct _nf_rule {
	rule_type rule;
	unsigned short s_port;
} nf_rule;

#define MAX_RULE 30
static nf_rule rules[MAX_RULE];
static char rules_str[MAX_RULE][20];
static int head = -1, tail = -1, rule_cnt = 0;

// e.g. 'F' -> FORWARD( == 2)
static rule_type rule_num(char c)
{
	// case-insensitive match
	switch(c) {
	case 'i':
	case 'I':
		return INBOUND;
	case 'o':
	case 'O':
		return OUTBOUND;
	case 'f':
	case 'F':
		return FORWARD;
	case 'p':
	case 'P':
		return PROXY;
	default:
		return RINVAL;	
	}
}

// e.g. 0 -> INBOUND
static const char* rule_name(int n)
{
	switch(n) {
	case 0:
		return "INBOUND";
	case 1:
		return "OUTBOUND";
	case 2:
		return "FORWARD";
	case 3:
		return "PROXY";
	default:
		return "RINVAL";
	}
}


// ip manipulation
unsigned int as_addr_to_net(char *str)
{
	unsigned char arr[4];
	sscanf(str, "%d.%d.%d.%d", &arr[0],&arr[1],&arr[2],&arr[3]);
	return *(unsigned int*)arr;
}

char *as_net_to_addr(unsigned int addr,char str[])
{
	char add[16];
	unsigned char a = ((unsigned char*)&addr)[0];
	unsigned char b = ((unsigned char*)&addr)[1];
	unsigned char c = ((unsigned char*)&addr)[2];
	unsigned char d = ((unsigned char*)&addr)[3];
	sprintf(add, "%u.%u.%u.%u", a,b,c,d);
	sprintf(str, "%s", add);
	return str;
}

/** netfilter hook functions
 * author: Hyokyung
 * date: 2020.12.11
 */
// inbound drop hook function
static unsigned int my_hook_inbound_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state * state){
	int proxy_check = 0;
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int saddr_ = ih->saddr;
	int daddr_ = ih->daddr;
	char tmp1[16], tmp2[16];
	char* saddr = as_net_to_addr(saddr_,tmp1);
	char* daddr = as_net_to_addr(daddr_,tmp2);
	u16 sport, dport;
	sport = ntohs(th->source);
	dport = ntohs(th->dest);
	if (!strcmp(saddr, SERV_ADDR)){
	 	for(idx = head, i = 0; i < rule_cnt; i++) {
	 		if (proxy_check == 0 &&
	 			rules[idx].rule == PROXY && rules[idx].s_port == sport)
	 			proxy_check = 1;

			if (rules[idx].rule == INBOUND && rules[idx].s_port == sport){
				printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n",
						"DROP(INBOUND)", ih->protocol, sport, dport, saddr, daddr,
						th->syn, th->fin, th->ack, th->rst);
				return NF_DROP;
			}
			idx = (idx + 1) % MAX_RULE;
		}
		/** if proxy rule exists for this port,
		 * my_hook_proxy_fn will print the log
		 */
		if (proxy_check == 0){
			printk(KERN_ALERT"%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n",
					"INBOUND", ih->protocol, sport, dport, saddr, daddr,
					th->syn, th->fin, th->ack, th->rst);
		}
	}
	return NF_ACCEPT;
}

// forward drop hook function
static unsigned int my_hook_forward_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state * state){
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int saddr_ = ih->saddr;
	int daddr_ = ih->daddr;
	char tmp1[16], tmp2[16];
	char* saddr = as_net_to_addr(saddr_,tmp1);
	char* daddr = as_net_to_addr(daddr_,tmp2);
	u16 sport, dport;
	sport = ntohs(th->source);
	dport = ntohs(th->dest);
	if (!strcmp(saddr, SERV_ADDR)){
	 	for(idx = head, i = 0; i < rule_cnt; i++) {
			if (rules[idx].rule == FORWARD && rules[idx].s_port == sport){
				printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n", 
						"DROP(FORWARD)", ih->protocol, sport, dport, saddr, daddr,
						th->syn, th->fin, th->ack, th->rst);
				return NF_DROP;
			}
			idx = (idx + 1) % MAX_RULE;
		}
		printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n", 
				"FORWARD", ih->protocol, sport, dport, saddr, daddr,
				th->syn, th->fin, th->ack, th->rst);
	}
	return NF_ACCEPT;
}

// outbound drop hook function
static unsigned int my_hook_outbound_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state * state){
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int saddr_ = ih->saddr;
	int daddr_ = ih->daddr;
	char tmp1[16], tmp2[16];
	char* saddr = as_net_to_addr(saddr_,tmp1);
	char* daddr = as_net_to_addr(daddr_,tmp2);
	u16 sport, dport;
	sport = ntohs(th->source);
	dport = ntohs(th->dest);
	if (!strcmp(daddr, SERV_ADDR) || !strcmp(saddr, SERV_ADDR)){
	 	for(idx = head, i = 0; i < rule_cnt; i++) {
			if (rules[idx].rule == OUTBOUND && rules[idx].s_port == dport){
				printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n", 
						"DROP(OUTBOUND)", ih->protocol, sport, dport, saddr, daddr,
						th->syn, th->fin, th->ack, th->rst);
				return NF_DROP;
			}
			idx = (idx + 1) % MAX_RULE;
		}
		printk(KERN_ALERT "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n",
				"OUTBOUND", ih->protocol, sport, dport, saddr, daddr,
				th->syn, th->fin, th->ack, th->rst);
	}
	return NF_ACCEPT;
}

// proxy hook function
static unsigned int my_hook_proxy_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state * state){
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int saddr_ = ih->saddr;
	int daddr_ = ih->daddr;
	char tmp1[16], tmp2[16];
	char* saddr = as_net_to_addr(saddr_,tmp1);
	char* daddr = as_net_to_addr(daddr_,tmp2);
	u16 sport, dport;
	sport = ntohs(th->source);
	dport = ntohs(th->dest);
	if (!strcmp(saddr, SERV_ADDR)){
	 	for(idx = head, i = 0; i < rule_cnt; i++) {
			if (rules[idx].rule == PROXY && rules[idx].s_port == sport){
				ih->daddr= as_addr_to_net("131.1.1.1");
				th->dest = htons(sport);
				saddr = as_net_to_addr(ih->saddr,tmp1);
				daddr = as_net_to_addr(ih->daddr,tmp2);
				sport = ntohs(th->source);
				dport = ntohs(th->dest);
				printk(KERN_ALERT"%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n",
						"PROXY(INBOUND)", ih->protocol, sport, dport, saddr, daddr,
						th->syn, th->fin, th->ack, th->rst);
				return NF_ACCEPT;
			}
			idx = (idx + 1) % MAX_RULE;
		}
	}
	return NF_ACCEPT;
}

/** structures for hooking point
 * author: Hyokyung
 * date: 2020.12.11
 */
// inbound
static struct nf_hook_ops my_nf_i_ops = {
	.hook = my_hook_inbound_fn,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FILTER
};
// forward
static struct nf_hook_ops my_nf_f_ops = {
	.hook = my_hook_forward_fn,
	.pf = PF_INET,
	.hooknum = NF_INET_FORWARD,
	.priority = NF_IP_PRI_FILTER
};
// outbound
static struct nf_hook_ops my_nf_o_ops = {
	.hook = my_hook_outbound_fn,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FILTER
};
// proxy
static struct nf_hook_ops my_nf_p_ops = {
	.hook = my_hook_proxy_fn,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FILTER+1
};


/** proc file system interface
 * author: Jiseong
 * date: 2020.12.10 ~ 2020.12.11
 */
// open: common function
static int my_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "proc file open: %s.\n",
			file->f_path.dentry->d_name.name);
	return 0;
}

// write to /proc/group3/add
static ssize_t rule_add(struct file *file,
		const char __user *user_buffer,
		size_t count,
		loff_t *ppos) 
{
	char buf[ADDBUF_SZ];
	unsigned short port_num;
	rule_type rule;

	if (copy_from_user(buf, user_buffer, ADDBUF_SZ)) {
		return -EFAULT;
	}

	// extract rule type and port number from user input
	rule = rule_num(buf[0]);
	sscanf(&buf[2], "%hu\n", &port_num);
	
	if (rule_cnt == MAX_RULE) {
		printk(KERN_INFO "proc file err: add: the number of rules reaches max.\n");
		return -EINVAL;
	} else {
		tail = (tail + 1) % MAX_RULE;
		rules[tail].rule = rule;
		rules[tail].s_port = port_num;
		rule_cnt++;
		
		head = (head == -1) ? 0 : head;
	}

	return count;
}

// write to /proc/group3/del
static ssize_t rule_del(struct file *file,
		const char __user *user_buffer,
		size_t count,
		loff_t *ppos) 
{
	char buf[DELBUF_SZ];
	int del_idx, idx, prev;

	if (copy_from_user(buf, user_buffer, DELBUF_SZ)) {
		return -EFAULT;
	}

	// extract target rule index to delete, from user input
	sscanf(&buf[0], "%d\n", &del_idx);
	
	if (del_idx >= rule_cnt || del_idx < 0) {
		printk(KERN_INFO "proc file err: no rule with index %d.\n", del_idx);
		return -EINVAL;
	}

	idx = (head + del_idx) % MAX_RULE;
	while (idx != head) {
		prev = (idx == 0) ? MAX_RULE - 1 : idx - 1;
		rules[idx] = rules[prev];
		idx = prev;
	}
	head = (head + 1) % MAX_RULE;
	rule_cnt--;

	return count;
}

// read from /proc/group3/show
static ssize_t rule_show(struct file *file,
		char __user *user_buffer,
		size_t len,
		loff_t *ppos) 
{
	int idx, i;
	ssize_t ret, cnt;

	// initialize `rules_str` buffer
	cnt = sizeof(rules_str);
	memset(rules_str, 0, cnt);

	// save string representation of `rules` to `rules_str`
	for (idx = head, i = 0; i < rule_cnt; i++) {
		sprintf(rules_str[i],
				"%2d: %8s  %5hu\n",
				i, rule_name(rules[idx].rule), rules[idx].s_port);
		idx = (idx + 1) % MAX_RULE;
	}
	
	// ret == `amount of bytes not copyed`
	ret = copy_to_user(user_buffer, rules_str, cnt);
	*ppos += cnt - ret;
	if (*ppos > cnt){
		return 0;
	} else {
		return cnt;
	}
}

/** operations for procfs entry
 * author: Jiseong
 * date: 2020.12.10 ~ 2020.12.11
 */
// /proc/group3/add
static const struct file_operations add_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = rule_add
};

// /proc/group3/del
static const struct file_operations del_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = rule_del
};

// /proc/group3/show
static const struct file_operations show_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.read = rule_show
};

static int __init simple_init(void)
{
	printk(KERN_INFO "Netfilter loaded!\n");

	proc_dir = proc_mkdir(PROC_DIR, NULL);
	proc_file_add = proc_create(RULE_ADD, 0600, proc_dir, &add_fops);
	proc_file_del = proc_create(RULE_DEL, 0600, proc_dir, &del_fops);
	proc_file_show = proc_create(RULE_SHOW, 0600, proc_dir, &show_fops);

	nf_register_hook(&my_nf_i_ops);
	nf_register_hook(&my_nf_f_ops);
	nf_register_hook(&my_nf_o_ops);
	nf_register_hook(&my_nf_p_ops);
	
	return 0;
}

static void __exit simple_exit(void)
{
	printk(KERN_INFO "==========================\n");
	printk(KERN_INFO "Unloading netfilter... \n");

	nf_unregister_hook(&my_nf_i_ops);
	nf_unregister_hook(&my_nf_f_ops);
	nf_unregister_hook(&my_nf_o_ops);
	nf_unregister_hook(&my_nf_p_ops);

	proc_remove(proc_file_add);
	proc_remove(proc_file_del);
	proc_remove(proc_file_show);
	proc_remove(proc_dir);

	printk(KERN_INFO "\tSuccessfully removed!\n");
	return;
}

module_init(simple_init);
module_exit(simple_exit);

MODULE_AUTHOR("Hyokyung, Jiseong");
MODULE_DESCRIPTION("custom firewall using netfilter");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
