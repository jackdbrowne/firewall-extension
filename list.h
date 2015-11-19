#ifndef _LIST_H
#define _LIST_H

#include <linux/list.h>

struct rules_list {
  int port_no;
  char* program;
  struct list_head list;
};

/* 
 * Create an empty message_list struct, containing a buffer of BUFFERSIZE
 */
// int init_rules (struct rules_list *lst);

/* 
 * Add a new message 'msg' of size 'len' to the back of the list
 */
int push_rule (struct list_head *lst, int port_no, char* program, size_t len);

/*
 * Create a list from a set of rules in format <port> <program>\n
 * len is the total length of the rules string
 * Return a pointer to a list head, will be allocated in this method
 * On error, return NULL
 */
struct list_head* set_rules (char *rules, size_t len);

/*
 * Check whether a given rule exists in the list lst
 */
int contains_rule (struct list_head *lst, int port_no, char* program);

/* 
 * Deallocate all items in the list and then the list itself 
 */
void destroy_rules (struct list_head *lst);

/*
 * Print all of the rules into /var/log/kern.log
 * In the format Firewall rule: <port> <program>
 */
void printk_rules (struct list_head *lst);
#endif // _LIST_H
