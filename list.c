#include <list.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/list.h>

int push_rule (struct list_head *lst, int port_no, char* program, size_t len)
{
  struct rules_list *rule;

  /* create the rule node */
  rule = kmalloc(sizeof(struct rules_list), GFP_KERNEL);
  if (rule == NULL)
    return -EAGAIN;
  rule->program = kmalloc(len, GFP_KERNEL);
  if (rule->program == NULL){
    kfree(rule);
    return -EAGAIN;
  }

  INIT_LIST_HEAD(&rule->list);
  rule->port_no = port_no;
  strncpy(rule->program, program, len);
  list_add_tail(&rule->list, lst);

  return 0;
}

struct list_head* set_rules (char *rules, size_t len)
{
  const char * curr;
  struct list_head *ret;
  ret = kmalloc(sizeof(struct list_head), GFP_KERNEL);
  if (ret == NULL)
    return NULL;
  INIT_LIST_HEAD(ret);

  curr = rules;
  while(curr) {
    int port;
    char program[512];
    char * next = strchr(curr, '\n');
    if (next) *next = '\0';  // temporarily terminate the current line

    if (sscanf(curr, "%i %512s\n", &port, program) != 2)
      goto error;

    /* Does not check whether program is executable, or whether the string contains the full path */
    /* Since we assume the kernel received a well formed file */
    if (push_rule(ret, port, program, strlen(program)) != 0)
      goto error;

    if (next) *next = '\n';  // then restore newline-char, just to be tidy    
    curr = next ? (next+1) : NULL;
  }
  return ret;

 error:
  destroy_rules(ret);
  kfree(ret);
  return NULL;
}

int contains_rule (struct list_head *lst, int port_no, char* program)
{
  struct rules_list *this;
  list_for_each_entry(this, lst, list){
    if (this->port_no == port_no && strcmp(this->program, program) == 0)
      return 1;
  }
  return 0;
}

void destroy_rules (struct list_head *lst)
{
  struct rules_list *this, *next;
  
  /* free all message length nodes */
  list_for_each_entry_safe(this, next, lst, list) {
    list_del (&this->list);
    kfree(this);
  }
}

void printk_rules (struct list_head *lst)
{
  struct rules_list *this;
  list_for_each_entry(this, lst, list){
    printk(KERN_INFO "Firewall rule: %i %s\n", this->port_no, this->program);
  }
}
