#ifndef __ARP_TODO_H_
#define __ARP_TODO_H_

#define ARP_TODO_UPDATE_DB	1
#define ARP_TODO_WRITE_SQL	2
#define ARP_TODO_MAX		2


int todo_enqueue (const int  cmd);
int todo_dequeue (void);

#endif
