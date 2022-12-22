#include <pthread.h>
#include "todo.h"


#define MAX_TODO_QUEUE	50

static pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;
static int		todo_list[MAX_TODO_QUEUE];
static int		todo_front = 0;
static int		todo_rear  = 0;

int todo_enqueue (const int  cmd) {
    int	i;
    int	retval = 0;

    pthread_mutex_lock   (&mutex);

    if ((i = (todo_front + 1) % MAX_TODO_QUEUE) != todo_rear) {
        todo_list[todo_front] = cmd;
        todo_front = i;
    } else {
        retval = -1;
    }

    pthread_mutex_unlock (&mutex);

    return retval;
}

int todo_dequeue (void) {
    int	retval = 0;

    pthread_mutex_lock   (&mutex);

    if (todo_rear != todo_front) {
        retval = todo_list[todo_rear];
        todo_rear = (todo_rear + 1) % MAX_TODO_QUEUE;
    } else {
        retval = -1;
    }

    pthread_mutex_unlock (&mutex);

    return retval;
}
