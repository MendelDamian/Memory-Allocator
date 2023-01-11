#include "heap.h"

int main(void)
{
    heap_setup();

    void *ptr = heap_malloc(100);
    if (ptr == NULL)
        return -1;

    void *new_ptr = heap_realloc(ptr, 200);
    if (new_ptr == NULL)
        return -1;
    ptr = new_ptr;

    heap_free(ptr);

    heap_clean();
    return 0;
}
