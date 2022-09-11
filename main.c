#include "heap.h"

int main(void)
{
    heap_setup();

    char *ptr1 = heap_malloc(1000);
    heap_malloc(1000);
    heap_free(ptr1);
    ptr1 = heap_malloc(100);
    ptr1 = heap_realloc(ptr1, 1000);
    heap_realloc(ptr1, 0);

    heap_print();
    heap_print_chunks();



    heap_clean();
    return 0;
}
