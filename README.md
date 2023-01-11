# Memory Manager
A custom memory manager implementation project developed for the "Operating Systems" classes to consolidate knowledge of memory management and system programming. The memory manager is based on a doubly-linked list and uses guard fences to detect buffer overflows and heap corruptions.

## Author

- [@MendelDamian](https://www.github.com/MendelDamian)

## Features
- Detects buffer overflows and heap corruptions using guard fences.
- Keeps track of the largest used block size, which can be queried using `heap_get_largest_used_block_size`.
- Provides the `get_pointer_type` function, which can be used to check the type of a pointer (e.g. whether it's a valid heap pointer or a null pointer).
- Can validate the heap and check for consistency using `heap_validate`.

## Usage
Include the `heap.h` header file in your project, and use the functions heap_malloc, heap_calloc, heap_realloc, and heap_free in place of the standard malloc, calloc, realloc, and free.

```c
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
```

## Configuration
The following constants can be defined before including the header file to customize the behavior of the memory manager:

- `PAGE_SIZE`: The size of a memory page, used for allocating memory in blocks. Default value is 4096.
- `FENCES`: The number of guard fences to use. Default value is 16.
- `CUSTOM_SBRK`: Define this constant to use a custom implementation of sbrk instead of the standard one.

## Functions
This project provides several functions for memory management, such as:

- `int heap_setup(void)`: sets up the memory manager and initializes the heap.
- `void heap_clean(void)`: releases the memory allocated by the memory manager.
- `void *heap_malloc(size_t size)`: allocates a block of `size` bytes of memory, and returns a pointer to the first byte of the block.
- `void *heap_calloc(size_t number, size_t size)`: allocates memory for an array of `number` elements of `size` bytes each, and returns a pointer to the first byte of the allocated memory.
- `void *heap_realloc(void *address, size_t count)`: changes the size of the memory block pointed to by `address` to `count` bytes.
- `void heap_free(void *address)`: releases the memory pointed to by `address` that was previously allocated using `heap_malloc` or `heap_calloc`.
- `size_t heap_get_largest_used_block_size(void)`: returns the size of the largest used memory block.
- `enum pointer_type_t get_pointer_type(const void *ptr)`: Determines the type of pointer passed in.
  * `pointer_null` if the pointer is NULL
  * `pointer_heap_corrupted` if heap is corrupted
  * `pointer_unallocated` if pointer is within memory that has been freed
  * `pointer_control_block` if pointer is within the control block (i.e. the memory that manages the data block)
  * `pointer_inside_fences` if pointer is within the fences (i.e. the memory that surrounds the data block)
  * `pointer_valid` if pointer points to the start of the data block
  * `pointer_inside_data_block` if pointer is inside the data block but not at the start
- `int heap_validate(void)`:  validates the heap for consistency.
  * `0` if heap is valid
  * `1` if fences are corrupted
  * `2` if heap is not setup
  * `3` if other heap corruption is detected

**NOTE** `heap_setup` should be called before any other memory allocation functions are used.

# Note
Please keep in mind that this project, despite passing automated tests, is bound to have some bugs and isn't perfect, so don't use it in production. It is for educational purposes only.
