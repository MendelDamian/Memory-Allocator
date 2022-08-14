#ifndef HEAP_H
#define HEAP_H
#include <stdint.h>
#include "custom_unistd.h"

enum mem_flag_t
{
    USED = 0,
    FREED = 1
};

enum pointer_type_t
{
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};

typedef struct memory_manager_t
{
    void *memory_start;
    size_t memory_size;
    struct memory_chunk_t *first_memory_chunk;
} MEMORY_MANAGER;

typedef struct memory_chunk_t
{
    struct memory_chunk_t* prev;
    struct memory_chunk_t* next;
    size_t size;
    int free;
} MEMORY_CHUNK;

int heap_setup(void);
void heap_clean(void);

void* heap_malloc(size_t size);
void* heap_calloc(size_t number, size_t size);
void* heap_realloc(void* address, size_t count);
void heap_free(void* address);

size_t heap_get_largest_used_block_size(void);
enum pointer_type_t get_pointer_type(const void* ptr);

int heap_validate(void);

void* heap_malloc_aligned(size_t size);
void* heap_calloc_aligned(size_t number, size_t size);
void* heap_realloc_aligned(void* address, size_t size);

#ifndef CUSTOM_SBRK
#define CUSTOM_SBRK
extern void* custom_sbrk(intptr_t delta);
#endif

#endif //HEAP_H
