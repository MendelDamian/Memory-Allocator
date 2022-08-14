#include "heap.h"
#include "tested_declarations.h"
#include "rdebug.h"

MEMORY_MANAGER memory_manager;

#define PAGE_SIZE 4096
#define FENCE 0xEA
#define FENCES 16
#define SBRK_FAIL ((void *)-1)

#define ALIGN(n) (((n) + 7) & (-8))

#define ALIGN_PAGE(n) (((n) + (PAGE_SIZE - 1)) & (-PAGE_SIZE))

#define MEMORY_CHUNK_DATA_ADDRESS(chunk) ((char *)(chunk) + sizeof(MEMORY_CHUNK) + FENCES)

#define MEMORY_CHUNK_OFFSET(chunk) ((char *)(chunk) - (char *)memory_manager.memory_start)

#define MEMORY_CHUNK_PHYSICAL_SIZE(chunk)                                               \
    ((chunk)->next                                                                      \
    ? ((size_t)(chunk)->next - (size_t)(chunk))                                         \
    : (sizeof(MEMORY_CHUNK) + FENCES + (chunk)->size + FENCES))

#define MEMORY_CHUNK_DATA_PHYSICAL_SIZE(chunk) \
    (MEMORY_CHUNK_PHYSICAL_SIZE(chunk) - sizeof(MEMORY_CHUNK))

#define MEMORY_CHUNK_NEXT(chunk) ((MEMORY_CHUNK *)((char *)(chunk) + MEMORY_CHUNK_PHYSICAL_SIZE(chunk)))

#define MEMORY_CHUNK_FROM_DATA_ADDRESS(address) ((MEMORY_CHUNK *)((char *)(address) - FENCES - sizeof(MEMORY_CHUNK)))

int heap_setup(void)
{
    memory_manager.first_memory_chunk = NULL;
    memory_manager.memory_size = 0;
    memory_manager.memory_start = NULL;
    return 0;
}

void heap_clean(void)
{
    custom_sbrk(-(intptr_t)memory_manager.memory_size);
    memory_manager.first_memory_chunk = NULL;
    memory_manager.memory_start = NULL;
    memory_manager.memory_size = 0;
}

void* heap_malloc(size_t size)
{
    if (size == 0 || heap_validate())
    {
        return NULL;
    }

    MEMORY_CHUNK *memory_chunk = memory_manager.first_memory_chunk;

    while (memory_chunk)
    {
        if (memory_chunk->free == FREED && memory_chunk->size >= size)
        {
            memory_chunk->size = size;
            memory_chunk->free = USED;
            // TODO: fences
            return MEMORY_CHUNK_DATA_ADDRESS(memory_chunk);
        }

        if (memory_chunk->next == NULL)
        {
            // TODO: sbrk if not enough space
            MEMORY_CHUNK *next = MEMORY_CHUNK_NEXT(memory_chunk);
            memory_chunk->next = next;
            next->prev = memory_chunk;
            next->next = NULL;
            next->size = size;
            next->free = USED;
            // TODO: fences
            return MEMORY_CHUNK_DATA_ADDRESS(next);
        }
    }

    memory_manager.memory_start = custom_sbrk(ALIGN_PAGE(size));
    if (memory_manager.memory_start == SBRK_FAIL)
    {
        return NULL;
    }

    memory_chunk = (MEMORY_CHUNK *)memory_manager.memory_start;
    memory_chunk->size = size;
    memory_chunk->free = USED;
    memory_chunk->prev = NULL;
    memory_chunk->next = NULL;

    memory_manager.memory_size = ALIGN_PAGE(size);
    memory_manager.first_memory_chunk = memory_chunk;
    // TODO: fences
    return MEMORY_CHUNK_DATA_ADDRESS(memory_chunk);
}

void* heap_calloc(size_t number, size_t size)
{
    (void)number;(void)size;
    return NULL;
}

void* heap_realloc(void* address, size_t count)
{
    (void)address;(void)count;
    return NULL;
}

void heap_free(void* address)
{
    (void)address;
}

size_t heap_get_largest_used_block_size(void)
{
    size_t largest_used_block = 0;
    MEMORY_CHUNK *memory_chunk = memory_manager.first_memory_chunk;
    while (memory_chunk)
    {
        if (memory_chunk->free == USED && memory_chunk->size > largest_used_block)
        {
            largest_used_block = memory_chunk->size;
        }
        memory_chunk = memory_chunk->next;
    }

    return largest_used_block;
}

enum pointer_type_t get_pointer_type(const void* ptr)
{
    (void)ptr;
    return pointer_valid;
}

int heap_validate(void)
{
    return 0;
}

void* heap_malloc_aligned(size_t size)
{
    (void)size;
    return NULL;
}

void* heap_calloc_aligned(size_t number, size_t size)
{
    (void)number;(void)size;
    return NULL;
}

void* heap_realloc_aligned(void* address, size_t size)
{
    (void)address;(void)size;
    return NULL;
}
