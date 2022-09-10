#include "heap.h"
#include <string.h>
#include "tested_declarations.h"
#include "rdebug.h"

MEMORY_MANAGER memory_manager;

#define PAGE_SIZE 4096
#define FENCE 0x23  // '#'
#define FENCES 16
#define SBRK_FAIL ((void *)-1)
#define CHUNK_SPACE (sizeof(MEMORY_CHUNK) + 2 * FENCES)

// Round number to 8.
#define ALIGN(n) (((n) + 7) & (-8))

// Round number to PAGE_SIZE.
#define ALIGN_PAGE(n) (((n) + (PAGE_SIZE - 1)) & (-PAGE_SIZE))

// Get pointer_valid using MEMORY_CHUNK.
void* heap_chunk_to_data_address(MEMORY_CHUNK* chunk)
{
    void* addr = (char *)chunk + sizeof(MEMORY_CHUNK) + FENCES;
    return addr;
}

// Get MEMORY_CHUNK using pointer_valid.
MEMORY_CHUNK* heap_chunk_from_data_address(void* addr)
{
    MEMORY_CHUNK* chunk = (MEMORY_CHUNK *) ((char *) addr - sizeof(MEMORY_CHUNK) - FENCES);
    return chunk;
}

// Get occupied size of MEMORY_CHUNK.
size_t cheap_chunk_occupied_size(MEMORY_CHUNK* chunk)
{
    size_t occupied_size;
    if (chunk->next)
    {
        occupied_size = chunk->next - chunk;
    }
    else
    {
        occupied_size = CHUNK_SPACE + chunk->size;
    }

    occupied_size = ALIGN(occupied_size);
    return occupied_size;
}

// Get offset between memory_start and passed ptr.
intptr_t heap_offset(void* addr)
{
    intptr_t offset = (char *)addr - (char *)memory_manager.memory_start;
    return offset;
}

// Get offset between memory_start and full chunk (aligned size + CHUNK_SPACE).
intptr_t heap_chunk_offset(MEMORY_CHUNK* chunk)
{
    void* addr = (char *)chunk + cheap_chunk_occupied_size(chunk);
    addr = (void *)ALIGN((size_t)addr);  // todo: may be unnecessary.
    return heap_offset(addr);
}

// Get remaining space in memory using last MEMORY_CHUNK.
size_t heap_remaining_space(MEMORY_CHUNK* last_chunk)
{
    return memory_manager.memory_size - heap_chunk_offset(last_chunk);
}

// Calculate size of chunk based on size.
size_t heap_chunk_size(size_t size)
{
    size_t chunk_size = CHUNK_SPACE + size;
    chunk_size = ALIGN(chunk_size);
    return chunk_size;
}

// Get address of next MEMORY_CHUNK.
MEMORY_CHUNK* heap_get_next_chunk(MEMORY_CHUNK* chunk)
{
    size_t occupied_size = cheap_chunk_occupied_size(chunk);
    MEMORY_CHUNK* next_chunk = (MEMORY_CHUNK *)((char *)chunk + occupied_size);
    return next_chunk;
}

void heap_set_fences(MEMORY_CHUNK *memory_chunk)
{
    memset((char *)memory_chunk + sizeof(MEMORY_CHUNK), FENCE, FENCES);
    memset((char *)memory_chunk + sizeof(MEMORY_CHUNK) + FENCES + memory_chunk->size, FENCE, FENCES);
}

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
            heap_set_fences(memory_chunk);
            return MEMORY_CHUNK_TO_DATA_ADDRESS(memory_chunk);
        }

        if (memory_chunk->next == NULL)
        {
            size_t remaining_space = MEMORY_REMAINING_SPACE(memory_chunk);
            size_t needed_space = MEMORY_CHUNK_SPACE(size);

            if (needed_space > remaining_space)
            {
                intptr_t to_allocate = ALIGN_PAGE(needed_space - remaining_space);
                void *result = custom_sbrk(to_allocate);
                if (result == SBRK_FAIL)
                {
                    return NULL;
                }

                memory_manager.memory_size += (size_t)to_allocate;
            }

            MEMORY_CHUNK *next = heap_get_next_chunk(memory_chunk);
            memory_chunk->next = next;
            next->prev = memory_chunk;
            next->next = NULL;
            next->size = size;
            next->free = USED;

            heap_set_fences(next);
            return MEMORY_CHUNK_TO_DATA_ADDRESS(next);
        }

        memory_chunk = memory_chunk->next;
    }

    intptr_t aligned_size = ALIGN_PAGE(size);
    memory_manager.memory_start = custom_sbrk(aligned_size);
    if (memory_manager.memory_start == SBRK_FAIL)
    {
        return NULL;
    }

    memory_chunk = (MEMORY_CHUNK *)memory_manager.memory_start;
    memory_chunk->size = size;
    memory_chunk->free = USED;
    memory_chunk->prev = NULL;
    memory_chunk->next = NULL;

    memory_manager.memory_size = aligned_size;
    memory_manager.first_memory_chunk = memory_chunk;

    heap_set_fences(memory_chunk);
    return MEMORY_CHUNK_TO_DATA_ADDRESS(memory_chunk);
}

void* heap_calloc(size_t number, size_t size)
{
    size_t total_size = number * size;
    char *result = heap_malloc(total_size);
    if (result)
    {
        memset(result, 0, total_size);
    }
    return result;
}

void* heap_realloc(void* address, size_t count)
{
    (void)address;(void)count;
    return NULL;
}

void heap_free(void* address)
{
    enum pointer_type_t ptr_type = get_pointer_type(address);
    if (ptr_type != pointer_valid)
    {
        return;
    }

    // Set the memory chunk to be freed.
    MEMORY_CHUNK *memory_chunk = MEMORY_CHUNK_FROM_DATA_ADDRESS(address);
    memory_chunk->free = FREED;
    memory_chunk->size = heap_data_full_occupied_size(memory_chunk);

    MEMORY_CHUNK *prev = memory_chunk->prev;
    MEMORY_CHUNK *next = memory_chunk->next;

    // Merge previous freed chunk.
    if (prev && prev->free == FREED)
    {
        prev->next = next;
        if (next)
        {
            next->prev = prev;
        }

        memory_chunk = prev;
    }

    // Merge next freed chunk.
    if (next && next->free == FREED)
    {
        memory_chunk->next = next->next;
        if (next->next)
        {
            next->next->prev = memory_chunk;
        }
    }

    if (memory_chunk->next == NULL)
    {
        if (memory_chunk->prev)
        {
            memory_chunk->prev->next = NULL;
        }
        else
        {
            // There is only one chunk and it's freed.
            memory_manager.first_memory_chunk = NULL;
        }
        return;
    }

    memory_chunk->size = heap_data_full_occupied_size(memory_chunk);
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
    if (ptr == NULL)
    {
        return pointer_null;
    }
    if (heap_validate())
    {
        return pointer_heap_corrupted;
    }

    MEMORY_CHUNK *memory_chunk = memory_manager.first_memory_chunk;
    while (memory_chunk)
    {
        void *control_block_start = memory_chunk;
        void *control_block_end = (char *)memory_chunk + sizeof(MEMORY_CHUNK);

        void *first_fences_start = control_block_end;
        void *first_fences_end = MEMORY_CHUNK_TO_DATA_ADDRESS(memory_chunk);

        void *data_block_start = first_fences_end;
        void *data_block_end = (char *)data_block_start + memory_chunk->size;

        void *second_fences_start = data_block_end;
        void *second_fences_end = (char *)second_fences_start + FENCES;

        if (memory_chunk->free == FREED && ptr >= control_block_start && ptr < second_fences_end)
        {
            return pointer_unallocated;
        }
        if (ptr >= control_block_start && ptr < control_block_end)
        {
            return pointer_control_block;
        }
        if (ptr >= first_fences_start && ptr < first_fences_end)
        {
            return pointer_inside_fences;
        }
        if (ptr == data_block_start)
        {
            return pointer_valid;
        }
        if (ptr > data_block_start && ptr < data_block_end)
        {
            return pointer_inside_data_block;
        }
        if (ptr >= second_fences_start && ptr < second_fences_end)
        {
            return pointer_inside_fences;
        }

        memory_chunk = memory_chunk->next;
    }

    return pointer_unallocated;
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
