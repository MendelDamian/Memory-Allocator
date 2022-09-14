#include "heap.h"
#include <string.h>
#include <stdio.h>
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
void* heap_chunk_to_data_address(MEMORY_CHUNK *chunk)
{
    return (char *)chunk + sizeof(MEMORY_CHUNK) + FENCES;
}

// Get MEMORY_CHUNK using pointer_valid.
MEMORY_CHUNK* heap_chunk_from_data_address(void *addr)
{
    MEMORY_CHUNK *chunk;
    size_t aligned_offset = (size_t)addr - sizeof(size_t);
    if (*(char *)((size_t)addr - sizeof(size_t)) == '#')
    {
        chunk = (MEMORY_CHUNK *)((char *)addr - sizeof(MEMORY_CHUNK) - FENCES);
    }
    else
    {
        chunk = (MEMORY_CHUNK *)((size_t)addr - aligned_offset);
    }
    return chunk;
}

// Get occupied size of MEMORY_CHUNK.
size_t heap_chunk_size(MEMORY_CHUNK* chunk)
{
    size_t occupied_size;
    if (chunk->free == FREED && chunk->next)
    {
        occupied_size = (char *)chunk->next - (char *)chunk;
    }
    else
    {
        occupied_size = CHUNK_SPACE + chunk->size;
    }

    occupied_size = ALIGN(occupied_size);
    return occupied_size;
}

// Get offset between memory_start and passed ptr.
intptr_t heap_offset(void *addr)
{
    intptr_t offset = (char *)addr - (char *)memory_manager.memory_start;
    return offset;
}

// Get offset between memory_start and full chunk (aligned size + CHUNK_SPACE).
intptr_t heap_chunk_offset(MEMORY_CHUNK *chunk)
{
    void *addr = (char *)chunk + heap_chunk_size(chunk);
    return heap_offset(addr);
}

// Get remaining space in memory using last MEMORY_CHUNK.
size_t heap_remaining_space(MEMORY_CHUNK *last_chunk)
{
    return memory_manager.memory_size - heap_chunk_offset(last_chunk);
}

// Calculate size of chunk based on size.
size_t heap_calc_size(size_t size)
{
    return CHUNK_SPACE + size;
}

// Get address of next MEMORY_CHUNK.
MEMORY_CHUNK* heap_get_next_chunk(MEMORY_CHUNK *chunk)
{
    size_t occupied_size = heap_chunk_size(chunk);
    MEMORY_CHUNK *next_chunk = (MEMORY_CHUNK *)((char *)chunk + occupied_size);
    return next_chunk;
}

void heap_set_fences(MEMORY_CHUNK *memory_chunk)
{
    memset((char *)memory_chunk + sizeof(MEMORY_CHUNK), FENCE, FENCES);
    memset((char *)memory_chunk + sizeof(MEMORY_CHUNK) + FENCES + memory_chunk->size, FENCE, FENCES);
}

int heap_setup(void)
{
    void *memory_start = custom_sbrk(PAGE_SIZE);
    if (memory_start == SBRK_FAIL)
    {
        return -1;
    }

    memory_manager.first_memory_chunk = NULL;
    memory_manager.memory_size = PAGE_SIZE;
    memory_manager.memory_start = memory_start;
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
        if (memory_chunk->free == FREED && memory_chunk->size >= (size + FENCES * 2))
        {
            memory_chunk->size = size;
            memory_chunk->free = USED;
            memory_chunk->aligned_offset = 0;
            heap_set_fences(memory_chunk);
            return heap_chunk_to_data_address(memory_chunk);
        }

        if (memory_chunk->next)
        {
            size_t occupied_size = (char *)memory_chunk->next - (char *)memory_chunk;
            occupied_size -= heap_chunk_size(memory_chunk);  // Free space between chunks.
            size_t needed_space = heap_calc_size(size);

            if (occupied_size >= needed_space)
            {
                MEMORY_CHUNK *new_chunk = heap_get_next_chunk(memory_chunk);
                new_chunk->size = size;
                new_chunk->free = USED;
                new_chunk->aligned_offset = 0;

                new_chunk->next = memory_chunk->next;
                new_chunk->prev = memory_chunk;
                memory_chunk->next = new_chunk;
                new_chunk->next->prev = new_chunk;

                heap_set_fences(new_chunk);
                return heap_chunk_to_data_address(new_chunk);
            }
        }
        else
        {
            size_t remaining_space = heap_remaining_space(memory_chunk);
            size_t needed_space = heap_calc_size(size);

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
            next->aligned_offset = 0;
            heap_set_fences(next);
            return heap_chunk_to_data_address(next);
        }

        memory_chunk = memory_chunk->next;
    }

    size_t needed_space = heap_calc_size(size);
    if (needed_space > memory_manager.memory_size)
    {
        intptr_t to_allocate = ALIGN_PAGE(needed_space - memory_manager.memory_size);
        void *result = custom_sbrk(to_allocate);
        if (result == SBRK_FAIL)
        {
            return NULL;
        }

        memory_manager.memory_size += (size_t)to_allocate;
    }

    memory_chunk = (MEMORY_CHUNK *)memory_manager.memory_start;
    memory_chunk->size = size;
    memory_chunk->free = USED;
    memory_chunk->prev = NULL;
    memory_chunk->next = NULL;
    memory_manager.first_memory_chunk = memory_chunk;
    memory_chunk->aligned_offset = 0;
    heap_set_fences(memory_chunk);
    return heap_chunk_to_data_address(memory_chunk);
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

void* heap_realloc(void *address, size_t count)
{
    if (heap_validate())
    {
        return NULL;
    }

    if (address == NULL)
    {
        return heap_malloc(count);
    }

    if (get_pointer_type(address) != pointer_valid)
    {
        return NULL;
    }

    if (count == 0)
    {
        heap_free(address);
        return NULL;
    }

    MEMORY_CHUNK *chunk_to_reallocate = heap_chunk_from_data_address(address);
    if (chunk_to_reallocate->size == count)
    {
        return address;
    }

    if (chunk_to_reallocate->size > count)
    {
        chunk_to_reallocate->size = count;
        heap_set_fences(chunk_to_reallocate);
        return address;
    }

    size_t needed_space = heap_calc_size(count), remaining_space;

    // Expand if last chunk.
    if (chunk_to_reallocate->next == NULL)
    {
        remaining_space = heap_offset(chunk_to_reallocate);
        if (needed_space > remaining_space)
        {
            size_t to_allocate = needed_space - remaining_space;
            to_allocate = ALIGN_PAGE(to_allocate);
            if (custom_sbrk((intptr_t)to_allocate) == SBRK_FAIL)
            {
                return NULL;
            }
            memory_manager.memory_size += to_allocate;
        }

        chunk_to_reallocate->size = count;
        heap_set_fences(chunk_to_reallocate);
        return address;
    }

    // Expand if there is enough space behind.
    remaining_space = (char *)chunk_to_reallocate->next - (char *)chunk_to_reallocate;
    if (needed_space <= remaining_space)
    {
        chunk_to_reallocate->size = count;
        heap_set_fences(chunk_to_reallocate);
        return address;
    }

    // Otherwise allocate new memory.
    void *new_address = heap_malloc(count);
    if (new_address == NULL)
    {
        return NULL;
    }

    memcpy(new_address, address, chunk_to_reallocate->size);
    heap_free(address);
    return new_address;
}

void heap_free(void *address)
{
    if (get_pointer_type(address) != pointer_valid)
    {
        return;
    }

    // Set the memory chunk to be freed.
    MEMORY_CHUNK *memory_chunk = heap_chunk_from_data_address(address);
    if (memory_chunk->next && memory_chunk->next->free == USED
        && memory_chunk->prev && memory_chunk->prev->free == USED)
    {
        memory_chunk->prev->next = memory_chunk->next;
        memory_chunk->next->prev = memory_chunk->prev;
        return;
    }

    memory_chunk->free = FREED;
    memory_chunk->size = heap_chunk_size(memory_chunk) - sizeof(MEMORY_CHUNK);  // Without control block.

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

    memory_chunk->size = heap_chunk_size(memory_chunk) - sizeof(MEMORY_CHUNK);  // Without control block.
}

size_t heap_get_largest_used_block_size(void)
{
    if (heap_validate())
    {
        return 0;
    }

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

enum pointer_type_t get_pointer_type(const void *ptr)
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
        void *first_fences_end = heap_chunk_to_data_address(memory_chunk);

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
        if (ptr == (char *)data_block_start + memory_chunk->aligned_offset)
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
    if (memory_manager.memory_start == NULL || memory_manager.memory_size == 0)
    {
        return 2;
    }

    MEMORY_CHUNK *memory_chunk = memory_manager.first_memory_chunk;
    while (memory_chunk)
    {
        // Check if the control block is corrupted.
        if (memory_chunk < memory_manager.first_memory_chunk
            || (char *)memory_chunk > (char *)memory_manager.first_memory_chunk + memory_manager.memory_size)
        {
            return 3;
        }

        if (memory_chunk->free != USED && memory_chunk->free != FREED)
        {
            return 3;
        }

        // todo: do some magic do check if size was changed.
        if (memory_chunk->size == 0 || memory_chunk->size > memory_manager.memory_size)
        {
            return 3;
        }

        if (memory_chunk->prev && memory_chunk->prev->next != memory_chunk)
        {
            return 3;
        }

        if (memory_chunk->next && memory_chunk->next->prev != memory_chunk)
        {
            return 3;
        }

        if (memory_chunk->free == USED)
        {
            // Check if fences are corrupted.
            for (int i = 0; i < FENCES; ++i)
            {
                char *first_fence = (char *)memory_chunk + sizeof(MEMORY_CHUNK);
                char *second_fence = (char *)first_fence + FENCES + memory_chunk->size;

                if (*(first_fence + i) != FENCE || *(second_fence + i) != FENCE)
                {
                    return 1;
                }
            }
        }

        memory_chunk = memory_chunk->next;
    }
     return 0;
}

void* heap_malloc_aligned(size_t size)
{
    if (size == 0)
    {
        return NULL;
    }

    void *malloc_addr = heap_malloc(size + PAGE_SIZE + sizeof(size_t));
    if (malloc_addr == NULL)
    {
        return NULL;
    }

    size_t addr = (size_t)malloc_addr + PAGE_SIZE + sizeof(size_t);

    void *aligned_addr = (void *)(addr - (addr % PAGE_SIZE));
    *((size_t *)aligned_addr - 1) = (size_t)malloc_addr;

    MEMORY_CHUNK *memory_chunk = heap_chunk_from_data_address(malloc_addr);
    memory_chunk->aligned_offset = (char *)aligned_addr - (char *)malloc_addr;
    return aligned_addr;
}

void* heap_calloc_aligned(size_t number, size_t size)
{
    (void)number;(void)size;
    return NULL;
}

void* heap_realloc_aligned(void *address, size_t size)
{
    (void)address;(void)size;
    return NULL;
}

void heap_print_chunks(void)
{
    if (heap_validate())
    {
        puts("Heap corrupted");
        return;
    }

    MEMORY_CHUNK *memory_chunk = memory_manager.first_memory_chunk;
    int i = 0;
    while (memory_chunk)
    {
        printf("\nChunk %d\n", i);
        printf("\tAddress: %p\n", (void *)memory_chunk);
        printf("\tSize: %zu\n", memory_chunk->size);
        printf("\tFree: %s\n", memory_chunk->free == USED ? "USED" : "FREED");
        printf("\tPrev: %p\n", (void *)memory_chunk->prev);
        printf("\tNext: %p\n", (void *)memory_chunk->next);
        printf("\tAligned offset: %x\n", memory_chunk->aligned_offset);

        i++;
        memory_chunk = memory_chunk->next;
    }
}

void heap_print(void)
{
    if (heap_validate())
    {
        puts("Heap corrupted");
        return;
    }

    putchar('[');
    int counter = 0;
    void* adr = memory_manager.memory_start;
    while ((char *)adr < (char *)memory_manager.memory_start + memory_manager.memory_size)
    {
        enum pointer_type_t pointer_type = get_pointer_type(adr);

        switch (pointer_type)
        {
            case pointer_control_block:
                putchar('C');
                break;
            case pointer_inside_fences:
                putchar(FENCE);
                break;
            case pointer_valid:
            case pointer_inside_data_block:
                putchar('b');
                break;
            case pointer_unallocated:
                putchar('.');
                break;
            default:
                putchar(']');
                return;
        }

        adr = (char *)adr + 1;
        if (counter == 127)
        {
            counter = 0;
            putchar('\n');
            putchar(' ');
        }
        else
        {
            counter++;
        }
    }

    puts("\r]\n");
}
