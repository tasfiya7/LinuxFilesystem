#include "filesys.h"

#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "utility.h"
#include "debug.h"

#define DATA_BLOCK_SIZE 64
#define INODE_DIRECT_BLOCK_COUNT 4
#define INDIRECT_DBLOCK_INDEX_COUNT 16
#define EFFECTIVE_INDIRECT_CAPACITY (INDIRECT_DBLOCK_INDEX_COUNT - 1)
#define DIRECTORY_ENTRY_SIZE (sizeof(inode_index_t) + MAX_FILE_NAME_LEN)


#define BLOCKS_TO_ALLOCATE(newSize, currSize) (calculate_necessary_dblock_amount(newSize) - calculate_necessary_dblock_amount(currSize))

#define INDIRECT_DBLOCK_MAX_DATA_SIZE ( DATA_BLOCK_SIZE * INDIRECT_DBLOCK_INDEX_COUNT )

#define NEXT_INDIRECT_INDEX_OFFSET (DATA_BLOCK_SIZE - sizeof(dblock_index_t))

// ----------------------- UTILITY FUNCTION ----------------------- //



// ----------------------- CORE FUNCTION ----------------------- //

fs_retcode_t writing_direct(filesystem_t *fs, inode_t *inode, byte *data, size_t *np, size_t *written){
    size_t current_size = inode->internal.file_size;
    size_t n = *np;
    size_t temp = 0;

    for (int i = 0; i < INODE_DIRECT_BLOCK_COUNT && n > 0; i++) {
        if (inode->internal.direct_data[i] == 0) {
            dblock_index_t newBlock;
            if (claim_available_dblock(fs, &newBlock) != SUCCESS) return DBLOCK_UNAVAILABLE;
            inode->internal.direct_data[i] = newBlock;
            memset(fs->dblocks + newBlock * DATA_BLOCK_SIZE, 0, DATA_BLOCK_SIZE);
        }

        dblock_index_t blk_idx = inode->internal.direct_data[i];
        byte *block = fs->dblocks + blk_idx * DATA_BLOCK_SIZE;

        size_t logical_offset = current_size + temp;
        size_t block_offset = logical_offset % DATA_BLOCK_SIZE;
        size_t space = DATA_BLOCK_SIZE - block_offset;
        size_t to_write = (n < space) ? n : space;

        memcpy(block + block_offset, data + temp, to_write);

        temp += to_write;
        n -= to_write;
    }

    *written = temp;
    *np = n;
    return SUCCESS;
}

fs_retcode_t writing_indirect(filesystem_t *fs, inode_t *inode, byte *data, size_t *np, size_t *written, size_t start_offset) {

    size_t n = *np;
    size_t temp = 0;

    if (inode->internal.indirect_dblock == 0) {
        dblock_index_t newIdx;
        if (claim_available_dblock(fs, &newIdx) != SUCCESS) return DBLOCK_UNAVAILABLE;
        inode->internal.indirect_dblock = newIdx;
        memset(fs->dblocks + newIdx * DATA_BLOCK_SIZE, 0, DATA_BLOCK_SIZE);
    }

    dblock_index_t index_blk_idx = inode->internal.indirect_dblock;
    byte *index_block = fs->dblocks + index_blk_idx * DATA_BLOCK_SIZE;

    size_t offset = start_offset;
    size_t logical_block_num = offset / DATA_BLOCK_SIZE;
    if (logical_block_num < INODE_DIRECT_BLOCK_COUNT) logical_block_num = INODE_DIRECT_BLOCK_COUNT;
    size_t indirect_idx = logical_block_num - INODE_DIRECT_BLOCK_COUNT;

    while (n > 0) {
        for (; indirect_idx < 15 && n > 0; indirect_idx++) {
            dblock_index_t *entry = cast_dblock_ptr(&index_block[indirect_idx * sizeof(dblock_index_t)]);
            if (*entry == 0) {
                dblock_index_t newDataBlk;
                if (claim_available_dblock(fs, &newDataBlk) != SUCCESS) return DBLOCK_UNAVAILABLE;
                *entry = newDataBlk;
                memset(fs->dblocks + newDataBlk * DATA_BLOCK_SIZE, 0, DATA_BLOCK_SIZE);
            }

            byte *block = fs->dblocks + (*entry) * DATA_BLOCK_SIZE;
            size_t block_offset = offset % DATA_BLOCK_SIZE;
            size_t space = DATA_BLOCK_SIZE - block_offset;
            size_t to_write = (n < space) ? n : space;

            memcpy(block + block_offset, data + temp, to_write);
            temp += to_write;
            n -= to_write;
            offset += to_write;
        }

        // Need a new index block
        if (n > 0) {
            dblock_index_t *next_index_blk = cast_dblock_ptr(&index_block[DATA_BLOCK_SIZE - sizeof(dblock_index_t)]);
            if (*next_index_blk == 0) {
                dblock_index_t new_idx_blk;
                if (claim_available_dblock(fs, &new_idx_blk) != SUCCESS) return DBLOCK_UNAVAILABLE;
                *next_index_blk = new_idx_blk;
                memset(fs->dblocks + new_idx_blk * DATA_BLOCK_SIZE, 0, DATA_BLOCK_SIZE);
            }
            index_blk_idx = *next_index_blk;
            index_block = fs->dblocks + index_blk_idx * DATA_BLOCK_SIZE;
            indirect_idx = 0;
        }
    }

    *written = temp;
    *np = 0;
    return SUCCESS;
}

static dblock_index_t* get_indirect_ptr(filesystem_t *fs, struct inode_internal *in, size_t logical_index, bool allocate) {
    if (in->indirect_dblock == 0) {
        if (!allocate) return NULL;
        dblock_index_t temp;
        if (claim_available_dblock(fs, &temp) != SUCCESS) return NULL;
        in->indirect_dblock = temp;
        memset(fs->dblocks + temp * DATA_BLOCK_SIZE, 0, DATA_BLOCK_SIZE);
    }

    dblock_index_t current = in->indirect_dblock;
    size_t cap = EFFECTIVE_INDIRECT_CAPACITY;
    size_t idx = logical_index;

    while (true) {
        dblock_index_t *indirect = (dblock_index_t*)(fs->dblocks + current * DATA_BLOCK_SIZE);
        if (idx < cap) return &indirect[idx];

        if (indirect[cap] == 0) {
            if (!allocate) return NULL;
            dblock_index_t next;
            if (claim_available_dblock(fs, &next) != SUCCESS) return NULL;
            indirect[cap] = next;
            memset(fs->dblocks + next * DATA_BLOCK_SIZE, 0, DATA_BLOCK_SIZE);
        }

        current = indirect[cap];
        idx -= cap;
    }
}


fs_retcode_t inode_write_data(filesystem_t *fs, inode_t *inode, void *data, size_t n)
{
    if (!fs || !inode || !data) return INVALID_INPUT;
    if (n == 0) return SUCCESS;

    struct inode_internal *in = &inode->internal;

    if (in->file_type == DIRECTORY && in->file_size < DIRECTORY_ENTRY_SIZE)
        in->file_size = DIRECTORY_ENTRY_SIZE;

    size_t orig_size = in->file_size;
    size_t final_size = orig_size + n;

    // Check enough blocks
    size_t required_blocks = calculate_necessary_dblock_amount(final_size);
    size_t current_blocks = calculate_necessary_dblock_amount(orig_size);
    if ((required_blocks - current_blocks) > available_dblocks(fs)) {
        return INSUFFICIENT_DBLOCKS;
    }

    byte *src = (byte *)data;
    size_t offset = orig_size;
    size_t remaining = n;

    while (remaining > 0) {
        size_t block_index = offset / DATA_BLOCK_SIZE;
        size_t offset_in_block = offset % DATA_BLOCK_SIZE;
        size_t space_in_block = DATA_BLOCK_SIZE - offset_in_block;
        size_t to_write = (remaining < space_in_block) ? remaining : space_in_block;

        dblock_index_t dblk;

        // Resolve or allocate the data block
        if (block_index < INODE_DIRECT_BLOCK_COUNT) {
            dblk = in->direct_data[block_index];
            if (dblk == 0) {
                if (claim_available_dblock(fs, &dblk) != SUCCESS)
                    return SYSTEM_ERROR;
                memset(fs->dblocks + dblk * DATA_BLOCK_SIZE, 0, DATA_BLOCK_SIZE);
                in->direct_data[block_index] = dblk;
            }
        } else {
            size_t logical_index = block_index - INODE_DIRECT_BLOCK_COUNT;
            dblock_index_t *ptr = get_indirect_ptr(fs, in, logical_index, true);
            if (!ptr) return SYSTEM_ERROR;
            dblk = *ptr;
            if (dblk == 0) {
                if (claim_available_dblock(fs, &dblk) != SUCCESS)
                    return SYSTEM_ERROR;
                memset(fs->dblocks + dblk * DATA_BLOCK_SIZE, 0, DATA_BLOCK_SIZE);
                *ptr = dblk;
            }
        }

        
        memcpy(fs->dblocks + dblk * DATA_BLOCK_SIZE + offset_in_block, src, to_write);

        // Update positions
        src += to_write;
        offset += to_write;
        remaining -= to_write;
    }

    in->file_size = final_size;
    return SUCCESS;
    //Check for valid input

    // do we have enough dblocks to store the data. if not, error. 

    // fill the direct nodes if necessary (helper function)

    // fill in indirect nodes if necessary (helper function)
}

fs_retcode_t inode_read_data(filesystem_t *fs, inode_t *inode, size_t offset, void *buffer, size_t n, size_t *bytes_read)
{

    if(fs == NULL || inode == NULL || buffer == NULL || bytes_read == NULL)
        return INVALID_INPUT;
    
    struct inode_internal *in = &inode->internal;
    
    // If offset is past the file's end, nothing is read.
    if (offset > in->file_size) {
        *bytes_read = 0;
        return SUCCESS;
    }
    
    size_t available = in->file_size - offset;
    size_t to_read = (n < available) ? n : available;
    *bytes_read = to_read;
    
    size_t bytes_copied = 0;
    size_t curr_offset = offset;
    byte *dest = (byte *)buffer;
    
    while (bytes_copied < to_read) {
        size_t block_index = curr_offset / DATA_BLOCK_SIZE;
        size_t offset_in_block = curr_offset % DATA_BLOCK_SIZE;
        size_t bytes_in_block = DATA_BLOCK_SIZE - offset_in_block;
        if (bytes_in_block > (to_read - bytes_copied))
            bytes_in_block = to_read - bytes_copied;
        
        dblock_index_t dblk;
        if (block_index < INODE_DIRECT_BLOCK_COUNT)
            dblk = in->direct_data[block_index];
        else {
            size_t indirect_idx = block_index - INODE_DIRECT_BLOCK_COUNT;
            if (in->indirect_dblock == 0 || indirect_idx >= INDIRECT_DBLOCK_INDEX_COUNT)
                break; // no more data blocks available
            dblock_index_t *indirect_array = (dblock_index_t *)(fs->dblocks + in->indirect_dblock * DATA_BLOCK_SIZE);
            dblk = indirect_array[indirect_idx];
        }
        byte *src = fs->dblocks + dblk * DATA_BLOCK_SIZE;
        memcpy(dest + bytes_copied, src + offset_in_block, bytes_in_block);
        bytes_copied += bytes_in_block;
        curr_offset += bytes_in_block;
    }
    
    return SUCCESS;

    
    //check to make sure inputs are valid

    //for 0 to n, use the helper function to read and copy 1 byte at a time
}

fs_retcode_t inode_modify_data(filesystem_t *fs, inode_t *inode, size_t offset, void *buffer, size_t n)
{
    if (!fs || !inode || !buffer) return INVALID_INPUT;

    struct inode_internal *in = &inode->internal;

    if (offset > in->file_size)
        return INVALID_INPUT;

    // If offset == file size, treat this as a write (append)
    if (offset == in->file_size)
        return inode_write_data(fs, inode, buffer, n);

    size_t end_offset = offset + n;

    
    if (end_offset <= in->file_size) {
        size_t curr_offset = offset;
        byte *src = (byte *)buffer;
        size_t bytes_written = 0;

        while (bytes_written < n) {
            size_t block_index = curr_offset / DATA_BLOCK_SIZE;
            size_t offset_in_block = curr_offset % DATA_BLOCK_SIZE;
            size_t writable = DATA_BLOCK_SIZE - offset_in_block;
            if (writable > (n - bytes_written))
                writable = n - bytes_written;

            dblock_index_t dblk;
            if (block_index < INODE_DIRECT_BLOCK_COUNT) {
                dblk = in->direct_data[block_index];
                if (dblk == 0) return INSUFFICIENT_DBLOCKS;
            } else {
                size_t logical_index = block_index - INODE_DIRECT_BLOCK_COUNT;
                dblock_index_t *ptr = get_indirect_ptr(fs, in, logical_index, false);
                if (!ptr || *ptr == 0) return INSUFFICIENT_DBLOCKS;
                dblk = *ptr;
            }

            byte *dest = fs->dblocks + dblk * DATA_BLOCK_SIZE;
            memcpy(dest + offset_in_block, src + bytes_written, writable);

            bytes_written += writable;
            curr_offset += writable;
        }

        return SUCCESS;
    }

    
    size_t existing = in->file_size - offset;
    fs_retcode_t ret = inode_modify_data(fs, inode, offset, buffer, existing);
    if (ret != SUCCESS) return ret;

    size_t remaining = n - existing;
    return inode_write_data(fs, inode, (byte *)buffer + existing, remaining);

    //check to see if the input is valid

    //calculate the final filesize and verify there are enough blocks to support it
    //use calculate_necessary_dblock_amount and available_dblocks


    //Write to existing data in your inode

    //For the new data, call "inode_write_data" and return
}




fs_retcode_t inode_shrink_data(filesystem_t *fs, inode_t *inode, size_t new_size)
{
    if (!fs || !inode) return INVALID_INPUT;

    struct inode_internal *in = &inode->internal;
    if (new_size > in->file_size) return INVALID_INPUT;

    size_t old_blocks = (in->file_size == 0) ? 0 : ((in->file_size - 1) / DATA_BLOCK_SIZE) + 1;
    size_t new_blocks = (new_size == 0) ? 0 : ((new_size - 1) / DATA_BLOCK_SIZE) + 1;

    // Shrink direct blocks
    for (int i = INODE_DIRECT_BLOCK_COUNT - 1; i >= 0; i--) {
        size_t block_index = i;
        if (block_index >= new_blocks && block_index < old_blocks) {
            dblock_index_t dblk = in->direct_data[i];
            if (dblk < fs->dblock_count) {
                byte *block_ptr = fs->dblocks + dblk * DATA_BLOCK_SIZE;
                release_dblock(fs, block_ptr);
                
            }
            
        }
    }

    if (in->indirect_dblock != 0) {
        dblock_index_t curr = in->indirect_dblock;
        dblock_index_t prev = 0;
        size_t logical_index = 0;

        while (curr != 0) {
            dblock_index_t *index_array = (dblock_index_t *)(fs->dblocks + curr * DATA_BLOCK_SIZE);
            dblock_index_t next = index_array[INDIRECT_DBLOCK_INDEX_COUNT - 1];

            bool all_data_freed = true;
            size_t base_index = logical_index;

            for (int i = 0; i < INDIRECT_DBLOCK_INDEX_COUNT - 1; i++, logical_index++) {
                size_t global_index = INODE_DIRECT_BLOCK_COUNT + logical_index;

                printf("Evaluating indirect block index %d (global %zu): new_blocks = %zu, old_blocks = %zu\n",
                       i, global_index, new_blocks, old_blocks);

                if (global_index >= new_blocks && global_index < old_blocks) {
                    dblock_index_t dblk = index_array[i];
                    if (dblk < fs->dblock_count) {
                        byte *block_ptr = fs->dblocks + dblk * DATA_BLOCK_SIZE;
                        release_dblock(fs, block_ptr);
                        printf("Releasing INDIRECT dblock index: %u (global index %zu)\n", dblk, global_index);
                    }
                }

                if (index_array[i] != 0 ) {
                    all_data_freed = false;
                }
            }

            if (all_data_freed && (INODE_DIRECT_BLOCK_COUNT + base_index) >= new_blocks) {
                byte *index_ptr = fs->dblocks + curr * DATA_BLOCK_SIZE;
                release_dblock(fs, index_ptr);
                printf("Releasing INDEX dblock at index block %u\n", curr);

                if (prev == 0) {
                    in->indirect_dblock = 0;
                } else {
                    dblock_index_t *prev_array = (dblock_index_t *)(fs->dblocks + prev * DATA_BLOCK_SIZE);
                    prev_array[INDIRECT_DBLOCK_INDEX_COUNT - 1] = 0;
                }
            } else {
                prev = curr;
            }

            curr = next;
        }
    }

    in->file_size = new_size;
    return SUCCESS;
    //check to see if inputs are in valid range

    //Calculate how many blocks to remove

    //helper function to free all indirect blocks

    //remove the remaining direct dblocks

    //update filesize and return
}

// make new_size to 0
fs_retcode_t inode_release_data(filesystem_t *fs, inode_t *inode)
{
    if (fs == NULL || inode == NULL)
    return INVALID_INPUT;

return inode_shrink_data(fs, inode, 0);
    
}
