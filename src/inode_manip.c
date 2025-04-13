#include "filesys.h"

#include <string.h>
#include <assert.h>

#include "utility.h"
#include "debug.h"

#define BLOCKS_TO_ALLOCATE(newSize, currSize) (calculate_necessary_dblock_amount(newSize) - calculate_necessary_dblock_amount(currSize))

#define INDIRECT_DBLOCK_INDEX_COUNT (DATA_BLOCK_SIZE / sizeof(dblock_index_t) - 1)
#define INDIRECT_DBLOCK_MAX_DATA_SIZE ( DATA_BLOCK_SIZE * INDIRECT_DBLOCK_INDEX_COUNT )

#define NEXT_INDIRECT_INDEX_OFFSET (DATA_BLOCK_SIZE - sizeof(dblock_index_t))

// ----------------------- UTILITY FUNCTION ----------------------- //



// ----------------------- CORE FUNCTION ----------------------- //

fs_retcode_t writing_direct(filesystem_t *fs, inode_t *inode, byte *data, size_t *np, size_t *written){
    size_t current_size = inode->internal.file_size;
    size_t n = *np;
    size_t temp = 0;

    for (int i = 0; i < INODE_DIRECT_BLOCK_COUNT && n > 0; i++){
        if (!inode->internal.direct_data[i]) {
            dblock_index_t newBlock;
            if (claim_available_dblock(fs, &newBlock) != SUCCESS) {
                return DBLOCK_UNAVAILABLE;  // or return the error code from claim_available_dblock()
            }

            inode->internal.direct_data[i] = newBlock;

            byte *newBlockPtr = fs->dblocks + (newBlock * DATA_BLOCK_SIZE);
            memset(newBlockPtr, 0, DATA_BLOCK_SIZE);
        }

        dblock_index_t index = inode->internal.direct_data[i];
        byte *block = &fs->dblocks[index * DATA_BLOCK_SIZE];
        size_t block_offset = (current_size + temp) % DATA_BLOCK_SIZE;
        size_t space_remaining = DATA_BLOCK_SIZE - block_offset;
        size_t to_write;
        if (n < space_remaining) {
            to_write = n;
        } else {
        to_write = space_remaining;
        }
        memcpy(block + block_offset, data + temp, to_write);

        temp = temp + to_write;
        n = n- to_write;

    }

    *written = temp;
    *np = n; 
    return SUCCESS;

}

fs_retcode_t writing_indirect(filesystem_t *fs, inode_t *inode, byte *data, size_t *np, size_t *written, size_t start_offset) {

    size_t n = *np;
    size_t temp = 0;

    dblock_index_t indirectIndex = inode->internal.indirect_dblock;

    if (indirectIndex == 0) {
        dblock_index_t newBlock;
        if (claim_available_dblock(fs, &newBlock) != SUCCESS) {
            return DBLOCK_UNAVAILABLE;  // or return the error code from claim_available_dblock()
        }
        inode->internal.indirect_dblock = newBlock;
        memset(fs->dblocks + (newBlock * DATA_BLOCK_SIZE), 0, DATA_BLOCK_SIZE);
    }

    byte *indexBlock = fs->dblocks + (indirectIndex * DATA_BLOCK_SIZE);
    size_t rawIndex = start_offset / DATA_BLOCK_SIZE;

    if (rawIndex < INODE_DIRECT_BLOCK_COUNT){
        rawIndex = INODE_DIRECT_BLOCK_COUNT;
    }
    rawIndex = rawIndex -INODE_DIRECT_BLOCK_COUNT;

    while(n>0){
        int startEntry = rawIndex % 15;
        for (int i = startEntry; i < 15 && n > 0; i++){
            dblock_index_t *entry = cast_dblock_ptr(&indexBlock[i * sizeof(dblock_index_t)]);

            if (*entry == 0) {
                fs_retcode_t result = claim_available_dblock(fs, entry);
                if (result != SUCCESS) {
                    return result;
                }

                byte *newBlockPtr = fs->dblocks + ((*entry) * DATA_BLOCK_SIZE);
                memset(newBlockPtr, 0, DATA_BLOCK_SIZE);
            }

            byte *block = &fs->dblocks[*entry * DATA_BLOCK_SIZE];

            size_t bytesToWrite;
            if (n < DATA_BLOCK_SIZE) {
                bytesToWrite = n;
            } else {
            bytesToWrite = DATA_BLOCK_SIZE;
            }

            memcpy(block, data + temp, bytesToWrite);
            temp = temp + bytesToWrite;
            n = n- bytesToWrite;
        }

        dblock_index_t *next_indirect = cast_dblock_ptr(&indexBlock[DATA_BLOCK_SIZE - sizeof(dblock_index_t)]);
        if (n>0){
            if (*next_indirect == 0) {
                fs_retcode_t result = claim_available_dblock(fs, next_indirect);
                if (result != SUCCESS) {
                    return result;
                }
                byte *nextBlockStart = fs->dblocks + ((*next_indirect) * DATA_BLOCK_SIZE);
                memset(nextBlockStart, 0, DATA_BLOCK_SIZE);

            }
            indirectIndex = *next_indirect;
            indexBlock = &fs->dblocks[indirectIndex * DATA_BLOCK_SIZE];
            rawIndex = 0;
        }

    }
    *written = temp;
    *np = 0;
    return SUCCESS;

}


fs_retcode_t inode_write_data(filesystem_t *fs, inode_t *inode, void *data, size_t n)
{
    if (!fs || !inode || !data){
        return INVALID_INPUT;
    } 

    size_t current_size = inode->internal.file_size;
    size_t new_size = current_size+n;

    size_t blocks_to_allocate = BLOCKS_TO_ALLOCATE(new_size, current_size);

    if (available_dblocks(fs) < blocks_to_allocate){
        return INSUFFICIENT_DBLOCKS;
    }

    size_t written_direct = 0;
    fs_retcode_t result = writing_direct(fs, inode, (byte *)data, &n, &written_direct);
    if (result != SUCCESS){
        return result;
    }

    size_t written_indirect = 0;
    if (n > 0) {
        result = writing_indirect(fs, inode, (byte *)data + written_direct, &n, &written_indirect, current_size + written_direct);
        if (result != SUCCESS){
            return result;
        } 
    }

    inode->internal.file_size = new_size;
    return SUCCESS;

    //Check for valid input

    // do we have enough dblocks to store the data. if not, error. 

    // fill the direct nodes if necessary (helper function)

    // fill in indirect nodes if necessary (helper function)
}

fs_retcode_t inode_read_data(filesystem_t *fs, inode_t *inode, size_t offset, void *buffer, size_t n, size_t *bytes_read)
{
    (void)fs;
    (void)inode;
    (void)offset;
    (void)buffer;
    (void)n;
    (void)bytes_read;
    return NOT_IMPLEMENTED;
    
    //check to make sure inputs are valid

    //for 0 to n, use the helper function to read and copy 1 byte at a time
}

fs_retcode_t inode_modify_data(filesystem_t *fs, inode_t *inode, size_t offset, void *buffer, size_t n)
{
    (void)fs;
    (void)inode;
    (void)offset;
    (void)buffer;
    (void)n;
    return NOT_IMPLEMENTED;

    //check to see if the input is valid

    //calculate the final filesize and verify there are enough blocks to support it
    //use calculate_necessary_dblock_amount and available_dblocks


    //Write to existing data in your inode

    //For the new data, call "inode_write_data" and return
}

fs_retcode_t inode_shrink_data(filesystem_t *fs, inode_t *inode, size_t new_size)
{
    (void)fs;
    (void)inode;
    (void)new_size;
    return NOT_IMPLEMENTED;
    
    //check to see if inputs are in valid range

    //Calculate how many blocks to remove

    //helper function to free all indirect blocks

    //remove the remaining direct dblocks

    //update filesize and return
}

// make new_size to 0
fs_retcode_t inode_release_data(filesystem_t *fs, inode_t *inode)
{
    (void)fs;
    (void)inode;
    return NOT_IMPLEMENTED;
    //shrink to size 0
}
