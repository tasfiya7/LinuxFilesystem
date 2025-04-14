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
#define MIN(a, b) ((a) < (b) ? (a) : (b))


#define BLOCKS_TO_ALLOCATE(newSize, currSize) (calculate_necessary_dblock_amount(newSize) - calculate_necessary_dblock_amount(currSize))

#define INDIRECT_DBLOCK_MAX_DATA_SIZE ( DATA_BLOCK_SIZE * INDIRECT_DBLOCK_INDEX_COUNT )

#define NEXT_INDIRECT_INDEX_OFFSET (DATA_BLOCK_SIZE - sizeof(dblock_index_t))

// ----------------------- UTILITY FUNCTION ----------------------- //



// ----------------------- CORE FUNCTION ----------------------- //

typedef struct {
    size_t block_offset;   
    size_t bytes_to_write; 
    dblock_index_t block;  
} write_operation_t;


typedef struct {
    filesystem_t *filesystem;
    struct inode_internal *inode;
    byte *source_data;
    size_t start_position;
    size_t total_bytes;
    size_t processed_bytes;
} modification_context_t;

typedef struct {
    size_t start;
    size_t finish;
} range_t;

typedef struct {
    filesystem_t* sys;
    struct inode_internal* i;
    range_t retain;
    range_t discard;
} shrink_ctx_t;

static dblock_index_t* get_indirect_ptr(filesystem_t *fs, struct inode_internal *in, size_t logical_index, bool allocate) {
    
    if (in->indirect_dblock == 0) {

        if (!allocate || claim_available_dblock(fs, &in->indirect_dblock) != SUCCESS) {
            return NULL;
        }
        memset(&fs->dblocks[in->indirect_dblock * DATA_BLOCK_SIZE], 0, DATA_BLOCK_SIZE);
    }

    size_t max = EFFECTIVE_INDIRECT_CAPACITY;
    size_t remaining = logical_index;
    dblock_index_t block = in->indirect_dblock;
    dblock_index_t* entry_ptr;
    
    do {
        byte* block_addr = fs->dblocks;
        block_addr += block * DATA_BLOCK_SIZE;
        entry_ptr = (dblock_index_t*)block_addr;
        
        if (remaining < max)
            break;
            
        if (entry_ptr[max] == 0) {
            if (!allocate)
                return NULL;
                
            dblock_index_t next_blk;
            if (SUCCESS != claim_available_dblock(fs, &next_blk))
                return NULL;
                
            entry_ptr[max] = next_blk;
            byte* next_addr = fs->dblocks + (next_blk * DATA_BLOCK_SIZE);
            memset(next_addr, 0, DATA_BLOCK_SIZE);
        }
        
        block = entry_ptr[max];
        remaining -= max;
    } while (1);
    
    return &entry_ptr[remaining];
}


static fs_retcode_t allocation(filesystem_t *fs, dblock_index_t *block_ptr) {
    if (*block_ptr != 0) {
        return SUCCESS;
    }
    
    dblock_index_t new_block;
    fs_retcode_t result = claim_available_dblock(fs, &new_block);
    if (result != SUCCESS) {
        return result;
    }
    byte *block_start = fs->dblocks + (new_block * DATA_BLOCK_SIZE);
    memset(block_start, 0, DATA_BLOCK_SIZE);
    *block_ptr = new_block;
    return SUCCESS;
}

static fs_retcode_t resolve_block(filesystem_t *fs, struct inode_internal *inode, size_t position,dblock_index_t *out_block_id) {
    size_t blockI = position / DATA_BLOCK_SIZE;
    
    if (blockI < INODE_DIRECT_BLOCK_COUNT) {
        dblock_index_t *block_ptr = &inode->direct_data[blockI];
        fs_retcode_t status = allocation(fs, block_ptr);
        if (status == SUCCESS) {
            *out_block_id = *block_ptr;
        }
        return status;
    }
    
    size_t indirectI = blockI - INODE_DIRECT_BLOCK_COUNT;
    dblock_index_t *indirect_ptr = get_indirect_ptr(fs, inode, indirectI, true);
    if (!indirect_ptr) {
        return SYSTEM_ERROR;
    }
    
    fs_retcode_t status = allocation(fs, indirect_ptr);
    if (status == SUCCESS) {
        *out_block_id = *indirect_ptr;
    }
    return status;
}



static fs_retcode_t prepare_write(filesystem_t *fs, struct inode_internal *inode, size_t file_position, size_t remaining_bytes, write_operation_t *operation) {

    operation->block_offset = file_position % DATA_BLOCK_SIZE;
    size_t available_space = DATA_BLOCK_SIZE - operation->block_offset;
    operation->bytes_to_write = MIN(remaining_bytes, available_space);
    
    fs_retcode_t result = resolve_block(fs, inode, file_position, &operation->block);
    return result;
}

static void directory_size(struct inode_internal *inode) {
    if (inode->file_type == DIRECTORY && inode->file_size < DIRECTORY_ENTRY_SIZE) {
        inode->file_size = DIRECTORY_ENTRY_SIZE;
    }
}

fs_retcode_t inode_write_data(filesystem_t *fs, inode_t *inode, void *data, size_t n)
{
    if (!fs || !inode || !data) {
        return INVALID_INPUT;
    }
    if (n == 0) {
        return SUCCESS;
    }
    struct inode_internal *in = &inode->internal;
    directory_size(in);
    
    size_t current = in->file_size;
    size_t new_size = current + n;
    size_t required = calculate_necessary_dblock_amount(new_size);
    size_t blocks_needed = required - calculate_necessary_dblock_amount(current);
                           
    if (blocks_needed > available_dblocks(fs)) {
        return INSUFFICIENT_DBLOCKS;
    }
    
    byte *d = (byte *)data;
    size_t current_position = current;
    size_t bytes_remaining = n;
    
    while (bytes_remaining > 0) {
        write_operation_t op;
        fs_retcode_t status = prepare_write(fs, in, current_position, bytes_remaining, &op);
        
        if (status != SUCCESS) {
            return status;
        }
        
        byte *dest = fs->dblocks + (op.block * DATA_BLOCK_SIZE) + op.block_offset;
        memcpy(dest, d, op.bytes_to_write);
        
        d = d + op.bytes_to_write;
        current_position = current_position + op.bytes_to_write;
        bytes_remaining = bytes_remaining - op.bytes_to_write;
    }
    
    in->file_size = new_size;
    return SUCCESS;

}

static bool is_position_valid(size_t file_size, size_t requested_position){
    return requested_position < file_size;
}

static size_t transfer_size(size_t available_bytes, size_t requested_bytes)
{
    return MIN(requested_bytes, available_bytes);

}

static dblock_index_t locate_data_block(filesystem_t *fs, struct inode_internal *inode, size_t logical_block_number, bool *success){
    *success = true;
    
    if (logical_block_number < INODE_DIRECT_BLOCK_COUNT) {
        return inode->direct_data[logical_block_number];
    }
    
    if (inode->indirect_dblock == 0) {
        *success = false;
        return 0;
    }
    
    size_t indirectI = logical_block_number - INODE_DIRECT_BLOCK_COUNT;
    if (indirectI >= INDIRECT_DBLOCK_INDEX_COUNT) {
        *success = false;
        return 0;
    }
    
    dblock_index_t *indirect_table = (dblock_index_t *)(fs->dblocks + (inode->indirect_dblock * DATA_BLOCK_SIZE));
    
    return indirect_table[indirectI];
}


static size_t read_data(filesystem_t *fs, dblock_index_t block_id, size_t start_offset, byte *destination, size_t max_bytes){

    if (block_id == 0) {
        return 0;
    }
    
    byte *source = fs->dblocks + (block_id * DATA_BLOCK_SIZE) + start_offset;
    
    memcpy(destination, source, max_bytes);
    
    return max_bytes;
}


fs_retcode_t inode_read_data(filesystem_t *fs, inode_t *inode, size_t offset, void *buffer, size_t n, size_t *bytes_read)
{

    if (!fs || !inode || !buffer || !bytes_read) {
        return INVALID_INPUT;
    }
    
    *bytes_read = 0;
    struct inode_internal *in = &inode->internal;
    
    if (!is_position_valid(in->file_size, offset)) {
        return SUCCESS;  
    }
    
    size_t remaining_in_file = in->file_size - offset;
    size_t total_to_transfer = transfer_size(remaining_in_file, n);
    
    byte *output_buffer = (byte *)buffer;
    size_t current_position = offset;
    size_t bytes_transferred = 0;
    
    while (bytes_transferred < total_to_transfer) {
        size_t current_block = current_position >> 6;
        size_t block_offset = current_position % DATA_BLOCK_SIZE;
        size_t bytes_left_in_block = DATA_BLOCK_SIZE - block_offset;
        size_t bytes_left_to_transfer = total_to_transfer - bytes_transferred;
        size_t chunk_size = MIN(bytes_left_in_block, bytes_left_to_transfer);
        
        bool block_found = false;
        dblock_index_t data_block = locate_data_block(fs, in, current_block, &block_found);
        
        if (!block_found || data_block == 0) {
            break;
        }
        
        size_t chunk_read = read_data(fs, data_block, block_offset, output_buffer + bytes_transferred, chunk_size
        );
        
        bytes_transferred = bytes_transferred + chunk_read;
        current_position = current_position + chunk_read;
        
        if (chunk_read == 0 || chunk_read < chunk_size) {
            break;
        }
    }
    
    *bytes_read = bytes_transferred;
    return SUCCESS;
   
}

static void initialize_Mod(modification_context_t *ctx,filesystem_t *fs, inode_t *inode, void *data, size_t position, size_t bytes) {
    ctx->filesystem = fs;
    ctx->inode = &inode->internal;
    ctx->source_data = (byte *)data;
    ctx->start_position = position;
    ctx->total_bytes = bytes;
    ctx->processed_bytes = 0;
}

static bool exists(filesystem_t *fs, struct inode_internal *inode, size_t blockI) {

    if (blockI < INODE_DIRECT_BLOCK_COUNT) {
        return (inode->direct_data[blockI] != 0);
    }
    
    size_t indirectI = blockI - INODE_DIRECT_BLOCK_COUNT;
    dblock_index_t *ptr = get_indirect_ptr(fs, inode, indirectI, false);
    if (ptr && *ptr) {
        return true;
    }
    return false;
}

static byte* access_block_data(filesystem_t *fs, struct inode_internal *inode, size_t blockI) {
    
    dblock_index_t block_id;
    
    if (blockI < INODE_DIRECT_BLOCK_COUNT) {
        block_id = inode->direct_data[blockI];
    } else {
        size_t indirect_idx = blockI - INODE_DIRECT_BLOCK_COUNT;
        dblock_index_t *ptr = get_indirect_ptr(fs, inode, indirect_idx, false);
        block_id = *ptr;
    }
    
    return fs->dblocks + (block_id * DATA_BLOCK_SIZE);
}

static size_t mod_chunk(modification_context_t *ctx) {

    size_t current_position = ctx->start_position + ctx->processed_bytes;
    
    size_t blockI = current_position / DATA_BLOCK_SIZE;
    size_t offset = current_position % DATA_BLOCK_SIZE;
    
    /* Ensure block exists */
    if (!exists(ctx->filesystem, ctx->inode, blockI)) {
        return 0;
    }
    
    size_t remaining_in_block = DATA_BLOCK_SIZE - offset;
    size_t remaining_to_process = ctx->total_bytes - ctx->processed_bytes;
    size_t chunk_size = MIN(remaining_in_block, remaining_to_process);
    
    byte *destination = access_block_data(ctx->filesystem, ctx->inode, blockI);
    memcpy(destination + offset, ctx->source_data + ctx->processed_bytes, chunk_size);
           
    return chunk_size;
}

static fs_retcode_t handle_mod(filesystem_t *fs, inode_t *inode, size_t position,  void *data, size_t length) {

    modification_context_t ctx;
    initialize_Mod(&ctx, fs, inode, data, position, length);
    
    while (ctx.processed_bytes < ctx.total_bytes) {
        size_t modified = mod_chunk(&ctx);
        
        if (modified == 0) {
            return INSUFFICIENT_DBLOCKS;
        }
        
        ctx.processed_bytes += modified;
    }
    
    return SUCCESS;
}


fs_retcode_t inode_modify_data(filesystem_t *fs, inode_t *inode, size_t offset, void *buffer, size_t n)
{
    if (!fs || !inode || !buffer) {
        return INVALID_INPUT;
    }
    
    struct inode_internal *in = &inode->internal;
    
    if (offset > in->file_size) {
        return INVALID_INPUT;
    }
    
    if (offset == in->file_size) {
        return inode_write_data(fs, inode, buffer, n);
    }
    
    size_t mod_end = offset + n;
    
    if (mod_end <= in->file_size) {
        return handle_mod(fs, inode, offset, buffer, n);
    }
    
    size_t existing = in->file_size - offset;
    fs_retcode_t status = handle_mod(fs, inode, offset, buffer, existing);
    
    if (status != SUCCESS) {
        return status;
    }
    
    size_t append_portion = n - existing;
    byte *append_source = (byte *)buffer + existing;
    
    return inode_write_data(fs, inode, append_source, append_portion);
}


static size_t calc_blocks(size_t size) {
    if (size == 0) {
        return 0;
    }
    return ((size - 1) / DATA_BLOCK_SIZE) + 1;

}

static void free_block(filesystem_t *fs, dblock_index_t blk_idx) {
    if (blk_idx < fs->dblock_count) {
        byte *blk = fs->dblocks + (blk_idx * DATA_BLOCK_SIZE);
        release_dblock(fs, blk);
    }
}

static void handle_direct_blocks(filesystem_t *fs, struct inode_internal *node, size_t needed, size_t existing) {
    for (size_t i = 0; i < INODE_DIRECT_BLOCK_COUNT; i++) {
        size_t idx = INODE_DIRECT_BLOCK_COUNT - i - 1;
        if (idx >= needed && idx < existing) {
        free_block(fs, node->direct_data[idx]);
        }
    }
}

static dblock_index_t* get_idx_block(filesystem_t *fs, dblock_index_t block) {
    return (dblock_index_t*)(fs->dblocks + block * DATA_BLOCK_SIZE);
}

static dblock_index_t process_idx_block(filesystem_t *fs, dblock_index_t idx_blk, dblock_index_t prev_idx_blk, size_t *offset_ptr, size_t needed, size_t existing, struct inode_internal *node) {
    dblock_index_t *indices = get_idx_block(fs, idx_blk);
    dblock_index_t next_idx_blk = indices[INDIRECT_DBLOCK_INDEX_COUNT - 1];
    size_t base = *offset_ptr;
    int all_zeros = 1;
    
    for (int i = 0; i < INDIRECT_DBLOCK_INDEX_COUNT - 1; ++i, ++(*offset_ptr)) {
        size_t global = INODE_DIRECT_BLOCK_COUNT + *offset_ptr;
        
        printf("Evaluating indirect block index %d (global %zu): new_blocks = %zu, old_blocks = %zu\n",
               i, global, needed, existing);
        
        if (global >= needed && global < existing) {
            dblock_index_t data_blk = indices[i];
            if (data_blk < fs->dblock_count) {
                free_block(fs, data_blk);
                printf("Releasing INDIRECT dblock index: %u (global index %zu)\n", data_blk, global);
            }
        }
        
        all_zeros &= (indices[i] == 0);
    }
    
    if (all_zeros && (INODE_DIRECT_BLOCK_COUNT + base) >= needed) {
        free_block(fs, idx_blk);
        printf("Releasing INDEX dblock at index block %u\n", idx_blk);
        
        if (!prev_idx_blk) {
            node->indirect_dblock = next_idx_blk;
        } else {
            get_idx_block(fs, prev_idx_blk)[INDIRECT_DBLOCK_INDEX_COUNT - 1] = next_idx_blk;
        }
        return next_idx_blk;
    }
    
    if (prev_idx_blk) {
        return next_idx_blk;
    }
    prev_idx_blk = idx_blk;
    return next_idx_blk;    
}

static void handle_indirect_blocks(filesystem_t *fs, struct inode_internal *node, size_t needed, size_t existing) {
    
    if (!node->indirect_dblock) {
        return;
    }
    
    dblock_index_t idx_blk = node->indirect_dblock;
    dblock_index_t prev_idx_blk = 0;
    size_t offset = 0;
    
    while (idx_blk) {
        dblock_index_t next = process_idx_block(fs, idx_blk, prev_idx_blk, &offset, needed, existing, node);
                                              
        if (prev_idx_blk == 0 && node->indirect_dblock != idx_blk) {
            idx_blk = next;
        } else if (next == idx_blk) {
            prev_idx_blk = idx_blk;
            idx_blk = get_idx_block(fs, idx_blk)[INDIRECT_DBLOCK_INDEX_COUNT - 1];
        } else {
            prev_idx_blk = next != idx_blk ? prev_idx_blk : idx_blk;
            idx_blk = next;
        }
    }
}



fs_retcode_t inode_shrink_data(filesystem_t* fs, inode_t* inode, size_t new_size) {
    if (fs == NULL || inode == NULL) {
        return INVALID_INPUT;
    }

    struct inode_internal *node = &inode->internal;
    
    if (new_size > node->file_size) {
        return INVALID_INPUT;
    }
    
    size_t blocks_existing = calc_blocks(node->file_size);
    size_t blocks_needed = calc_blocks(new_size);
    
    handle_direct_blocks(fs, node, blocks_needed, blocks_existing);
    handle_indirect_blocks(fs, node, blocks_needed, blocks_existing);
    
    node->file_size = new_size;
    return SUCCESS;
}

// make new_size to 0
fs_retcode_t inode_release_data(filesystem_t *fs, inode_t *inode)
{
    if (fs == NULL || inode == NULL)
    return INVALID_INPUT;

return inode_shrink_data(fs, inode, 0);
    
}
