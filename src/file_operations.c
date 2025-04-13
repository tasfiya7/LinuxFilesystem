#include "filesys.h"
#include "debug.h"
#include "utility.h"

#include <string.h>
#include <stdbool.h>

#define DIRECTORY_ENTRY_SIZE (sizeof(inode_index_t) + MAX_FILE_NAME_LEN)
#define DIRECTORY_ENTRIES_PER_DATABLOCK (DATA_BLOCK_SIZE / DIRECTORY_ENTRY_SIZE)

// ----------------------- CORE FUNCTION ----------------------- //

typedef struct directory_entry {
    inode_index_t inode_index;
    char name[MAX_FILE_NAME_LEN];
} directory_entry_t;



// Helper: compare two names (up to MAX_FILE_NAME_LEN chars)
static int name_match(const char *a, const char *b) {
    return strncmp(a, b, MAX_FILE_NAME_LEN) == 0;
}

// Helper: get directory entry count from file size
static size_t dir_entry_count(size_t size) {
    return size / sizeof(struct directory_entry);
}

// Helper: try to find a child inode by name
static inode_t *get_child_inode(filesystem_t *fs, inode_t *dir, const char *name) {
    if (dir->internal.file_type != DIRECTORY) return NULL;

    // Special case: ".." at root stays at root
    if (strcmp(name, "..") == 0 && dir == &fs->inodes[0]) {
        return &fs->inodes[0];
    }

    size_t count = dir_entry_count(dir->internal.file_size);
    struct directory_entry *entries = (struct directory_entry *)(fs->dblocks + dir->internal.direct_data[0] * DATA_BLOCK_SIZE);

    info(1, "Searching for '%s' in inode %ld — %zu entries, direct_data[0] = %u", name, dir - fs->inodes, count, dir->internal.direct_data[0]);

    for (size_t i = 0; i < count; ++i) {
        info(2, "Entry[%zu]: name='%s', inode_index=%d", i, entries[i].name, entries[i].inode_index);

        if (entries[i].inode_index == 0) continue;

        if (name_match(entries[i].name, name)) {
            return &fs->inodes[entries[i].inode_index];
        }
    }

    return NULL;
}


// Helper: resolve path into inode
static inode_t *resolve_path(filesystem_t *fs, inode_t *start, char *path, fs_retcode_t *ret, int is_final_expected_file) {
    if (!fs || !start || !path) {
        *ret = INVALID_INPUT;
        return NULL;
    }

    inode_t *current = start;
    char *saveptr;
    char *token = strtok_r(path, "/", &saveptr);

    while (token) {
        char *next_token = strtok_r(NULL, "/", &saveptr);
        int is_last_token = (next_token == NULL);

        if (strlen(token) == 0 || strcmp(token, ".") == 0) {
            // Skip current dir
        } else if (strcmp(token, "..") == 0) {
            if (current == &fs->inodes[0]) {
                *ret = DIR_NOT_FOUND;  // too many ".."
                return NULL;
            }
            inode_t *up = get_child_inode(fs, current, "..");
            if (!up) {
                *ret = DIR_NOT_FOUND;
                return NULL;
            }
            current = up;
        }else {
            inode_t *child = get_child_inode(fs, current, token);
            if (!child) {
                *ret = (is_last_token && is_final_expected_file) ? FILE_NOT_FOUND : DIR_NOT_FOUND;
                return NULL;
            }

            if (!is_last_token && child->internal.file_type != DIRECTORY) {
                *ret = DIR_NOT_FOUND;
                return NULL;
            }

            current = child;
        }

        token = next_token;
    }

    if (is_final_expected_file && current->internal.file_type != DATA_FILE) {
        *ret = INVALID_FILE_TYPE;
        return NULL;
    }

    *ret = SUCCESS;
    return current;
}



int new_file(terminal_context_t *context, char *path, permission_t perms)
{
    (void) context;
    (void) path;
    (void) perms;
    return -2;
}

int new_directory(terminal_context_t *context, char *path)
{
    (void) context;
    (void) path;
    return -2;
}

int remove_file(terminal_context_t *context, char *path)
{
    (void) context;
    (void) path;
    return -2;
}

// we can only delete a directory if it is empty!!
int remove_directory(terminal_context_t *context, char *path)
{
    (void) context;
    (void) path;
    return -2;
}

int change_directory(terminal_context_t *context, char *path)
{
    (void) context;
    (void) path;
    return -2;
}

int list(terminal_context_t *context, char *path)
{
    (void) context;
    (void) path;
    return -2;
}

char *get_path_string(terminal_context_t *context)
{
    (void) context;

    return NULL;
}

int tree(terminal_context_t *context, char *path)
{
    (void) context;
    (void) path;
    return -2;
}

//Part 2
void new_terminal(filesystem_t *fs, terminal_context_t *term)
{
    if (!fs || !term) return;

    term->fs = fs;                          
    term->working_directory = &fs->inodes[0];
    //check if inputs are valid

    //assign file system and root inode.
}

fs_file_t fs_open(terminal_context_t *context, char *path)
{
    if (!context || !path) return NULL;

    char path_copy[strlen(path) + 1];
    strcpy(path_copy, path);

    fs_retcode_t ret;
    inode_t *inode = resolve_path(context->fs, context->working_directory, path_copy, &ret, 1);

    if (ret != SUCCESS) {
        REPORT_RETCODE(ret);
        return NULL;
    }

    fs_file_t file = malloc(sizeof(struct fs_file));
    if (!file) return NULL;

    file->fs = context->fs;
    file->inode = inode;
    file->offset = 0;
    return file;
    //confirm path exists, leads to a file
    //allocate space for the file, assign its fs and inode. Set offset to 0.
    //return file


}

void fs_close(fs_file_t file)
{
    if (!file) return; 
    free(file);
}

size_t fs_read(fs_file_t file, void *buffer, size_t n)
{
    if (!file || !buffer) return 0;

    filesystem_t *fs = file->fs;
    inode_t *inode = file->inode;
    size_t offset = file->offset;

    size_t bytes_read = 0;
    fs_retcode_t ret = inode_read_data(fs, inode, offset, buffer, n, &bytes_read);

    if (ret != SUCCESS) return 0;

    file->offset += bytes_read;
    return bytes_read;
}

size_t fs_write(fs_file_t file, void *buffer, size_t n)
{
    if (file == NULL || buffer == NULL || n == 0) return 0;

    filesystem_t *fs = file->fs;
    inode_t *inode = file->inode;

    // Writing within file bounds → use modify
    if (file->offset <= inode->internal.file_size) {
        fs_retcode_t status = inode_modify_data(fs, inode, file->offset, buffer, n);
        if (status != SUCCESS) {
            REPORT_RETCODE(status);
            return 0;
        }
    } else {
        // Writing past EOF → need to pad zeros and write new data
        size_t gap = file->offset - inode->internal.file_size;
        byte *zero_pad = calloc(gap, sizeof(byte));
        if (!zero_pad) return 0;

        // Extend file with zeros to fill the gap
        fs_retcode_t pad_status = inode_write_data(fs, inode, zero_pad, gap);
        free(zero_pad);

        if (pad_status != SUCCESS) {
            REPORT_RETCODE(pad_status);
            return 0;
        }

        // Now write actual data
        fs_retcode_t write_status = inode_write_data(fs, inode, buffer, n);
        if (write_status != SUCCESS) {
            REPORT_RETCODE(write_status);
            return 0;
        }
    }

    file->offset += n;
    return n;
}

int fs_seek(fs_file_t file, seek_mode_t seek_mode, int offset)
{
    if (file == NULL || file == (fs_file_t)-1) return -1;
    if (seek_mode != FS_SEEK_START && seek_mode != FS_SEEK_CURRENT && seek_mode != FS_SEEK_END) return -1;

    size_t file_size = file->inode->internal.file_size;
    long new_offset = 0;

    switch (seek_mode)
    {
        case FS_SEEK_START:
            new_offset = offset;
            break;
        case FS_SEEK_CURRENT:
            new_offset = (long)file->offset + offset;
            break;
        case FS_SEEK_END:
            new_offset = (long)file_size + offset;
            break;
    }

    if (new_offset < 0) return -1;
    if ((size_t)new_offset > file_size) new_offset = file_size;

    file->offset = (size_t)new_offset;
    return 0;
}

