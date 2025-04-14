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

    //info(1, "Searching for '%s' in inode %ld — %zu entries, direct_data[0] = %u", name, dir - fs->inodes, count, dir->internal.direct_data[0]);

    for (size_t i = 0; i < count; ++i) {
        //info(2, "Entry[%zu]: name='%s', inode_index=%d", i, entries[i].name, entries[i].inode_index);

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



int new_file(terminal_context_t *context, char *path, permission_t perms){
   if (!context || !path) {
        REPORT_RETCODE(INVALID_INPUT);
        return 0;
    }

    // Copy path and split
    char path_copy[strlen(path) + 1];
    strcpy(path_copy, path);

    // Find basename (final component)
    char *saveptr;
    char *token = strtok_r(path_copy, "/", &saveptr);
    char *prev_token = token;

    while (token) {
        prev_token = token;
        token = strtok_r(NULL, "/", &saveptr);
    }

    // Re-parse dirname
    strcpy(path_copy, path);
    char *last_slash = strrchr(path_copy, '/');
    if (last_slash) {
        *last_slash = '\0';
    } else {
        strcpy(path_copy, ".");
    }

    fs_retcode_t ret;
    inode_t *parent = resolve_path(context->fs, context->working_directory, path_copy, &ret, 0);
    if (!parent) {
        REPORT_RETCODE(ret);
        return -1;
    }

    if (get_child_inode(context->fs, parent, prev_token)) {
        REPORT_RETCODE(FILE_EXIST);
        return -1;
    }

    inode_index_t inode_idx;
    if (claim_available_inode(context->fs, &inode_idx) != SUCCESS) {
        REPORT_RETCODE(INODE_UNAVAILABLE);
        return -1;
    }

    dblock_index_t dblock_idx;
    if (claim_available_dblock(context->fs, &dblock_idx) != SUCCESS) {
        release_inode(context->fs, &context->fs->inodes[inode_idx]);
        REPORT_RETCODE(INSUFFICIENT_DBLOCKS); // Fixed error code
        return -1;
    }

    // Zero out the allocated data block
    memset(context->fs->dblocks + dblock_idx * DATA_BLOCK_SIZE, 0, DATA_BLOCK_SIZE);

    // Setup the new file's inode
    inode_t *new_inode = &context->fs->inodes[inode_idx];
    new_inode->internal.file_type = DATA_FILE;
    new_inode->internal.file_perms = FS_READ | FS_WRITE; // default file permission
    strncpy(new_inode->internal.file_name, prev_token, MAX_FILE_NAME_LEN);
    new_inode->internal.file_size = 0;
    memset(new_inode->internal.direct_data, 0, sizeof(new_inode->internal.direct_data));
    new_inode->internal.direct_data[0] = dblock_idx;
    new_inode->internal.indirect_dblock = 0;

    // Create directory entry
    size_t count = dir_entry_count(parent->internal.file_size);
    directory_entry_t *entries = (directory_entry_t *)(context->fs->dblocks + parent->internal.direct_data[0] * DATA_BLOCK_SIZE);
    int written = 0;

    for (size_t i = 0; i < count; ++i) {
        if (entries[i].inode_index == 0) {
            entries[i].inode_index = inode_idx;
            strncpy(entries[i].name, prev_token, MAX_FILE_NAME_LEN);
            written = 1;
            break;
        }
    }

    if (!written) {
        entries[count].inode_index = inode_idx;
        strncpy(entries[count].name, prev_token, MAX_FILE_NAME_LEN);
        parent->internal.file_size += sizeof(directory_entry_t);
    }

    return 0;
}




int new_directory(terminal_context_t *context, char *path)
{
    if (!context || !path) return 0;

    filesystem_t *fs = context->fs;

    
    char path_copy[MAX_FILE_NAME_LEN * 10]; // enough buffer
    strncpy(path_copy, path, sizeof(path_copy));
    path_copy[sizeof(path_copy) - 1] = '\0';

    char *saveptr;
    char *token = strtok_r(path_copy, "/", &saveptr);
    inode_t *parent = context->working_directory;
    inode_t *child = NULL;
    char *final_name = NULL;

    while (token) {
        final_name = token;
        token = strtok_r(NULL, "/", &saveptr);

        if (!token) break;

        child = get_child_inode(fs, parent, final_name);
        if (!child || child->internal.file_type != DIRECTORY) {
            REPORT_RETCODE(DIR_NOT_FOUND);
            return -1;
        }
        parent = child;
    }

    // Check if directory already exists
    if (get_child_inode(fs, parent, final_name)) {
        REPORT_RETCODE(DIRECTORY_EXIST);
        return -1;
    }

    // Allocate inode and dblock
    inode_index_t new_inode_index;
    if (claim_available_inode(fs, &new_inode_index) != SUCCESS) {
        REPORT_RETCODE(INODE_UNAVAILABLE);
        return -1;
    }

    dblock_index_t new_dblk;
    if (claim_available_dblock(fs, &new_dblk) != SUCCESS) {
        release_inode(fs, &fs->inodes[new_inode_index]);
        REPORT_RETCODE(INSUFFICIENT_DBLOCKS);
        return -1;
    }

    inode_t *new_dir = &fs->inodes[new_inode_index];
    memset(new_dir, 0, sizeof(inode_t));
    new_dir->internal.file_type = DIRECTORY;
    new_dir->internal.file_perms = FS_READ | FS_WRITE | FS_EXECUTE;
    new_dir->internal.file_size = 2 * DIRECTORY_ENTRY_SIZE;
    new_dir->internal.direct_data[0] = new_dblk;
    strncpy(new_dir->internal.file_name, final_name, MAX_FILE_NAME_LEN);

    // Set up '.' and '..' directory entries
    struct directory_entry entries[2];
    entries[0].inode_index = new_inode_index;
    strncpy(entries[0].name, ".", MAX_FILE_NAME_LEN);
    entries[1].inode_index = parent - fs->inodes;
    strncpy(entries[1].name, "..", MAX_FILE_NAME_LEN);

    if (inode_write_data(fs, new_dir, entries, sizeof(entries)) != SUCCESS) {
        release_dblock(fs, fs->dblocks + new_dblk * DATA_BLOCK_SIZE);
        release_inode(fs, new_dir);
        REPORT_RETCODE(INSUFFICIENT_DBLOCKS);
        return -1;
    }

    // Add entry to parent directory
    struct directory_entry parent_entry;
    parent_entry.inode_index = new_inode_index;
    strncpy(parent_entry.name, final_name, MAX_FILE_NAME_LEN);

    if (inode_write_data(fs, parent, &parent_entry, sizeof(parent_entry)) != SUCCESS) {
        release_dblock(fs, fs->dblocks + new_dblk * DATA_BLOCK_SIZE);
        release_inode(fs, new_dir);
        REPORT_RETCODE(INSUFFICIENT_DBLOCKS);
        return -1;
    }

    return 0;
}

int remove_file(terminal_context_t *context, char *path)
{
    if (!context || !path) {
        REPORT_RETCODE(INVALID_INPUT);
        return 0;
    }

    fs_retcode_t ret;
    inode_t *parent;
    char path_copy[strlen(path) + 1];
    strcpy(path_copy, path);

    // Extract basename
    char *saveptr;
    char *token = strtok_r(path_copy, "/", &saveptr);
    char *basename = token;
    while (token) {
        basename = token;
        token = strtok_r(NULL, "/", &saveptr);
    }

    // Get parent path
    strcpy(path_copy, path);
    char *last_slash = strrchr(path_copy, '/');
    if (last_slash) {
        *last_slash = '\0';
    } else {
        strcpy(path_copy, ".");
    }

    parent = resolve_path(context->fs, context->working_directory, path_copy, &ret, 0);
    if (!parent || parent->internal.file_type != DIRECTORY) {
        REPORT_RETCODE(ret);
        return -1;
    }

    inode_t *target = get_child_inode(context->fs, parent, basename);
    if (!target || target->internal.file_type != DATA_FILE) {
        REPORT_RETCODE(FILE_NOT_FOUND);
        return -1;
    }

    // Release data
    inode_release_data(context->fs, target);

    // Release inode
    release_inode(context->fs, target);

    // Update parent directory with tombstone
    size_t count = dir_entry_count(parent->internal.file_size);
    directory_entry_t *entries = (directory_entry_t *)(context->fs->dblocks + parent->internal.direct_data[0] * DATA_BLOCK_SIZE);
    for (size_t i = 0; i < count; ++i) {
        if (strncmp(entries[i].name, basename, MAX_FILE_NAME_LEN) == 0) {
            entries[i].inode_index = 0;
            memset(entries[i].name, 0, MAX_FILE_NAME_LEN);
            break;
        }
    }

    return 0;
}

// can only delete a directory if it is empty
int remove_directory(terminal_context_t *context, char *path)
{
    if (!context || !path) {
        REPORT_RETCODE(INVALID_INPUT);
        return 0;
    }

    // Parse path and get base name
    char path_copy[strlen(path) + 1];
    strcpy(path_copy, path);

    char *saveptr;
    char *token = strtok_r(path_copy, "/", &saveptr);
    char *prev_token = token;
    while (token) {
        prev_token = token;
        token = strtok_r(NULL, "/", &saveptr);
    }

    if (strcmp(prev_token, ".") == 0 || strcmp(prev_token, "..") == 0) {
        REPORT_RETCODE(INVALID_FILENAME);
        return -1;
    }

    // Re-parse dirname path
    strcpy(path_copy, path);
    char *last_slash = strrchr(path_copy, '/');
    if (last_slash)
        *last_slash = '\0';
    else
        strcpy(path_copy, ".");

    fs_retcode_t ret;
    inode_t *parent = resolve_path(context->fs, context->working_directory, path_copy, &ret, 0);
    if (!parent) {
        REPORT_RETCODE(ret);
        return -1;
    }

    inode_t *target = get_child_inode(context->fs, parent, prev_token);
    if (!target || target->internal.file_type != DIRECTORY) {
        REPORT_RETCODE(DIR_NOT_FOUND);
        return -1;
    }

    if (target == context->working_directory) {
        REPORT_RETCODE(ATTEMPT_DELETE_CWD);
        return -1;
    }

   
    size_t dir_size = target->internal.file_size;
    size_t entry_count = dir_entry_count(dir_size);
    directory_entry_t *entries = (directory_entry_t *)(context->fs->dblocks + target->internal.direct_data[0] * DATA_BLOCK_SIZE);

    int non_special_count = 0;
    for (size_t i = 0; i < entry_count; ++i) {
        if (entries[i].inode_index != 0 &&
            strcmp(entries[i].name, ".") != 0 &&
            strcmp(entries[i].name, "..") != 0) {
            non_special_count++;
        }
    }

    if (non_special_count > 0) {
        REPORT_RETCODE(DIR_NOT_EMPTY);
        return -1;
    }

    
    size_t parent_entry_count = dir_entry_count(parent->internal.file_size);
    directory_entry_t *parent_entries = (directory_entry_t *)(context->fs->dblocks + parent->internal.direct_data[0] * DATA_BLOCK_SIZE);

    int found_index = -1;
    for (size_t i = 0; i < parent_entry_count; ++i) {
        if (parent_entries[i].inode_index != 0 &&
            strncmp(parent_entries[i].name, prev_token, MAX_FILE_NAME_LEN) == 0) {
            parent_entries[i].inode_index = 0;
            memset(parent_entries[i].name, 0, MAX_FILE_NAME_LEN);
            found_index = i;
            break;
        }
    }

    if (found_index == -1) {
        REPORT_RETCODE(SYSTEM_ERROR);
        return -1;
    }

    //  Shrink file if tombstone was at the end
    int shrink = 1;
    for (size_t i = found_index + 1; i < parent_entry_count; ++i) {
        if (parent_entries[i].inode_index != 0) {
            shrink = 0;
            break;
        }
    }
    if (shrink) {
        parent->internal.file_size -= sizeof(directory_entry_t);
    }

    
    inode_release_data(context->fs, target);
    release_inode(context->fs, target);

    return 0;
}

int change_directory(terminal_context_t *context, char *path)
{
    if (!context || !path) {
        REPORT_RETCODE(INVALID_INPUT);
        return 0;
    }

    fs_retcode_t ret;
    inode_t *target = resolve_path(context->fs, context->working_directory, path, &ret, 0);

    if (!target) {
        REPORT_RETCODE(ret);
        return -1;
    }

    if (target->internal.file_type != DIRECTORY) {
        REPORT_RETCODE(INVALID_FILE_TYPE);
        return -1;
    }

    context->working_directory = target;
    return 0;
}

static void print_permissions(file_type_t type, permission_t perms) {
    printf("%c", type == DIRECTORY ? 'd' : 'f');
    printf("%c", (perms & FS_READ) ? 'r' : '-');
    printf("%c", (perms & FS_WRITE) ? 'w' : '-');
    printf("%c", (perms & FS_EXECUTE) ? 'x' : '-');
}

int list(terminal_context_t *context, char *path)
{
    if (!context || !path) return 0;

    fs_retcode_t ret;
    inode_t *target = resolve_path(context->fs, context->working_directory, path, &ret, 0);

    if (!target) {
        if (ret == FILE_NOT_FOUND || ret == DIR_NOT_FOUND)
            REPORT_RETCODE(NOT_FOUND);
        else
            REPORT_RETCODE(ret);
        return -1;
    }

    if (target->internal.file_type == DATA_FILE) {
        // Print file info
        print_permissions(target->internal.file_type, target->internal.file_perms);
        printf("\t%lu\t%s\n", target->internal.file_size, target->internal.file_name);
        return 0;
    }

    // It's a directory — read entries
    size_t file_size = target->internal.file_size;
    size_t buffer_size = file_size;
    byte *buffer = malloc(buffer_size);
    if (!buffer) return -1;

    size_t bytes_read = 0;
    if (inode_read_data(context->fs, target, 0, buffer, buffer_size, &bytes_read) != SUCCESS) {
        free(buffer);
        REPORT_RETCODE(SYSTEM_ERROR);
        return -1;
    }

    size_t entry_size = sizeof(inode_index_t) + MAX_FILE_NAME_LEN;
    size_t count = bytes_read / entry_size;

    for (size_t i = 0; i < count; ++i) {
        inode_index_t *entry_idx = (inode_index_t *)(buffer + i * entry_size);
        char *entry_name = (char *)(buffer + i * entry_size + sizeof(inode_index_t));

        if (*entry_name == '\0') continue;

        inode_t *entry_inode = &context->fs->inodes[*entry_idx];
        print_permissions(entry_inode->internal.file_type, entry_inode->internal.file_perms);
        printf("\t%lu\t%s", entry_inode->internal.file_size, entry_name);

        // Show symbolic name for "."
        if (strcmp(entry_name, ".") == 0) {
            printf(" -> %s", entry_inode->internal.file_name);
        }

        printf("\n");
    }

    free(buffer);
    return 0;
}

char *get_path_string(terminal_context_t *context)
{
    if (!context || !context->fs || !context->working_directory) {
        return strdup("");  // empty string if context is null
    }

    filesystem_t *fs = context->fs;
    inode_t *current = context->working_directory;
    inode_t *root = &fs->inodes[0];

    // Prepare temporary array to hold path segments (up to depth 100)
    char *segments[100];
    int count = 0;

    while (current != root) {
        segments[count++] = strdup(current->internal.file_name);

        inode_t *parent = get_child_inode(fs, current, "..");
        if (!parent) break;
        current = parent;
    }

    // Add root
    segments[count++] = strdup("root");

    // Calculate total length needed
    size_t total_len = 0;
    for (int i = count - 1; i >= 0; --i) {
        total_len += strlen(segments[i]);
        if (i != 0) total_len += 1;  // for '/'
    }

    char *result = malloc(total_len + 1);
    if (!result) return NULL;

    result[0] = '\0';

    for (int i = count - 1; i >= 0; --i) {
        strcat(result, segments[i]);
        if (i != 0) strcat(result, "/");
        free(segments[i]);  // clean up
    }

    return result;
}

static void print_tree(filesystem_t *fs, inode_t *inode, int level) {
    if (!inode) return;

    // Print file or directory name with correct indentation
    printf("%*s%s\n", level * 3, "", inode->internal.file_name);

    if (inode->internal.file_type != DIRECTORY) return;

    // Iterate through directory entries
    byte *block = fs->dblocks + inode->internal.direct_data[0] * DATA_BLOCK_SIZE;
    size_t entries = inode->internal.file_size / DIRECTORY_ENTRY_SIZE;

    for (size_t i = 0; i < entries; ++i) {
        directory_entry_t *entry = (directory_entry_t *)(block + i * DIRECTORY_ENTRY_SIZE);

        if (entry->inode_index == 0 || strcmp(entry->name, ".") == 0 || strcmp(entry->name, "..") == 0) {
            continue; // skip empty/tombstone entries and special entries
        }

        inode_t *child = &fs->inodes[entry->inode_index];
        print_tree(fs, child, level + 1);
    }
}


int tree(terminal_context_t *context, char *path)
{
    if (!context || !path) return 0;

    fs_retcode_t ret;
    inode_t *target = resolve_path(context->fs, context->working_directory, path, &ret, false);

    if (!target) {
        REPORT_RETCODE(ret == DIR_NOT_FOUND ? NOT_FOUND : ret);
        return -1;
    }

    print_tree(context->fs, target, 0);
    return 0;

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

