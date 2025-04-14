#include "filesys.h"
#include "debug.h"
#include "utility.h"

#include <string.h>
#include <stdbool.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define DIRECTORY_ENTRY_SIZE (sizeof(inode_index_t) + MAX_FILE_NAME_LEN)
#define DIRECTORY_ENTRIES_PER_DATABLOCK (DATA_BLOCK_SIZE / DIRECTORY_ENTRY_SIZE)

#define TRY_FREE_ON_ERROR(ptr, retcode) do { free(ptr); REPORT_RETCODE(retcode); return -1; } while(0)
    #define FAIL_EARLY_WITH(msg) do { REPORT_RETCODE(msg); return -1; } while(0)

// ----------------------- CORE FUNCTION ----------------------- //

typedef struct directory_entry {
    inode_index_t inode_index;
    char name[MAX_FILE_NAME_LEN];
} directory_entry_t;



static int name_match(const char *a, const char *b) {
    return strncmp(a, b, MAX_FILE_NAME_LEN) == 0;
}

static size_t dir_entry_count(size_t size) {
    size_t entry_size = sizeof(struct directory_entry);
    return size / entry_size;
}

static inode_t *get_child_inode(filesystem_t *fs, inode_t *dir, const char *name) {
    
    if(dir->internal.file_type != DIRECTORY){
        return NULL;
    }
    if (strcmp(name, "..") == 0 && dir == &fs->inodes[0]) {
        return &fs->inodes[0];
    }

    size_t count = dir_entry_count(dir->internal.file_size);
    struct directory_entry *entries = (struct directory_entry *)(fs->dblocks + dir->internal.direct_data[0] * DATA_BLOCK_SIZE);

    info(1, "Searching for '%s' in inode %ld — %zu entries, direct_data[0] = %u", name, dir - fs->inodes, count, dir->internal.direct_data[0]);

    size_t i = 0;
while (i < count) {
    const char *entry_name = entries[i].name;
    inode_index_t index = entries[i].inode_index;

    info(2, "Entry[%zu]: name='%s', inode_index=%d", i, entry_name, index);

    if (index && name_match(entry_name, name)) {
        return &fs->inodes[index];
    }

    ++i;
}

    return NULL;
}


static inode_t *resolve_path(filesystem_t *fs, inode_t *start, char *path, fs_retcode_t *ret, int is_final_expected_file) {
    if (!fs || !start || !path) {
        if (ret) {
            *ret = INVALID_INPUT;
        }
        return NULL;
    }

    inode_t *current = start;
    char *saveptr;
    char *token = strtok_r(path, "/", &saveptr);

    while (token) {
        char *next_token = strtok_r(NULL, "/", &saveptr);
        int is_last_token = (next_token == NULL);

        if (strlen(token) == 0 || strcmp(token, ".") == 0) {
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
        return 0;  
    }

    const char *basename = path;
    const char *slash = path;
    
    // Find the last slash to get the basename
    while (*slash) {
        if (*slash == '/') {
            basename = slash + 1;
        }
        slash++;
    }
    
    char dirname[256];
    if (basename == path) {
        strcpy(dirname, ".");
    } else {
        size_t dir_len = basename - path - 1;
        if (dir_len == 0) {
            strcpy(dirname, "/");
        } else {
            memcpy(dirname, path, dir_len);
            dirname[dir_len] = '\0';
        }
    }

    fs_retcode_t ret;
    inode_t *parent = NULL;
    inode_index_t inode_idx;
    dblock_index_t dblock_idx;

do {
    parent = resolve_path(context->fs, context->working_directory, dirname, &ret, 0);
    if (!parent) {
        REPORT_RETCODE(ret);
        break;
    }

    if (get_child_inode(context->fs, parent, basename)) {
        REPORT_RETCODE(FILE_EXIST);
        break;
    }

    if (claim_available_inode(context->fs, &inode_idx) != SUCCESS) {
        REPORT_RETCODE(INODE_UNAVAILABLE);
        break;
    }

    if (claim_available_dblock(context->fs, &dblock_idx) != SUCCESS) {
        release_inode(context->fs, &context->fs->inodes[inode_idx]);
        REPORT_RETCODE(INSUFFICIENT_DBLOCKS);
        break;
    }

    return 0;

} while (0);

    return -1;


    memset(context->fs->dblocks + dblock_idx * DATA_BLOCK_SIZE, 0, DATA_BLOCK_SIZE);

    inode_t *new_inode = &context->fs->inodes[inode_idx];
    struct inode_internal *meta = &new_inode->internal;

    *meta = (struct inode_internal){
        .file_type = DATA_FILE,
        .file_perms = perms,
        .file_size = 0,
        .indirect_dblock = 0
    };

    strncpy(meta->file_name, basename, MAX_FILE_NAME_LEN);

    memset(meta->direct_data, 0, sizeof(meta->direct_data));
    meta->direct_data[0] = dblock_idx;

    directory_entry_t *entries = (directory_entry_t *)(context->fs->dblocks + parent->internal.direct_data[0] * DATA_BLOCK_SIZE);

    size_t count = parent->internal.file_size / sizeof(directory_entry_t);
    int written = 0;

    
    for (size_t i = 0; i < count; ++i) {
        if (entries[i].inode_index == 0) {
            entries[i].inode_index = inode_idx;
            strncpy(entries[i].name, basename, MAX_FILE_NAME_LEN);
            written = 1;
            break;
        }
    }

    if (!written) {
        entries[count].inode_index = inode_idx;
        strncpy(entries[count].name, basename, MAX_FILE_NAME_LEN);
        parent->internal.file_size += sizeof(directory_entry_t);
    }

    return 0;
}



int new_directory(terminal_context_t *context, char *path)
{
    if (!context || !path) {
        return 0;
    }
    
    filesystem_t *fs = context->fs;

    char buffer[MAX_FILE_NAME_LEN * 10];
    strncpy(buffer, path, sizeof(buffer));
    buffer[sizeof(buffer) - 1] = '\0';

    char *saveptr = NULL;
    char *token = strtok_r(buffer, "/", &saveptr);
    inode_t *parent = context->working_directory;
    inode_t *child = NULL;
    char *last_component = NULL;

    while (token) {
        last_component = token;
        token = strtok_r(NULL, "/", &saveptr);

        if (!token) break;

        child = get_child_inode(fs, parent, last_component);
        if (!child || child->internal.file_type != DIRECTORY) {
            REPORT_RETCODE(DIR_NOT_FOUND);
            return -1;
        }
        parent = child;
    }

    if (get_child_inode(fs, parent, last_component)) {
        REPORT_RETCODE(DIRECTORY_EXIST);
        return -1;
    }

    inode_index_t new_inode_index = 0;
    if (claim_available_inode(fs, &new_inode_index) != SUCCESS) {
        REPORT_RETCODE(INODE_UNAVAILABLE);
        return -1;
    }

    dblock_index_t new_dblock_index = 0;
    if (claim_available_dblock(fs, &new_dblock_index) != SUCCESS) {
        release_inode(fs, &fs->inodes[new_inode_index]);
        REPORT_RETCODE(INSUFFICIENT_DBLOCKS);
        return -1;
    }

    inode_t *new_dir = &fs->inodes[new_inode_index];
    memset(new_dir, 0, sizeof(inode_t));
    struct inode_internal *meta = &new_dir->internal;

    meta->file_type = DIRECTORY;
    meta->file_perms = FS_READ | FS_WRITE | FS_EXECUTE;
    meta->file_size = 2 * DIRECTORY_ENTRY_SIZE;
    meta->direct_data[0] = new_dblock_index;
    strncpy(meta->file_name, last_component, MAX_FILE_NAME_LEN);

    struct directory_entry self_entries[2] = {
        { .inode_index = new_inode_index, .name = "." },
        { .inode_index = (inode_index_t)(parent - fs->inodes), .name = ".." }
    };

    if (inode_write_data(fs, new_dir, self_entries, sizeof(self_entries)) != SUCCESS) {
        release_dblock(fs, fs->dblocks + new_dblock_index * DATA_BLOCK_SIZE);
        release_inode(fs, new_dir);
        REPORT_RETCODE(INSUFFICIENT_DBLOCKS);
        return -1;
    }

    struct directory_entry new_entry = {
        .inode_index = new_inode_index
    };
    strncpy(new_entry.name, last_component, MAX_FILE_NAME_LEN);

    if (inode_write_data(fs, parent, &new_entry, sizeof(new_entry)) != SUCCESS) {
        release_dblock(fs, fs->dblocks + new_dblock_index * DATA_BLOCK_SIZE);
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

    char *saveptr = NULL;
    char *basename = NULL;
    for (char *segment = strtok_r(path_copy, "/", &saveptr); segment != NULL; segment = strtok_r(NULL, "/", &saveptr)) {
        basename = segment;
    }

    strcpy(path_copy, path);
    char *slash_position = strrchr(path_copy, '/');
    if (slash_position != NULL) {
       *slash_position = '\0';
    } else {
      strcpy(path_copy, ".");
    }   

    parent = resolve_path(context->fs, context->working_directory, path_copy, &ret, 0);
    bool invalid_parent = (parent == NULL || parent->internal.file_type != DIRECTORY);
    if (invalid_parent) {
     REPORT_RETCODE(ret);
        return -1;
    }

    inode_t *target = get_child_inode(context->fs, parent, basename);
    bool invalid_target = (target == NULL || target->internal.file_type != DATA_FILE);
    if (invalid_target) {
        REPORT_RETCODE(FILE_NOT_FOUND);
        return -1;
    }

    inode_release_data(context->fs, target);

    //  inode
    release_inode(context->fs, target);

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

int remove_directory(terminal_context_t *context, char *path)
{
    if (!context || !path) {
        REPORT_RETCODE(INVALID_INPUT);
        return 0;
    }

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

    fs_retcode_t status;
    inode_t *target;
    target = resolve_path(context->fs, context->working_directory, path, &status, 0);

    if (!target) {
        if (status == FILE_NOT_FOUND || status == DIR_NOT_FOUND)
            REPORT_RETCODE(NOT_FOUND);
        else
            REPORT_RETCODE(status);
        return -1;
    }

    if (target->internal.file_type == DATA_FILE) {
        print_permissions(target->internal.file_type, target->internal.file_perms);
        printf("\t%lu\t%s\n", target->internal.file_size, target->internal.file_name);
        return 0;
    }

    filesystem_t *fs = context->fs;
    dblock_index_t block_idx = target->internal.direct_data[0];
    
    if (block_idx >= fs->dblock_count) {
        REPORT_RETCODE(SYSTEM_ERROR);
        return -1;
    }
    
    byte *dir_data = fs->dblocks + (block_idx * DATA_BLOCK_SIZE);
    int entry_count = target->internal.file_size / DIRECTORY_ENTRY_SIZE;
    
    for (int i = 0; i < entry_count; i++) {
        directory_entry_t *entry = (directory_entry_t*)(dir_data + i * DIRECTORY_ENTRY_SIZE);
        
        if (entry->name[0] == '\0') continue;
        
        inode_index_t idx = entry->inode_index;
        if (idx >= fs->inode_count) continue;
        
        inode_t *entry_inode = &fs->inodes[idx];
        
        print_permissions(entry_inode->internal.file_type, entry_inode->internal.file_perms);
        printf("\t%lu\t%s", entry_inode->internal.file_size, entry->name);
        
        if (strcmp(entry->name, ".") == 0) {
            printf(" -> %s", entry_inode->internal.file_name);
        }
        
        printf("\n");
    }
    
    return 0;
}

char *get_path_string(terminal_context_t *context)
{
    if (context == NULL) goto error_case;
    if (context->fs == NULL) goto error_case;
    if (context->working_directory == NULL) goto error_case;
    
    filesystem_t *system = context->fs;
    inode_t *node = context->working_directory;
    inode_t *start = &system->inodes[0];
    
    #define MAX_PATH_DEPTH 256
    void *name_ptrs[MAX_PATH_DEPTH];
    int depth = 0;
    
    do {
        name_ptrs[depth++] = strdup(node->internal.file_name);
        
        if (node == start) break;
        
        inode_t *up;
        
        int found = 0;
        byte *entries = system->dblocks + (node->internal.direct_data[0] * DATA_BLOCK_SIZE);
        int entry_count = node->internal.file_size / DIRECTORY_ENTRY_SIZE; 
        
        for (int i = 0; i < entry_count; i++) {
            directory_entry_t *e = (directory_entry_t*)(entries + i * DIRECTORY_ENTRY_SIZE);
            if (e->name[0] == '.' && e->name[1] == '.' && e->name[2] == 0) {
                up = &system->inodes[e->inode_index];
                found = 1;
                break;
            }
        }
        
        if (!found) break;
        
        node = up;
    } while (depth < MAX_PATH_DEPTH);
    
    if (depth == 0 || depth >= MAX_PATH_DEPTH) goto cleanup;
    
    if (strcmp((char*)name_ptrs[depth-1], "root") != 0) {
        name_ptrs[depth++] = strdup("root");
    }
    
    size_t size = 0;
    for (int i = 0; i < depth; i++) {
        size += strlen((char*)name_ptrs[i]);
    }
    
    size += depth;
    
    char *out = (char*)malloc(size);
    if (out == NULL) goto cleanup;
    
    out[0] = 0;
    
    {
        int pos = 0;
        for (int i = depth-1; i >= 0; i--) {
            char *part = (char*)name_ptrs[i];
            int len = strlen(part);
            memcpy(out + pos, part, len);
            pos += len;
            
            if (i > 0) {
                out[pos++] = '/';
            }
        }
        
        out[pos] = 0;
    }
    
    cleanup:
    {
        for (int i = 0; i < depth; i++) {
            free(name_ptrs[i]);
        }
    }
    
    return out;
    
    error_case:
    return strdup("");
}


typedef struct visit_context {
    int spaces;
    filesystem_t *system;
} visit_context_t;




static void print_tree(filesystem_t *fs, inode_t *inode, int level) {
    if (!inode) return;

    printf("%*s%s\n", level * 3, "", inode->internal.file_name);

    if (inode->internal.file_type != DIRECTORY) return;

    byte *block = fs->dblocks + inode->internal.direct_data[0] * DATA_BLOCK_SIZE;
    size_t entries = inode->internal.file_size / DIRECTORY_ENTRY_SIZE;

    for (size_t i = 0; i < entries; ++i) {
        directory_entry_t *entry = (directory_entry_t *)(block + i * DIRECTORY_ENTRY_SIZE);

        if (entry->inode_index == 0 || 
            strcmp(entry->name, ".") == 0 || 
            strcmp(entry->name, "..") == 0) {
            continue;
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
        if (ret == DIR_NOT_FOUND) {
            REPORT_RETCODE(DIR_NOT_FOUND);
        } else {
            REPORT_RETCODE(NOT_FOUND);
        }
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
    
}

fs_file_t fs_open(terminal_context_t *context, char *path)
{
    struct fs_file *handle = NULL;
    
    if (context == NULL) return NULL;
    if (path == NULL) return NULL;
    
    handle = (struct fs_file*)malloc(sizeof(struct fs_file));
    if (!handle) return NULL;
    
    handle->offset = 0;
    handle->fs = context->fs;
    handle->inode = NULL;
    
    char *path_buffer = strdup(path);
    if (!path_buffer) {
        free(handle);
        return NULL;
    }
    
    fs_retcode_t result_code;
    inode_t *found_inode = resolve_path(context->fs, context->working_directory, path_buffer, &result_code, 1);
    
    free(path_buffer);
    
    if (result_code != SUCCESS) {
        REPORT_RETCODE(result_code);
        free(handle);
        return NULL;
    }
    
    handle->inode = found_inode;
    
    return handle;
}

void fs_close(fs_file_t file)
{
    if (!file) return; 
    free(file);
}

size_t fs_read(fs_file_t file, void *buffer, size_t n)
{
    size_t data_transferred = 0;
    
    if (buffer == NULL || file == NULL) {
        return data_transferred;
    }
    
    filesystem_t *filesystem = file->fs;
    size_t current_pos = file->offset;
    inode_t *target = file->inode;
    
    fs_retcode_t status = inode_read_data(filesystem, target, current_pos, buffer, n, &data_transferred
    );
    
    if (status == SUCCESS && data_transferred > 0) {
        file->offset = current_pos + data_transferred;
    }
    
    return data_transferred;
}

size_t fs_write(fs_file_t file, void *buffer, size_t n)
{
    if (!n) goto failure;
    if (!buffer) goto failure;
    if (!file) goto failure;
    
    filesystem_t *fs = file->fs;
    inode_t *entity = file->inode;
    const size_t current_position = file->offset;
    const size_t entity_size = entity->internal.file_size;
    
    enum { WITHIN_BOUNDS, BEYOND_EOF } scenario;
    if (current_position <= entity_size) {
        scenario = WITHIN_BOUNDS;
    } else {
        scenario = BEYOND_EOF;
    }

    
    if (scenario == WITHIN_BOUNDS) {
        fs_retcode_t outcome;
        outcome = inode_modify_data(fs, entity, current_position, buffer, n);
        
        if (SUCCESS != outcome) {
            REPORT_RETCODE(outcome);
            goto failure;
        }
        
        goto success;
    }
    
    
    size_t void_size = current_position - entity_size;
    byte *void_data = NULL;
    fs_retcode_t void_result, write_result;
        
    void_data = calloc(void_size, sizeof(byte));
    if (!void_data) goto failure;
        
    void_result = inode_write_data(fs, entity, void_data, void_size);
    free(void_data);
        
    if (SUCCESS != void_result) {
        REPORT_RETCODE(void_result);
            goto failure;
    }
        
    write_result = inode_write_data(fs, entity, buffer, n);
        
    if (SUCCESS != write_result) {
        REPORT_RETCODE(write_result);
        goto failure;
    }
    
    
success:
    file->offset += n;
    return n;
    
failure:
    return 0;
}

int fs_seek(fs_file_t file, seek_mode_t seek_mode, int offset)
{
    long target_pos;
    
    if (file == NULL || file == (fs_file_t)-1)
        return -1;
        
    if (!(seek_mode == FS_SEEK_START || seek_mode == FS_SEEK_CURRENT ||seek_mode == FS_SEEK_END)){
        return -1;
    }   
    size_t current_size = file->inode->internal.file_size;
    
    if (seek_mode == FS_SEEK_START) {
        target_pos = offset;
    }
    else if (seek_mode == FS_SEEK_CURRENT) {
        target_pos = (long)file->offset + offset;
    }
    else {
        target_pos = (long)current_size + offset;
    }
    
    if (target_pos < 0)
        return -1;
        
    file->offset = MIN((size_t)target_pos, current_size);
                   
    return 0;

}

