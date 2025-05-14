Linux Filesystem Simulation 

This C project simulates key aspects of the Linux filesystem, including low-level inode and file data block manipulation. The goal is to emulate core filesystem functionality by working directly with C data structures, memory management, and helper functions that mirror file operations in real operating systems.

Functionality:

Inode Management:

Allocate and free inodes.
Write to and read from inodes.
Manage direct and indirect blocks.
Handle shrinking and resizing of inode data.

File Operations:

Simulate opening, writing, reading, and closing files.
Handle internal file descriptors and file tables.
Manage file metadata and memory usage.

Filesystem Emulation:

Create a structure that mimics Linux-like file access at the block level.
Track which blocks and inodes are in use.
Ensure read/write access follows Linux behavior and boundary conditions.

See [filesystem.md](https://github.com/BatDan24/CSE220_HW3/blob/Remote_Files/src/filesystem.md) for detailed documentation of all required functions and behavior.

File Structure:

inode_manip.c – implementations for inode-related operations.

file_operations.c – implementations for file system operations.

main.c – manual testing .

CMakeLists.txt – Used to build the project with CMake.

tests/ – Includes unit tests for each part of the project.

Build and Run:
1. Configure:
cmake -S . -B build
2. Build:
cmake --build build
3. Run executable (manual test):
./build/hw3_main
4. Run unit tests:
./build/part1_tests
./build/part2_tests
./build/part3_tests
