# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.18

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/sergeyb/.local/lib/python3.8/site-packages/cmake/data/bin/cmake

# The command to remove a file.
RM = /home/sergeyb/.local/lib/python3.8/site-packages/cmake/data/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/sergeyb/sources/snippets/microb

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/sergeyb/sources/snippets/microb

# Include any dependencies generated for this target.
include CMakeFiles/microb.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/microb.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/microb.dir/flags.make

CMakeFiles/microb.dir/main.c.o: CMakeFiles/microb.dir/flags.make
CMakeFiles/microb.dir/main.c.o: main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/sergeyb/sources/snippets/microb/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/microb.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/microb.dir/main.c.o -c /home/sergeyb/sources/snippets/microb/main.c

CMakeFiles/microb.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/microb.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/sergeyb/sources/snippets/microb/main.c > CMakeFiles/microb.dir/main.c.i

CMakeFiles/microb.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/microb.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/sergeyb/sources/snippets/microb/main.c -o CMakeFiles/microb.dir/main.c.s

CMakeFiles/microb.dir/cpuid.c.o: CMakeFiles/microb.dir/flags.make
CMakeFiles/microb.dir/cpuid.c.o: cpuid.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/sergeyb/sources/snippets/microb/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/microb.dir/cpuid.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/microb.dir/cpuid.c.o -c /home/sergeyb/sources/snippets/microb/cpuid.c

CMakeFiles/microb.dir/cpuid.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/microb.dir/cpuid.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/sergeyb/sources/snippets/microb/cpuid.c > CMakeFiles/microb.dir/cpuid.c.i

CMakeFiles/microb.dir/cpuid.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/microb.dir/cpuid.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/sergeyb/sources/snippets/microb/cpuid.c -o CMakeFiles/microb.dir/cpuid.c.s

CMakeFiles/microb.dir/fsync.c.o: CMakeFiles/microb.dir/flags.make
CMakeFiles/microb.dir/fsync.c.o: fsync.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/sergeyb/sources/snippets/microb/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/microb.dir/fsync.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/microb.dir/fsync.c.o -c /home/sergeyb/sources/snippets/microb/fsync.c

CMakeFiles/microb.dir/fsync.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/microb.dir/fsync.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/sergeyb/sources/snippets/microb/fsync.c > CMakeFiles/microb.dir/fsync.c.i

CMakeFiles/microb.dir/fsync.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/microb.dir/fsync.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/sergeyb/sources/snippets/microb/fsync.c -o CMakeFiles/microb.dir/fsync.c.s

CMakeFiles/microb.dir/getifaddrs.c.o: CMakeFiles/microb.dir/flags.make
CMakeFiles/microb.dir/getifaddrs.c.o: getifaddrs.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/sergeyb/sources/snippets/microb/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/microb.dir/getifaddrs.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/microb.dir/getifaddrs.c.o -c /home/sergeyb/sources/snippets/microb/getifaddrs.c

CMakeFiles/microb.dir/getifaddrs.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/microb.dir/getifaddrs.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/sergeyb/sources/snippets/microb/getifaddrs.c > CMakeFiles/microb.dir/getifaddrs.c.i

CMakeFiles/microb.dir/getifaddrs.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/microb.dir/getifaddrs.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/sergeyb/sources/snippets/microb/getifaddrs.c -o CMakeFiles/microb.dir/getifaddrs.c.s

CMakeFiles/microb.dir/malloc.c.o: CMakeFiles/microb.dir/flags.make
CMakeFiles/microb.dir/malloc.c.o: malloc.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/sergeyb/sources/snippets/microb/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/microb.dir/malloc.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/microb.dir/malloc.c.o -c /home/sergeyb/sources/snippets/microb/malloc.c

CMakeFiles/microb.dir/malloc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/microb.dir/malloc.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/sergeyb/sources/snippets/microb/malloc.c > CMakeFiles/microb.dir/malloc.c.i

CMakeFiles/microb.dir/malloc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/microb.dir/malloc.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/sergeyb/sources/snippets/microb/malloc.c -o CMakeFiles/microb.dir/malloc.c.s

CMakeFiles/microb.dir/mmap.c.o: CMakeFiles/microb.dir/flags.make
CMakeFiles/microb.dir/mmap.c.o: mmap.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/sergeyb/sources/snippets/microb/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/microb.dir/mmap.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/microb.dir/mmap.c.o -c /home/sergeyb/sources/snippets/microb/mmap.c

CMakeFiles/microb.dir/mmap.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/microb.dir/mmap.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/sergeyb/sources/snippets/microb/mmap.c > CMakeFiles/microb.dir/mmap.c.i

CMakeFiles/microb.dir/mmap.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/microb.dir/mmap.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/sergeyb/sources/snippets/microb/mmap.c -o CMakeFiles/microb.dir/mmap.c.s

CMakeFiles/microb.dir/sigbench.c.o: CMakeFiles/microb.dir/flags.make
CMakeFiles/microb.dir/sigbench.c.o: sigbench.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/sergeyb/sources/snippets/microb/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/microb.dir/sigbench.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/microb.dir/sigbench.c.o -c /home/sergeyb/sources/snippets/microb/sigbench.c

CMakeFiles/microb.dir/sigbench.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/microb.dir/sigbench.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/sergeyb/sources/snippets/microb/sigbench.c > CMakeFiles/microb.dir/sigbench.c.i

CMakeFiles/microb.dir/sigbench.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/microb.dir/sigbench.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/sergeyb/sources/snippets/microb/sigbench.c -o CMakeFiles/microb.dir/sigbench.c.s

CMakeFiles/microb.dir/vmm.c.o: CMakeFiles/microb.dir/flags.make
CMakeFiles/microb.dir/vmm.c.o: vmm.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/sergeyb/sources/snippets/microb/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/microb.dir/vmm.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/microb.dir/vmm.c.o -c /home/sergeyb/sources/snippets/microb/vmm.c

CMakeFiles/microb.dir/vmm.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/microb.dir/vmm.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/sergeyb/sources/snippets/microb/vmm.c > CMakeFiles/microb.dir/vmm.c.i

CMakeFiles/microb.dir/vmm.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/microb.dir/vmm.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/sergeyb/sources/snippets/microb/vmm.c -o CMakeFiles/microb.dir/vmm.c.s

# Object files for target microb
microb_OBJECTS = \
"CMakeFiles/microb.dir/main.c.o" \
"CMakeFiles/microb.dir/cpuid.c.o" \
"CMakeFiles/microb.dir/fsync.c.o" \
"CMakeFiles/microb.dir/getifaddrs.c.o" \
"CMakeFiles/microb.dir/malloc.c.o" \
"CMakeFiles/microb.dir/mmap.c.o" \
"CMakeFiles/microb.dir/sigbench.c.o" \
"CMakeFiles/microb.dir/vmm.c.o"

# External object files for target microb
microb_EXTERNAL_OBJECTS =

bin/microb: CMakeFiles/microb.dir/main.c.o
bin/microb: CMakeFiles/microb.dir/cpuid.c.o
bin/microb: CMakeFiles/microb.dir/fsync.c.o
bin/microb: CMakeFiles/microb.dir/getifaddrs.c.o
bin/microb: CMakeFiles/microb.dir/malloc.c.o
bin/microb: CMakeFiles/microb.dir/mmap.c.o
bin/microb: CMakeFiles/microb.dir/sigbench.c.o
bin/microb: CMakeFiles/microb.dir/vmm.c.o
bin/microb: CMakeFiles/microb.dir/build.make
bin/microb: CMakeFiles/microb.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/sergeyb/sources/snippets/microb/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Linking C executable bin/microb"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/microb.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/microb.dir/build: bin/microb

.PHONY : CMakeFiles/microb.dir/build

CMakeFiles/microb.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/microb.dir/cmake_clean.cmake
.PHONY : CMakeFiles/microb.dir/clean

CMakeFiles/microb.dir/depend:
	cd /home/sergeyb/sources/snippets/microb && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/sergeyb/sources/snippets/microb /home/sergeyb/sources/snippets/microb /home/sergeyb/sources/snippets/microb /home/sergeyb/sources/snippets/microb /home/sergeyb/sources/snippets/microb/CMakeFiles/microb.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/microb.dir/depend

