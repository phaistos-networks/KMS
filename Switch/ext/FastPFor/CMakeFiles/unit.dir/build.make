# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /db/storage/Development/Projects/Trinity/Switch/ext/FastPFor

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /db/storage/Development/Projects/Trinity/Switch/ext/FastPFor

# Include any dependencies generated for this target.
include CMakeFiles/unit.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/unit.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/unit.dir/flags.make

CMakeFiles/unit.dir/src/unit.cpp.o: CMakeFiles/unit.dir/flags.make
CMakeFiles/unit.dir/src/unit.cpp.o: src/unit.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/db/storage/Development/Projects/Trinity/Switch/ext/FastPFor/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/unit.dir/src/unit.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/unit.dir/src/unit.cpp.o -c /db/storage/Development/Projects/Trinity/Switch/ext/FastPFor/src/unit.cpp

CMakeFiles/unit.dir/src/unit.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/unit.dir/src/unit.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /db/storage/Development/Projects/Trinity/Switch/ext/FastPFor/src/unit.cpp > CMakeFiles/unit.dir/src/unit.cpp.i

CMakeFiles/unit.dir/src/unit.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/unit.dir/src/unit.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /db/storage/Development/Projects/Trinity/Switch/ext/FastPFor/src/unit.cpp -o CMakeFiles/unit.dir/src/unit.cpp.s

CMakeFiles/unit.dir/src/unit.cpp.o.requires:

.PHONY : CMakeFiles/unit.dir/src/unit.cpp.o.requires

CMakeFiles/unit.dir/src/unit.cpp.o.provides: CMakeFiles/unit.dir/src/unit.cpp.o.requires
	$(MAKE) -f CMakeFiles/unit.dir/build.make CMakeFiles/unit.dir/src/unit.cpp.o.provides.build
.PHONY : CMakeFiles/unit.dir/src/unit.cpp.o.provides

CMakeFiles/unit.dir/src/unit.cpp.o.provides.build: CMakeFiles/unit.dir/src/unit.cpp.o


# Object files for target unit
unit_OBJECTS = \
"CMakeFiles/unit.dir/src/unit.cpp.o"

# External object files for target unit
unit_EXTERNAL_OBJECTS =

unit: CMakeFiles/unit.dir/src/unit.cpp.o
unit: CMakeFiles/unit.dir/build.make
unit: libFastPFor.a
unit: CMakeFiles/unit.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/db/storage/Development/Projects/Trinity/Switch/ext/FastPFor/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable unit"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/unit.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/unit.dir/build: unit

.PHONY : CMakeFiles/unit.dir/build

CMakeFiles/unit.dir/requires: CMakeFiles/unit.dir/src/unit.cpp.o.requires

.PHONY : CMakeFiles/unit.dir/requires

CMakeFiles/unit.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/unit.dir/cmake_clean.cmake
.PHONY : CMakeFiles/unit.dir/clean

CMakeFiles/unit.dir/depend:
	cd /db/storage/Development/Projects/Trinity/Switch/ext/FastPFor && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /db/storage/Development/Projects/Trinity/Switch/ext/FastPFor /db/storage/Development/Projects/Trinity/Switch/ext/FastPFor /db/storage/Development/Projects/Trinity/Switch/ext/FastPFor /db/storage/Development/Projects/Trinity/Switch/ext/FastPFor /db/storage/Development/Projects/Trinity/Switch/ext/FastPFor/CMakeFiles/unit.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/unit.dir/depend

