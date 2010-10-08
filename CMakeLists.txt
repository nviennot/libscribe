cmake_minimum_required(VERSION 2.6)
project(scribe C)
add_definitions(-Wall -O2 -g)
include_directories(include)

add_library(scribe SHARED src/context.c src/clone_x86_32.c src/debug.c)

add_executable(scribe_init src/init_process.c)
install(TARGETS scribe scribe_init
	LIBRARY DESTINATION /usr/lib
	RUNTIME DESTINATION /usr/bin
)
install(FILES include/scribe.h DESTINATION /usr/include)
install(FILES include/linux/scribe_api.h DESTINATION /usr/include/linux)

add_executable(record src/scribe.c)
target_link_libraries(record scribe)

add_executable(profiler src/profiler.c)
target_link_libraries(profiler scribe)
