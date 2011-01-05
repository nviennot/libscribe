cmake_minimum_required(VERSION 2.6)
project(scribe C)
add_definitions(-Wall -O2 -g)
include_directories(include)

add_library(scribe SHARED src/context.c src/debug.c src/process.c)

add_executable(scribe_init src/init_process.c)

install(TARGETS scribe scribe_init
	LIBRARY DESTINATION /usr/lib
	RUNTIME DESTINATION /usr/bin
)
install(FILES include/scribe.h DESTINATION /usr/include)
install(FILES include/linux/scribe_events.h
	      include/linux/scribe_api.h
	      include/linux/scribe_defines.h
	DESTINATION /usr/include/linux)
