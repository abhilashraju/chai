project(chai_server)

cmake_minimum_required(VERSION 3.5)
find_package(Boost 1.82.0 ) 
set (CMAKE_CXX_STANDARD 20)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS}) 
endif()
include_directories(../thirdparty/stdexec/include)
include_directories(../include)
add_executable(chai_server
    main.cpp)
