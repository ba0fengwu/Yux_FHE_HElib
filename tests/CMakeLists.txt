include_directories(${CMAKE_SOURCE_DIR})
include_directories("${CMAKE_SOURCE_DIR}/Yux")
include_directories("${CMAKE_SOURCE_DIR}/transciphering")


add_executable(test-blockcipher-dagger-F_p         test-blockcipher-dagger-F_p.cpp)
add_executable(test-blockcipher-F_p        test-blockcipher-F_p.cpp)

add_executable(test-transciphering-dagger-F_p-16        test-transciphering-dagger-F_p-16.cpp)

add_executable(test-transciphering-F_p-16    test-transciphering-F_p-16.cpp)



#message("${SYMMETRIC_FILES}")
#message("${CMAKE_SOURCE_DIR}/Yux/")

target_link_libraries(test-blockcipher-dagger-F_p                   Symmetric)
# target_link_libraries(test-Yu2x-16      PUBLIC  Symmetric helib)
target_link_libraries(test-blockcipher-F_p                   Symmetric)

target_link_libraries(test-transciphering-dagger-F_p-16  PUBLIC Transcipher Symmetric helib)


target_link_libraries(test-transciphering-F_p-16  PUBLIC Transcipher Symmetric helib)

