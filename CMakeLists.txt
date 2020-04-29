cmake_minimum_required(VERSION 2.8)

project(CryptoArticle)

file(GLOB PROJECT_SRC
    "src/*.cpp"
    "src/include/*.h"
    "src/twofish/common/*.*"
    "resources/*.*"
)

add_executable(${PROJECT_NAME} ${PROJECT_SRC})

target_include_directories(${PROJECT_NAME} PRIVATE src/include)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/resources/text100000.txt
     ${CMAKE_CURRENT_SOURCE_DIR}/resources/text1000.txt
     ${CMAKE_CURRENT_SOURCE_DIR}/resources/text10000.txt
     ${CMAKE_CURRENT_SOURCE_DIR}/resources/key.txt
     ${CMAKE_CURRENT_SOURCE_DIR}/resources/des.txt
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
