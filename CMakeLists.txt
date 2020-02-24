cmake_minimum_required(VERSION 2.8)

project(CryptoArticle)

file(GLOB PROJECT_SRC
    "src/*.cpp"
    "src/include/*.h"
)

add_executable(${PROJECT_NAME} ${PROJECT_SRC})

target_include_directories(${PROJECT_NAME} PRIVATE src/include)
