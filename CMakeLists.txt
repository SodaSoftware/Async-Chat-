cmake_minimum_required(VERSION 3.10)
project(AsyncChatWithDB)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
include_directories(/usr/include)

# СЕРВЕР
add_executable(chat_server chat_server.cpp)
target_link_libraries(chat_server PRIVATE 
    boost_thread      # System удалили, она теперь в инклюдах
    sqlite3 
    cryptopp 
    pthread
)

# КЛИЕНТ
add_executable(chat_client chat_client.cpp)
target_link_libraries(chat_client PRIVATE 
    boost_thread 
    cryptopp 
    pthread
)
target_link_libraries(chat_client PRIVATE Qt6::Widgets)