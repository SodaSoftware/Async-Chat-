cmake_minimum_required(VERSION 3.10)
project(AsyncChatWithDB)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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