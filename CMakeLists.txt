cmake_minimum_required(VERSION 3.15)
project(ChatApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#                                                                                                  COMMON                                                                                                 
set(COMMON_SOURCES
    protocol/Packet.cpp
    utils/Logger.cpp
)

add_library(Common ${COMMON_SOURCES})
target_include_directories(Common PUBLIC ${CMAKE_SOURCE_DIR})

#                                                                                                  SERVER                                                                                                 
set(SERVER_SOURCES
    main.cpp
    session/Session.cpp
    session/SessionManager.cpp
    chat/Group.cpp
    chat/GroupManager.cpp
    chat/MessageRouter.cpp
    filetransfer/FileTransferManager.cpp
    filetransfer/FileDownload.cpp
    network/IOCPManager.cpp
    server/Server.cpp
    offlineManager/ManageOffline.cpp
    pool/SessionPool.cpp  
    pool/PacketPool.cpp
    authentication/SignUp.cpp
    authentication/AuthManager.cpp
)

add_executable(Server ${SERVER_SOURCES})
find_package(ZLIB REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

target_link_libraries(Server PRIVATE
    Common
    ws2_32
    mswsock
    ZLIB::ZLIB 
    PkgConfig::SODIUM
)

#                                                                                                  CLIENT                                                                                                 
set(CLIENT_SOURCES
    client/main.cpp
    client/Client.cpp
)

add_executable(Client ${CLIENT_SOURCES})

target_link_libraries(Client PRIVATE
    Common
    ws2_32
)