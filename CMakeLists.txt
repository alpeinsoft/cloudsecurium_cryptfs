project(cryptfs)
set(CMAKE_AUTOMOC TRUE)

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
    set(BUILD_SHARED_LIBS TRUE)
endif()

OPTION(CRYPTFS_DEBUG "Enable debug output in cryptfs" OFF)
if(CRYPTFS_DEBUG)
    message(STATUS "CRYPTFS_DEBUG ON")
    add_definitions(-DCRYTPFS_DEBUG)
endif()

OPTION(CRYPTFS_REDIRECT_DEBUG_TO_FILE "Redirect debug messages from cryptfs from stdout to file" OFF)
if(CRYPTFS_REDIRECT_DEBUG_TO_FILE)
    message(STATUS "CRYPTFS_REDIRECT_DEBUG_TO_FILE ON")
    add_definitions(-DCRYPTFS_REDIRECT_DEBUG_TO_FILE)
endif()

OPTION(CRYPTFS_REDIRECT_ERRORS_TO_FILE "Redirect error messages from cryptfs from stderr to file" OFF)
if(CRYPTFS_REDIRECT_ERRORS_TO_FILE)
    message(STATUS "CRYPTFS_REDIRECT_ERRORS_TO_FILE ON")
    add_definitions(-DCRYPTFS_REDIRECT_ERRORS_TO_FILE)
endif()

set(cryptfs_SRCS
    base32.c
    buf.c
    common.c
    crypher.c
    cryptfs.c
    key_file.c
    kref.c
    kref_alloc.c
    list.c
)


# These headers are installed for libowncloudsync to be used by 3rd party apps
set(cryptfs_HEADERS
    base32.h
    buf.h
    common.h
    crypher.h
    crypher.h
    key_file.h
    kref.h
    kref_alloc.h
    list.h
    types.h
    cfs_syscall.h
)

if(MSVC)
    list(APPEND cryptfs_SRCS win_dirent.c cfs_syscall_windows.c)
    list(APPEND cryptfs_HEADERS win_dirent.h)
else()
    list(APPEND cryptfs_SRCS cfs_syscall_unix.c)
endif()

add_definitions(-O3 -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26)

add_library(${PROJECT_NAME} SHARED ${cryptfs_SRCS})
target_link_libraries(${PROJECT_NAME}
    PRIVATE
    OpenSSL::Crypto
    OpenSSL::SSL
)
if(UNIX)
    target_link_libraries(${PROJECT_NAME}
       PRIVATE m
    )
endif()

if(APPLE)
    target_link_libraries(${PROJECT_NAME}
        PRIVATE osxfuse
        )
elseif(UNIX)
    target_link_libraries(${PROJECT_NAME}
        PRIVATE fuse
        )
else()
    add_library(DOKANFUSE SHARED IMPORTED)
    set_property(
        TARGET DOKANFUSE
        PROPERTY IMPORTED_LOCATION ${DOKANFUSE_ROOT_DIR}/dokanfuse1.dll
        )
    set_property(
        TARGET DOKANFUSE
        PROPERTY IMPORTED_IMPLIB ${DOKANFUSE_ROOT_DIR}/lib/dokanfuse1.lib
        )

    target_include_directories(${PROJECT_NAME}
        PRIVATE ${DOKANFUSE_ROOT_DIR}/include
        )
    target_link_directories(${PROJECT_NAME}
        PRIVATE ${DOKANFUSE_ROOT_DIR}
    )
    target_link_libraries(${PROJECT_NAME}
            PRIVATE DOKANFUSE
        )
endif()

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

set_target_properties( ${PROJECT_NAME}  PROPERTIES
	VERSION ${MIRALL_VERSION}
	SOVERSION ${MIRALL_SOVERSION}
	RUNTIME_OUTPUT_DIRECTORY ${BIN_OUTPUT_DIRECTORY}
)
set_target_properties( ${PROJECT_NAME} PROPERTIES
	INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}/${APPLICATION_EXECUTABLE};${CMAKE_INSTALL_RPATH}" )

if(NOT BUILD_OWNCLOUD_OSX_BUNDLE)
    install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
else()
    install(TARGETS ${PROJECT_NAME} DESTINATION ${OWNCLOUD_OSX_BUNDLE}/Contents/MacOS)
    if (SPARKLE_FOUND)
        install(DIRECTORY "${SPARKLE_LIBRARY}"
	        DESTINATION "${OWNCLOUD_OSX_BUNDLE}/Contents/Frameworks" USE_SOURCE_PERMISSIONS)
    endif (SPARKLE_FOUND)
endif()


