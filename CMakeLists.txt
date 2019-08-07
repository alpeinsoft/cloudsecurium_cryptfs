project(cryptfs)
set(CMAKE_AUTOMOC TRUE)

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
)

add_definitions(-O3 -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26)

add_library(${PROJECT_NAME} SHARED ${cryptfs_SRCS})
target_link_libraries(${PROJECT_NAME}
    OpenSSL::Crypto
    OpenSSL::SSL
    m
)

if(APPLE)
    target_link_libraries(${PROJECT_NAME}
        osxfuse
        )
else()
    target_link_libraries(${PROJECT_NAME}
        fuse
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


