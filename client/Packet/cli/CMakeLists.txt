
set(MODULE_NAME "pfreerdp-client-cli")
set(MODULE_PREFIX "FREERDP_CLIENT_PACKET_CLI")

include_directories(..)

set(${MODULE_PREFIX}_SRCS
	pfreerdp.c)

add_executable(${MODULE_NAME} ${${MODULE_PREFIX}_SRCS})

set(${MODULE_PREFIX}_LIBS ${${MODULE_PREFIX}_LIBS} pfreerdp-client)

target_link_libraries(${MODULE_NAME} ${${MODULE_PREFIX}_LIBS})

set_target_properties(${MODULE_NAME} PROPERTIES OUTPUT_NAME "pfreerdp")

if(NOT WIN32)
	set_target_properties(${MODULE_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "..")
endif()

install(TARGETS ${MODULE_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT client)

if(WITH_DEBUG_SYMBOLS AND MSVC)
	install(FILES ${CMAKE_PDB_BINARY_DIR}/${MODULE_NAME}.pdb DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT symbols)
endif()

set_property(TARGET ${MODULE_NAME} PROPERTY FOLDER "Client/Packet")