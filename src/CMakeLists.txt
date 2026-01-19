set(EXEC_NAME "sink-demo-app")
set(LOGGER_LIB "logger-lib")
set(CLI_LIB "cli-lib")
set(AHOI_SERVICE "ahoi-service-lib")
set(SCHC_SERVICE "schc-service-lib")

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
add_library(${LOGGER_LIB} OBJECT "logger_helper.c")
target_include_directories(${LOGGER_LIB} PRIVATE
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_SOURCE_DIR}/include/sink_demo_app"
)
target_compile_definitions(${LOGGER_LIB} PRIVATE LOG_CONFIG_FILE="${LOG_CONFIG_FILE}")
target_link_libraries(${LOGGER_LIB} PRIVATE ${ZLOG_LIB} ${AHOI_SERIAL_LIB})

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
add_library(${CLI_LIB} OBJECT "cli_helper.c" $<TARGET_OBJECTS:${LOGGER_LIB}>)
target_include_directories(${CLI_LIB} PRIVATE
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_SOURCE_DIR}/include/sink_demo_app"
)
target_link_libraries(${CLI_LIB} PRIVATE ${ZLOG_LIB} ${AHOI_SERIAL_LIB})

# ---------------------------------------------------------------------------
# L2 (AHOI)
# ---------------------------------------------------------------------------
if ("${EXT}" STREQUAL "ahoi")
    add_library(${AHOI_SERVICE} OBJECT "l2_ahoi_service.c" $<TARGET_OBJECTS:${LOGGER_LIB}>)
    target_include_directories(${AHOI_SERVICE} PRIVATE
            "${PROJECT_SOURCE_DIR}/include"
            "${PROJECT_SOURCE_DIR}/include/sink_demo_app"
            "${PROJECT_SOURCE_DIR}/include/sink_demo_app/l2"

    )
    target_compile_definitions(${AHOI_SERVICE} PUBLIC L2_AHOI_EXT)
    target_link_libraries(${AHOI_SERVICE} PRIVATE ${AHOI_SERIAL_LIB} ${ZLOG_LIB})

    set(L2_LIB "${AHOI_SERVICE}")
endif ()

# ---------------------------------------------------------------------------
# SCHC service
# ---------------------------------------------------------------------------
add_library(${SCHC_SERVICE} OBJECT "schc_service.c")
target_include_directories(${SCHC_SERVICE} PRIVATE
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_SOURCE_DIR}/include/sink_demo_app"
        "${PROJECT_SOURCE_DIR}/include/sink_demo_app/services"
        "${PROJECT_SOURCE_DIR}/include/sink_demo_app/l2"
)
target_link_libraries(${SCHC_SERVICE} PRIVATE ${SCHC_FULL_SDK_LIB} ${ZLOG_LIB} ${AHOI_SERIAL_LIB})

# ---------------------------------------------------------------------------
# Executable
# ---------------------------------------------------------------------------
add_executable(${EXEC_NAME}
        "main.c"
        $<TARGET_OBJECTS:${CLI_LIB}>
        $<TARGET_OBJECTS:${LOGGER_LIB}>
        $<TARGET_OBJECTS:${SCHC_SERVICE}>
)

target_include_directories(${EXEC_NAME} PRIVATE
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_SOURCE_DIR}/include/sink_demo_app"
)

target_link_libraries(${EXEC_NAME}
        ${L2_LIB}
        ${SCHC_FULL_SDK_LIB}
        ${AHOI_SERIAL_LIB}
        ${ZLOG_LIB}
)
