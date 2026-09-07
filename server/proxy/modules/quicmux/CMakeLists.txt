cmake_minimum_required(VERSION 3.13)

if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()
if(NOT FREERDP_DEFAULT_PROJECT_VERSION)
    set(FREERDP_DEFAULT_PROJECT_VERSION "1.0.0.0")
endif()

project(proxy-quicmux-plugin VERSION ${FREERDP_DEFAULT_PROJECT_VERSION} LANGUAGES C)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../../../cmake/)
include(CommonConfigOptions)

# quic_bridge.c переиспользуем как есть из client/quic — не копируем, компилируем прямо оттуда
set(SRCS
        quicmux_module.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../client/quic/quic_bridge.c
)

addtargetwithresourcefile(${PROJECT_NAME} FALSE "${PROJECT_VERSION}" SRCS FALSE)

target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../client/quic
)

target_compile_definitions(${PROJECT_NAME} PRIVATE $<$<BOOL:${BUILD_SHARED_LIBS}>:BUILD_SHARED_LIBS>)
target_link_libraries(${PROJECT_NAME} winpr freerdp)

installwithrpath(TARGETS ${PROJECT_NAME} DESTINATION ${FREERDP_PROXY_PLUGINDIR})

set(PROJECT_PC_REQUIRES_PRIVATE "winpr${FREERDP_API_VERSION} freerdp${FREERDP_API_VERSION}")
include(ProxyModuleConfig)
generate_proxy_module_config()

# Автоматически копируем собранный .so туда, где его реально ищет freerdp-proxy
# (FREERDP_PROXY_PLUGINDIR зашит в бинарник на этапе компиляции, поэтому
# просто "собрать в нужное место" через LIBRARY_OUTPUT_DIRECTORY не сработает —
# копия нужна отдельным шагом, при каждой пересборке).
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${FREERDP_PROXY_PLUGINDIR}"
        COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:${PROJECT_NAME}>"
        "${FREERDP_PROXY_PLUGINDIR}"
        COMMENT "Копирую ${PROJECT_NAME} в ${FREERDP_PROXY_PLUGINDIR}"
)