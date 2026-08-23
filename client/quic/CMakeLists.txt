cmake_minimum_required(VERSION 3.13)

# ── xfreerdp-quic ─────────────────────────────────────────────
add_executable(xfreerdp-quic
        quic_client.c
        quic_transport.c
        quic_bridge.c
)

target_link_libraries(xfreerdp-quic
        PRIVATE
        freerdp-client
        freerdp
        winpr
)

target_include_directories(xfreerdp-quic
        PRIVATE
        ${CMAKE_SOURCE_DIR}/include    # публичные заголовки FreeRDP
        ${CMAKE_CURRENT_SOURCE_DIR}    # наши файлы
)

# ── freerdp-quic-proxy ────────────────────────────────────────
add_executable(freerdp-quic-proxy
        quic_proxy.c
        quic_bridge.c
)

target_link_libraries(freerdp-quic-proxy
        PRIVATE
        pthread
)

target_include_directories(freerdp-quic-proxy
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

install(TARGETS xfreerdp-quic freerdp-quic-proxy
        DESTINATION ${CMAKE_INSTALL_BINDIR})