
project(Bro-Plugin-MQTT)

cmake_minimum_required(VERSION 2.8)

if ( NOT BRO_DIST )
    message(FATAL_ERROR "BRO_DIST not set")
endif ()

include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_custom_target(
    fix_up_event_bif_bro ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/tmp
    )

add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/tmp 
    COMMAND "../support/fixupeventsbif.sh" ${BRO_PLUGIN_BUILD} ${CMAKE_MODULE_PATH} CBro_MQTT
    )

bro_plugin_begin(CBro MQTT)
	bro_plugin_cc(src/MQTT.cc src/Plugin.cc)
	bro_plugin_bif(src/events.bif)
	bro_plugin_bif(src/types.bif)
	bro_plugin_pac(src/mqtt.pac src/mqtt-analyzer.pac src/mqtt-protocol.pac)
bro_plugin_end()
