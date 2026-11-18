idf_component_register(
    SRCS term.c sshio.c fs.c vi.c top.c console.c ping.c script.c ipcmd.c account.c netmgr.c server.c shell.c sshstore.c sshc.c xfer.c ovpn.c vpnif.c esp/port_esp.c
    INCLUDE_DIRS .
    REQUIRES wolfssl wolfssh joltwallet__littlefs esp_wifi esp_netif esp_event nvs_flash spi_flash mbedtls esp_driver_usb_serial_jtag esp_driver_gpio vfs esp_timer pthread lwip)
# Routes pushed by the VPN server: see __wrap_ip4_route_src_hook() in esp/port_esp.c.
target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=ip4_route_src_hook")
# Traffic counters and the activity LED: see __wrap_ethernet_input() in esp/port_esp.c.
target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=ethernet_input" "-Wl,--wrap=etharp_output")
