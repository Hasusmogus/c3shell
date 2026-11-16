idf_component_register(
    SRCS term.c sshio.c fs.c vi.c account.c netmgr.c server.c shell.c sshstore.c sshc.c esp/port_esp.c
    INCLUDE_DIRS .
    REQUIRES wolfssl wolfssh joltwallet__littlefs esp_wifi esp_netif esp_event nvs_flash esp_timer pthread lwip)
