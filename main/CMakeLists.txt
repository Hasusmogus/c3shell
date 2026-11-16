idf_component_register(
    SRCS term.c sshio.c account.c netmgr.c server.c shell.c sshstore.c sshc.c esp/port_esp.c
    INCLUDE_DIRS .
    REQUIRES wolfssl wolfssh esp_wifi esp_netif esp_event nvs_flash esp_timer pthread lwip)
