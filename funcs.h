#include<stdint.h>
 #include <sys/socket.h>
       #include <netinet/in.h>
       #include <arpa/inet.h>
#include<stdio.h>
/****************************************************************************
 * Convierte una cadena de texto a una direccion Ethernet
 * entra:
 *   dir - una direccion en formato aa:bb:cc:dd:ee:ff
 *   eth - puntero a un BYTE[ETH_ALEN] donde escribir la dir. Ethernet obtenida
 * sale:
 *   -1 si error, 0 si todo bien (y la dir Ethernet bien copiada)
 ****************************************************************************/
int lee_cadena_eth(char *texto, uint8_t *dir_eth) ;

/****************************************************************************
 * Convierte una cadena de texto a una direccion IP
 * entra:
 *   dir - una direccion en formato aaa.bbb.ccc.ddd
 *   ip - puntero a un BYTE[IP_ALEN] donde escribir la direccion IP obtenida
 * sale:
 *   -1 si error, 0 si todo bien (y la dir. IP bien copiada)
 ****************************************************************************/
int lee_cadena_ip(char *texto, uint32_t *dir_ip) ;