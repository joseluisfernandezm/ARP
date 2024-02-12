#include<stdio.h>
#include<pcap.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

/**************************
*Arquitectura de Redes II *
*Funciones de Nivel 1a    *
*Javier Ramos 2013-2014   *
* Manuel Ruiz 2017-2018   *
***************************/
#define TYPE2 0x4444
#define TYPE1 0x0806// cambio respecto de la actica 2 para poder reconocer el type ARP dento de la trama Eth
#define ETH_ALEN 6
#define ETH_TLEN 2
#define ETH_HLEN 14
#define HWADDR_len 6
#define ETH_MAX_LEN 1514
#define ETH_MIN_LEN 60
#define CRC_LEN 2
#define BUFFSIZE 64

#define ETH_OK 1
#define ETH_ERROR 0



typedef int (*tpfNotificacionRecepcionEth) (const uint8_t *, int, const uint8_t *, uint16_t, const struct timeval *);
/************************************************************************************************
*Funcion:InicializarEth								*
*Descripcion: Esta funcion inicia el nivelEth registrando la función de notificación, abriendo 	*
*	      una captura live pcap y lanzando un hilo de proceso de paquetes			*
*												*
*************************************************************************************************/
int InicializarEth(uint16_t *Tipos, uint8_t nType, tpfNotificacionRecepcionEth funcion, int timeout);
/************************************************************************************************
*Funcion:FinalizarEth									*
*Descripcion: Esta funcion finaliza el nivel1a liberando los recursos que se hayan reservado y 	*
*	      cerrando la captura live pcap							*
*												*
*************************************************************************************************/
int FinalizarEth(void);
/************************************************************************************************
*Funcion:EnviarDatagramaNivel1a									*
*Descripcion: Esta funcion anyade una cabecera Ethernet y el CRC al mensaje pasado 		*
*             como argumento y lo envía utilizando la funcion pcap_inject			*
*												*
*************************************************************************************************/
int EnviarDatagramaEth(const uint8_t *direccion_destino, const uint8_t *mensaje, uint16_t tamano,uint16_t tipo);
/************************************************************************************************
*Funcion:getMACAddr 										*
*Descripcion: Obtiene la direccion MAC de una interfaz						*
*Entrada:											*
*	mac:vector de 6 bytes a rellenar con la MAC de la interfaz				*
*	interface: nombre la de interfaz de la cual se obtendra la MAC. Por ejemplo "eth0"	*
*Retorno: Ninguno										*
*************************************************************************************************/
void getMACAddr(uint8_t *mac,char *interface);
