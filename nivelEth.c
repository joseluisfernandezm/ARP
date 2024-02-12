#include "nivelEth.h"
#include <pthread.h>
#include "rc_funcs.h"
#include "arp.h"


/******************************
*Arquitectura de Redes II     *
*Funciones de Nivel Ethernet  *
*Javier Ramos 2013-2014       *
* Manuel Ruiz 2017-2018       *
*******************************/


pthread_t t;//hilo t
pcap_t  *p;
uint8_t MAC_Origen[6] = {0};   // variable que guardara la direccion MAC local
uint8_t numProto = {0};//para indicar que ethertype es
uint16_t tipo[10] = {0};//array que guardara los tipos pasados en InicializarEth
tpfNotificacionRecepcionEth notif;



/************************************************************************************************
*Funcion:getMACAddr 									                                     	*
*Descripcion: Obtiene la direccion MAC de una interfaz						                    *
*Entrada:											                                            *
*	mac:vector de 6 bytes a rellenar con la MAC de la interfaz				                    *
*	interface: nombre la de interfaz de la cual se obtendra la MAC. Por ejemplo "eth0"	        *
*Retorno: Ninguno										                                        *
*************************************************************************************************/

void getMACAddr(uint8_t *mac,char *interface)
{

    int s;//para el return de la inicializacion del socket
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);// inicializamos socket
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(mac,ifr.ifr_hwaddr.sa_data,HWADDR_len);//guardamos la direccion en *mac

}
/************************************************************************************************
*Funcion:attendPacket										*
*Descripcion: Esta funcion se ejecuta cada vez que se recibe un paquete. Aqui dentro debe	*
*	      ejecutarse cualquier operación sobre el paquete recibido				*
*Entrada:											*
*	user:informacion pasada a nivel de usuario por la libreria pcap (desde pcap_loop)	*
*	h: esructura de cabecera pcap del paquete recibido (tiempo y tamanyo)			*
*	packet: buffer con el contenido binario del paquete					*
*Retorno: Ninguno										*
*************************************************************************************************/

void attendPacket(u_char *user,const struct pcap_pkthdr *h,const u_char *packet)
{
	/**PRACTICA Implementar aquí las acciones necesarias al recibir un paquete*/
		//printf(" IMPLEMENTAR attendPacket \n");

    uint8_t MAC_destino[6] = {0}, MAC_origen[6] = {0}, Payload[1496] = {0}, broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};//CRC_pckt[4] = {0},
    uint16_t auxtype = 0, type = 0;
    uint32_t sizeRead = 0;
    int i, token = 0, ret = 0, ret2 = 0;

    memcpy(MAC_destino, packet+sizeRead, sizeof(uint8_t)*6); //metemos en Mac_destino los primeros 6 bytes del paquete recibido
    sizeRead+=sizeof(uint8_t)*6; // avanzo 6 bytes para leer el siguiente campo del paquete

    memcpy(MAC_origen, packet+sizeRead, sizeof(uint8_t)*6); //metemos en Mac_origen los 6 bytes siguientes que se corresponden con la mac origen del paquete recibido
    sizeRead+=sizeof(uint8_t)*6; // avanzo 6 bytes para leer el siguiente campo del paquete

    memcpy(&auxtype, packet+sizeRead, sizeof(uint16_t));//guardamos en auxtype el ethertype que nos llega 2bytes
    sizeRead+=sizeof(uint16_t);//avanzo 2bytes
    type = ntohs(auxtype); //paso a orden de host auxtype y lo guardo en type (ethertype)
    for(i=0;i<numProto; i++)
      if(tipo[i] == type)
        token++;//comprobamos el type
    if(token == 0)
      return;

    memcpy(Payload, packet+sizeRead, (sizeof(uint8_t)*h->len)-4-14);   //4 bytes del CRC y 14 de la cabecera
    sizeRead+=sizeof(uint8_t)*h->len-4-14;//avanzo todo lo que ocupa Payload dentro del paquete

    /*memcpy(CRC_pckt, packet+sizeRead, sizeof(uint8_t)*4);
    sizeRead+=sizeof(uint8_t)*4;// avanzo 4 bytes dentro del paquete


    if(crc32(sizeRead, packet) != 0) {
      return; }
    CRC no necesario en la proctica 3*/

    ret = memcmp(MAC_destino, MAC_Origen, sizeof(uint8_t)*6);
    ret2 = memcmp(MAC_destino, broadcast, sizeof(uint8_t)*6);
    if(ret == 0 ||  ret2 == 0) {
      notif(MAC_origen, sizeof(uint8_t)*h->len-4-14, Payload, type, &h->ts);
    } //comprobacion que ninguna de las Mac este a 0, si lo está notifico
    return;


}


/************************************************************************************************
*Funcion:startCapture										*
*Descripcion: Esta funcion se ejecuta en un hilo nuevo e inicia la captura de paquetes a	*
*	      través de la función pcap_loop. Se ejecuta en un nuevo hilo parta evitar que el 	*
*	      programa principal quede bloqueado al llamar a la función InicializarNivel1a	*
*Entrada:											*
*	arg: argumentos del hilo. En nuestro caso ninguno					*
*Retorno: Ninguno										*
*************************************************************************************************/
void * startCapture(void *arg)
{
	pcap_loop(p,-1,attendPacket,NULL);// primer campo de la funcion p que es el puntero de la estructura pcap_t previamente rellena por la función pcap_open_live en InicializarEth()
}
/************************************************************************************************
*Funcion:InicializarStackRed							*
*Descripcion: Esta funcion inicia el nivel1a registrando la función de notificación, abriendo 	*
*	      una captura live pcap y lanzando un hilo de proceso de paquetes			*
*												*
*************************************************************************************************/
int InicializarEth(uint16_t *Tipos, uint8_t nType, tpfNotificacionRecepcionEth funcion, int timeout)
{
	char errbuff[1000];
	/**PRACTICA Implementar aquí las acciones necesarias para inciar el nivel Ethernet*/
	//printf(" IMPLEMENTAR InicializarEth\n");
  int i;//variable aux para for

  for(i=0; i < nType; i++){
    tipo[i] = Tipos[i];
  }//nos dice el tipo de trama que nos llega, metemos en el array tipo el contenido de Tipos

  notif = funcion;
  getMACAddr(MAC_Origen, "ens33");//obtenemos la MAC del emisor NOTA:Pongo ens33 porque es la unica que me reconoce wireshark, la direccion se guarda en MAC_Origen
  numProto = nType;//metemos en numProto el contenido de nType que nos dice el numero de tipos que existen


	p = pcap_open_live("ens33",ETH_MAX_LEN,1,timeout,errbuff); //abre la interfaz de red (ens33 en mi caso) en modo promiscuo, es decir, analiza todas las tramas que le llegan, tenemos que ver si son para nosotros o no (ver la direccion de destino)
	if (p == NULL){                                            //NOTA:Pongo ens33 porque es la unica que me reconoce wireshark
		printf ("Error: %s\n", errbuff);//el error se guarda en errbuff
		return ETH_ERROR;
	}
	pthread_create(&t,NULL,startCapture,NULL);//t: hilo declarado al inicio, esta funcion genera un hilo para evitar el bloqueo, la funcion startCapture se ejecutará en el hilo t.

	return ETH_OK;

}

/************************************************************************************************
*Funcion:FinalizarEth							*
*Descripcion: Esta funcion finaliza el nivel1a liberando los recursos que se hayan reservado y 	*
*	      cerrando la captura live pcap							*
*												*
*************************************************************************************************/
int FinalizarEth(void)
{
	/**PRACTICA Implementar aquí las acciones necesarias para finalizar el nivel Ethernet*/
		//printf(" IMPLEMENTAR FinalizarStackRed \n");

    free(p);//liberamos el puntero pcap_t *
    if(p == NULL){
      return -1;
    }
    pcap_breakloop(p);//funcion de la libreria pcap que se usa para salir del bucle generado por pcap_loop
    pcap_close(p);//las capturas abiertas con pcap_open_live, se cierran con pcap_close
    pthread_join(t, NULL);//comprueba que el hilo t acabó.

	return ETH_OK;
}

/************************************************************************************************
*Funcion:EnviarDatagramaEth									*
*Descripcion: Esta funcion anyade una cabecera Ethernet y el CRC al mensaje pasado 		*
*             como argumento y lo envía utilizando la funcion pcap_inject			*
*												*
*************************************************************************************************/

int EnviarDatagramaEth(const uint8_t *direccion_destino, const  uint8_t *mensaje, uint16_t tamano, uint16_t tipo)
{
/**PRACTICA Implementar aquí las acciones necesarias para enviar un paquete*/
	//printf(" IMPLEMENTAR EnviarDatagramaEth \n");

  uint8_t datagrama[1514];//donde guardaremos la cabecera y el mensaje
  uint16_t tipo2 = htons(tipo);//pasamos el tipo a orden de red, lo llamo tipo 2 ya que siempre le llega de este tipo  el de la fecha, usuario, mensaje...
  uint32_t size = 0; //crcCalc = 0; de la practica 2
  int i;

  memcpy(datagrama+size, direccion_destino, sizeof(uint8_t)*6);//metemos en datagrama la direccion destino (broadcast en nuestro caso) 6bytes
  size+=sizeof(uint8_t)*6;//avanzamos en el datagrama

  memcpy(datagrama+size, MAC_Origen, sizeof(uint8_t)*6);//metemos en datagrama la MAC local que antes hemos generado 6 bytes
  size+=sizeof(uint8_t)*6;//avanzamos en el datagrama

  memcpy(datagrama+size, &tipo2, sizeof(uint16_t));//metemos el tipo2 en el datagrama 2 bytes
  size+=sizeof(uint16_t);//avanzamos en el datagrama

  memcpy(datagrama+size, mensaje, tamano);//metemos el mensaje en el datagrama ocupa el tamaño del mensaje pasado desde main_enviar.c (incremento)
  size+=tamano;//avanzamos en el datagrama lo que ocupa el mensaje

  /*crcCalc = crc32(size,datagrama);//metemos en crcCalc el retorno de la funcion crc32 (rc_funcs.c)-> CRC calculado en orden de red (4bytes)
  memcpy(datagrama+size, &crcCalc, sizeof(uint8_t)*4);//metemos el CRC en el datagrama 4 bytes
  size+=sizeof(uint8_t)*4;//avanzamos 4 bytes en datagrama

  CRC no necesario en la proctica 3*/

  if(size < 60) {
    for(i=size; i<60; i++)
      datagrama[i] = 0;
    size = 60;
  }// si el datagrama<60 rellenamos con 0
  pcap_inject(p, datagrama, size);//pasamos el datagrama a pcap_inject para que sea enviado

	return 0;


}
