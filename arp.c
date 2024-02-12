/***************************************************************************
 * arp.c
 *
 *  Funciones para implementar ARP en las practicas de
 *  Arquitectura de Redes 2 de la EPS-UAM
 *
 *  Autor: Manuel Freire
 *  Modificaciones: Manuel Ruiz, Javier Ramos
 *  (C) 2006-14 EPS-UAM
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "nivelEth.h"
#include "arp.h"
#include "rc_funcs.h"

// DEFINEs Y ENUMs INTERNOS

#define ARP_DATA_MIN 28//tamaño minimo de una trama ARP ->28 bytes
#define ARP_HLEN 6//tamaño cabecera arp desde hard type hasta prot size
#define ARP_TLEN 2// referente a los 2 bytes de tipo
#define ARP_REQ_TIMEOUT_US (1000*500)//usado en arp_solicita_direccion_eth() para pausar la ejecucion(1000*500) microsegundos
#define ARP_REQ_RETRIES 3//nos dice cuantos intentos tendremos que hacer en arp_solicita_direccion_eth
#define ETH_FRAME_MIN 60//tamaño minimo en bytes de la trama eth

enum {
    trama_arp_o_eth = 8,
    trama_arp_o_ip = 14,
    trama_arp_d_eth = 18,
    trama_arp_d_ip = 24
};

// VARIABLES GLOBALES INTERNAS

// dir ip local;  inicializada en arp_inicializa
uint32_t dir_ip_local;

// dir ethernet local, inicializada en arp_inicializa
uint8_t dir_eth_local[ETH_ALEN];

// dir ethernet para broadcast
uint8_t dir_eth_any[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ethertype para tramas ARP
uint16_t ethertype_arp= 0x0806;//nos sirve para identificar si es una trama ARP en funciones como gestionaTramaEthernetatra

// parte invariante de una trama ARP (IP sobre Ethernet)
uint8_t cabecera_arp[ARP_HLEN] = {0, 1, 8, 0, 6, 4};

// tipo de mensaje ARP para solicitud (REQ)
uint16_t arptype_req= 0x0001;

// tipo de mensaje ARP para respuesta (REP)
uint16_t arptype_rep = 0x0002;

uint32_t dir_ip_peticion_arp=0;
// si 1, ya se ha inicializado este nivel (y la dir. IP no estaba tomada)
int arp_inicializado = 0;
int ip_validada; // 1 = nadie ha respondido a un gratitious ARP

// entrada de cache ARP
typedef struct {
   time_t expiry;            // cuando llegue este momento, habra expirado
   uint32_t dir_ip;
   uint8_t dir_eth[ETH_ALEN];
} entrada_arp;

// cache ARP (global); todos los accesos deben estar protegidos mediante sem_tabla_arp
struct {
   entrada_arp t[ARP_CACHE_SIZE];
   int n;
} tabla_arp;

// ojo: no se puede incluir dentro de una estructura, porque es mas bien feo...
pthread_mutex_t sem_tabla_arp = PTHREAD_MUTEX_INITIALIZER; //para los hilos

// Semaforo para las variables globales necesarias para arp (dir_peticion_arp  y esperando_respuesta_arp)

pthread_mutex_t semaforo_globales= PTHREAD_MUTEX_INITIALIZER; //para los hilos
// usada por arp_solicita_direccion_eth / arp_procesa_trama para peticiones en curso:
// - el que pide pone esperando_respuesta a 1
// - el que recibe lo lee, mete la respuesta en eth_pedida, deja esperando_respuesta a 0
// - el que pide encuentra que esperando_respuesta esta a 0, devuelve eth_pedida
int esperando_respuesta_arp; // 1 = esperando una respuesta
uint8_t dir_eth_respuesta_arp[ETH_ALEN];//donde guardaremos la MAC que nos han respondido

// PROTOTIPOS INTERNOS

// gestion de cache

void arp_limpia_cache();
int arp_busca_entrada_cache(uint32_t dir_ip, uint8_t *dir_ether_buscada);
// NOTA: arp_actualiza_cache es publica: se llama desde IP...

// manejo de tramas ARP

int arp_lee_datos_trama(uint8_t *datos_trama, uint16_t *tipo,
    uint8_t *dir_eth_origen, uint32_t *dir_ip_origen,
    uint8_t *dir_eth_destino, uint32_t *dir_ip_destino);


void arp_escribe_trama(uint8_t *trama, uint16_t tipo,
    uint8_t *dir_eth_destino, uint32_t dir_ip_destino);

int arp_solicita_direccion_eth(uint32_t dir_ip, uint8_t *dir_eth_pedida);

// FUNCIONES DE GESTION DE CACHE

/****************************************************************************
 * Limpia correspondencias viejas
 * Basta con buscar la primera entrada no expirada (primeras = mas antiguas),
 * y eliminar todas las anteriores.
 *
 * entra/sale: nada
 ****************************************************************************/
void arp_limpia_cache() {
    int i;
    time_t t = time(NULL);

    pthread_mutex_lock(&sem_tabla_arp);
    {
        for (i=0; i<tabla_arp.n; i++) {
            if (t < tabla_arp.t[i].expiry) break;
        }

        if (i > 0) {
            memmove(tabla_arp.t, tabla_arp.t+i,
                (tabla_arp.n - i) * sizeof(entrada_arp));
        }

        tabla_arp.n -= i;
    }
    pthread_mutex_unlock(&sem_tabla_arp);
}

/****************************************************************************
 * Actualiza la cache ARP con una nueva entrada.
 * Si la entrada ya estaba presente, solo actualiza su 'tiempo de vida'
 * Si no tiene espacio para una nueva entrada, borra la entrada mas antigua.
 *
 * entra:
 *    dir_ip, dir_ether - direcciones a introducir en la nueva entrada
 * sale: nada
 ****************************************************************************/
void arp_actualiza_cache(uint32_t dir_ip, uint8_t *dir_ether) {
    int i;

    arp_limpia_cache();

    pthread_mutex_lock(&sem_tabla_arp);
    {
        // elimina entrada ya existente (si la hay)
        for (i=0; i<tabla_arp.n; i++) {
            if (memcmp(&(tabla_arp.t[i].dir_ip), &dir_ip, IP_ALEN) == 0) {
                memmove(tabla_arp.t+i, tabla_arp.t+i+1,
                    (tabla_arp.n - i - 1) * sizeof(entrada_arp));
                tabla_arp.n --;
                break;
            }
        }

        // necesaria entrada nueva; asegurar espacio
        if (tabla_arp.n == ARP_CACHE_SIZE) {
            memmove(tabla_arp.t, tabla_arp.t+1,
                    (tabla_arp.n - 1) * sizeof(entrada_arp));
            tabla_arp.n --;
        }

        memcpy(&(tabla_arp.t[tabla_arp.n].dir_ip), &(dir_ip), IP_ALEN);
        memcpy(tabla_arp.t[tabla_arp.n].dir_eth, dir_ether, ETH_ALEN);
        tabla_arp.t[tabla_arp.n].expiry = time(NULL) + ARP_CACHE_TTL;
        tabla_arp.n ++;
    }
    pthread_mutex_unlock(&sem_tabla_arp);
}

/****************************************************************************
 * Busca una entrada  la cache ARP con una nueva entrada.
 * Si la entrada ya estaba presente, solo actualiza su 'tiempo de vida'
 * Si no tiene espacio para una nueva entrada, borra la entrada mas antigua.
 *
 * entra:
 *    dir_ip - direccion IP cuya correspondiente dir. ethernet se busca
 *    dir_ether_buscada - direccion ethernet donde escribir el resultado
 * sale:
 *    0 si encontrada, -1 si no encontrada
 ****************************************************************************/
int arp_busca_entrada_cache(uint32_t dir_ip, uint8_t *dir_ether_buscada) {
    int i, rc;

    arp_limpia_cache();

    pthread_mutex_lock(&sem_tabla_arp);
    {
        rc = -1;
        for (i=0; i<tabla_arp.n; i++) {
            if (memcmp(&(tabla_arp.t[i].dir_ip), &dir_ip, IP_ALEN) == 0) {      //tabla_arp.t[i].dir_ip nos dice en que posicion de la columna Ip estamos
                memcpy(dir_ether_buscada, tabla_arp.t[i].dir_eth, ETH_ALEN);    //si la entrada de la tabla coincide con la IP que hemos solicitado rc=0->encontrado si no
                rc = 0;                                                         //lo encuentra rc=-1
                break;
            }
        }
    }
    pthread_mutex_unlock(&sem_tabla_arp);
    return rc;
}

/****************************************************************************
 * Muestra la cache ARP por stdout
 * entra / sale: nada
 ****************************************************************************/
void arp_muestra_cache() {
    int i;
    time_t t = time(NULL);
    uint8_t *dir_ip_aux;
    pthread_mutex_lock(&sem_tabla_arp);
    {
        for (i=0; i<tabla_arp.n; i++) {
            // ignora las entradas que ya han expirado, pero no las limpia todavia
            if (t > tabla_arp.t[i].expiry) continue;
            dir_ip_aux=(uint8_t*)&(tabla_arp.t[i].dir_ip);
            printf("%3.3d.%3.3d.%3.3d.%3.3d    %2.2x.%2.2x.%2.2x.%2.2x.%2.2x.%2.2x    %d\n",
              dir_ip_aux[3], dir_ip_aux[2],dir_ip_aux[1],dir_ip_aux[0],
              tabla_arp.t[i].dir_eth[0], tabla_arp.t[i].dir_eth[1], tabla_arp.t[i].dir_eth[2],
              tabla_arp.t[i].dir_eth[3], tabla_arp.t[i].dir_eth[4], tabla_arp.t[i].dir_eth[5],
              (int)(tabla_arp.t[i].expiry - t));
        }
    }
    pthread_mutex_unlock(&sem_tabla_arp);
}



/****************************************************************************
 * Lee los datos de una trama ARP
 *
 * entra:
 *    datos_trama - puntero al comienzo de los datos ARP de una trama Ethernet
 *    tipo, dir_eth_origen, dir_ip_origen, dir_eth_destino, dir_ip_destino -
 *        punteros a los campos a rellenar con los datos correpondientes
 * sale:
 *    0 si todo bien, -1 si error (no son datos ARP validos)
 ****************************************************************************/
int arp_lee_datos_trama(uint8_t *datos_trama, uint16_t *tipo,
    uint8_t *dir_eth_origen, uint32_t *dir_ip_origen,
    uint8_t *dir_eth_destino, uint32_t *dir_ip_destino)
{
	uint8_t arp_header[ARP_HLEN]={0};//variable en la que guardaremos la cabecera de la trama ethernet
	uint32_t aux32=0;//variable auxialiar de 4 bytes
	uint16_t aux16;//variable auxiliar de 2 bytes NOTA:he cambiado el unint32_t por uno unint16_t respecto del codigo original (ya que el tipo es de 16 bits, 2 bytes)
  uint32_t dir_ip_aux_2, dir_ip_aux_3;//donde guardaremos las Ip extraidas de la trama de forma auxiliar tras pasar de orden de red a orden de host

      /* PRACTICA: implementa la funcion; y devuelve 0 si la trama es valida
		Extraer los campos de ARP de la trama ARP contenida en datos_tramas.
		Para ello, usar memcpy para extraer:
			-Cabecera comun ARP
			-Tipo de operacion ARP (peticion/respuesta)
			-Direccion ETH origen (en cabecera ARP)
			-Direccion IP origen (en cabecera ARP)
			-Direccion ETH destino (en cabecera ARP)
			-Direccion IP destino (en cabecera ARP)

		Esta informacion debe copiarse a las variables que se pasan como argumento a esta funcion o en arp_header
		Un vez implementada cambiar el return -1 a return 0*/

	//printf("%s/%d: Falta por implementar 'arp_lee_datos_trama'.\n", __FILE__, __LINE__);

  memcpy(arp_header, datos_trama, ARP_HLEN);//metemos en arp_header la cabecera de la trama ARP
  if(memcmp(arp_header, cabecera_arp, ARP_HLEN)!=0){
      printf("ERROR, arp_header no coincide con cabecera_arp\n");
      return -1;
  }// comparamos lo guardado en arp_header con cabecera:arp que esla parte invariante de una trama ARP (IP sobre Ethernet)


  aux32+=ARP_HLEN;//avanzamos 6 bytes en la trama que es lo que ocupará la cabecera sin incluir el tipo
  memcpy(&aux16, datos_trama+aux32, ARP_TLEN);//guardamos el tipo en aux16

  *tipo = ntohs(aux16);//transformamos a orden de host el campo tipo y lo guardamos ya que estamos leyendo en nuestro pc una trama qur viene de la red
  aux32+=ARP_TLEN;// avanzamos los 2 bytes del campo tipo

  memcpy(dir_eth_origen, datos_trama+aux32, ETH_ALEN);//guardamos en dir_eth_origen la MAC origen
  aux32+=ETH_ALEN;//avanzamos ETH_ALEN, que son los 6 bytes que ocupa la MAC

  memcpy(&dir_ip_aux_2, datos_trama+aux32, IP_ALEN);//guardamos en dir_ip_origen1 la IP origen
  *dir_ip_origen=ntohl(dir_ip_aux_2);//La función ntohl() convierte el entero largo sin signo netlong desde el orden de bytes de la red al del host
  aux32+=IP_ALEN;//avanzamos IP_ALEN que son los 4 bytes que ocupa la IP

  memcpy(dir_eth_destino, datos_trama+aux32, ETH_ALEN);//guardamos en dir_eth_destino la MAC destino
  aux32+=ETH_ALEN;//avanzamos ETH_ALEN, que son los 6 bytes que ocupa la MAC

  memcpy(&dir_ip_aux_3, datos_trama+aux32, IP_ALEN);//guardamos en dir_ip_destino_aux la IP destino
  *dir_ip_destino=ntohl(dir_ip_aux_3);//La función ntohl() convierte el entero largo sin signo netlong desde el orden de bytes de la red al del host


    return 0;
}

/****************************************************************************
 * Prepara una trama ARP para ser enviada, con los datos que se soliciten
 *
 * entra:
 *    trama - trama ARP
 *    tipo - tipo de peticion
 *    dir_eth_destino, dir_ip_destino - dir. a incluir en los campos de destino
 * sale:
 *    nada
 ****************************************************************************/
void arp_escribe_trama(uint8_t *trama, uint16_t tipo,
    uint8_t *dir_eth_destino, uint32_t dir_ip_destino) {



      /* PRACTICA: implementa la funcion;
		Construir una trama ARP en la variable trama.
		Para ello, usar memcpy para copiar:
			-Cabecera comun ARP
			-Tipo de operacion ARP (peticion/respuesta)
			-Direccion ETH origen (en cabecera ARP)
			-Direccion IP origen (en cabecera ARP)
			-Direccion ETH destino (en cabecera ARP)
			-Direccion IP destino (en cabecera ARP)

		Esta informacion debe copiarse a partir de las variables que se pasan como argumento a esta funcion*/

    //printf("%s/%d: Falta por implementar 'arp_escribe_trama'.\n", __FILE__, __LINE__);

    uint32_t sizeAux = 0;//varaiable usada para desplazarse por la trama, es de 4 Bytes
    uint16_t aux_tipo;//variable auxiliar que almacena el tipo
    uint32_t dir_ip_aux_2, dir_ip_aux_3;//variables que usaremos para transformar las IP a orden de red

    aux_tipo= htons(tipo); //transformamos el tipo a orden de red ya que lo vamos a enviar

    dir_ip_aux_2 = htonl(dir_ip_destino);//transformamos a orden de red usando htonl ya que es una variable long de 32 bits
    dir_ip_aux_3 = htonl(dir_ip_local);//transformamos a orden de red usando htonl ya que es una variable long de 32 bits


    memcpy(trama, cabecera_arp, ARP_HLEN);// incluimos en la trama a enviar la cabecera estandar definida arriba
    sizeAux+=ARP_HLEN;//aumentamos lo que ocupa la cabezera 6 Bytes
    memcpy(trama+sizeAux, &aux_tipo,ARP_TLEN);//incluimos despues de la cabcera el tipo
    sizeAux+=ARP_TLEN;//aumentamos los 2 Bytes del tipo
    memcpy(trama+sizeAux, dir_eth_local, ETH_ALEN);//ahora incluimos la MAC origen
    sizeAux+=ETH_ALEN;//aumentamos los 6 bytes de la MAC origen
    memcpy(trama+sizeAux, &dir_ip_aux_3 , IP_ALEN);//metemos la IP origen
    sizeAux+=IP_ALEN;//Aumentamos los 4 Btes de la IP
    memcpy(trama+sizeAux, dir_eth_destino, ETH_ALEN);//ahora incluimos la MAC destino
    sizeAux+=ETH_ALEN;//aumentamos los 6 bytes de la MAC destino
    memcpy(trama+sizeAux, &dir_ip_aux_2 , IP_ALEN);//por ultimo metemos la ip destino


}

// FUNCIONES PRINCIPALES DE ARP

/****************************************************************************
 * Procesa una trama Ethernet de tipo ARP
 * Si la direccion 'ip' del campo 'destino' es la propia,
 *    Si se trata de una consulta, envia una respuesta
 *    Si se trata de una respuesta, y el origen era la ip de una peticion
 *       en curso, considera que ha satisfecho la peticion.
 * En cualquier caso, actualiza la cache con la ip/eth origen de la trama
 *
 * entra:
 *    tamano, trama - longitud y datos de la trama ethernet recibida
 *    dir_eth_nivel1 - direccion ethernet origen de la trama recibida
 * sale:
 *    0 si no hay fallos, -1 en caso contrario
 ****************************************************************************/


int arp_procesa_trama(const uint8_t *dir_eth_nivel1,int tamano, const uint8_t *trama) {


     uint16_t tipo_arp;//Variable que nos dirá si se trata de una peticion o de una respuesta
     uint8_t dir_eth_origen[ETH_ALEN],dir_eth_destino[ETH_ALEN];//campos que guardaran las MAC Origen y Destino de la trama ARP
     uint32_t dir_ip_origen,dir_ip_destino;//campos que guardaran las IP Origen y Destino de la trama ARP
     uint8_t trama_respuesta[ETH_FRAME_MIN];//donde guardaremos la trama respuesta

    /* PRACTICA: implementa la parte correspondiente de ARP, teniendo en cuenta      */
    /* ... notificar error si la dir_eth_nivel1 no corresponde a la dir. eth. origen */
    /* ... ignorar peticiones cuya dir. eth. origen somos nosotros (ARP gratuito)    */
    /* ... usar arp_escribe_trama para responder a peticiones dirigidas a esta IP    */
    /* (elimina tambien el siguiente "printf")
	Esta funcion se llama automaticamente cada vez que se recibe una trama ARP. En trama
	se encuentra la trama ARP y en tamano su correspondiente tamano. Esta funcion tiene que llamar a
	arp_lee_datos_trama. arp_lee_datos_trama extrae cada campo de la trama ARP (dir_eth_origen y destino e IP origen y destino).
	Tareas de la funcion

		-Comprobar (usando memcmp) si la direccion eth origen es la eth local, es decir, es una trama que he enviado yo.
		En este caso se debe salir de la funcion porque no queremos procesarla
		-Comprobar (usando memcp) si la direccion eth origen es igual a la dir_eth_nivel1. Si no es igual esto quiere decir
		que la trama ARP no esta bien construida. En este caso se debe salir de la funcion porque no queremos procesarla.
		-Actualizar la cache de arp con la IP origen y la etg origen
		-Comprobar si la ip destino es la local. Si no es la misma, esto quiere decir que la trama no va dirigida a mi. En este caso salir de
		la funcion.
		-Comprobar si el tipo de operacion (tipo_arp) es peticion (arptype_req) o respuesta (arptype_rep)
			-Si es una peticion:
				-Escribir (usando la funcion arp_escribe_trama) en trama_respuesta una trama ARP respuesta utilizando como direccion IP destino la IP origen recibida y
				como direccion eth destino la direccion eth origen.
				-Enviar trama_respuesta con EnviarDatagramaNivel1 utilizando como destino la direccion eth origen.
			-Si es una respuesta:
				-Comprobar si la ip origen es igual a la IP almacenada en dir_ip_peticion_arp. Si no es igual, esto quiere decir que es una respuesta a algo que no habiamos preguntado.
				En este caso salir de la funcion.
				-Copiar a dir_eth_respuesta_arp la dir_eth_origen
				-Poner la variable global esperando_respuesta_arp a 0
				-OJO se deben usar los semaforos para proteger estas 2 operaciones
	*/

   int comparacion1=0,comparacion2=0,comparacion3=0,comparacion4=0;//int auxiliares para hacer las diferentes comparaciones

   //printf("%s/%d: Falta por implementar 'arp_procesa_trama'.\n", __FILE__, __LINE__);


  arp_lee_datos_trama((uint8_t *)trama, &tipo_arp, dir_eth_origen, &dir_ip_origen, dir_eth_destino, &dir_ip_destino);//funcion que nos extrae los campos de la trama recibida

  //tras leer los datos los comparamos

  comparacion1= memcmp(dir_eth_origen, dir_eth_local, ETH_ALEN);//Comparo si la direccion ethernet de la inicialización de la trama es la misma que la MAC MAC_origen
    if(comparacion1==0){
      printf("ARP gratuito: No proceso la trama porque es justo la que me he enviado yo a mi mismo para ver si las MAC origen y destino son las mismas\n");
      return -1;
    }

  comparacion2 = memcmp(dir_eth_origen, dir_eth_nivel1, ETH_ALEN); //Ahora comparo con dir_eth_nivel1 para ver si la trama está bien construida
    if(comparacion2!=0){
      printf("La trama ARP no ha sido construida correctamente\n");
      return -1;
    }
    arp_actualiza_cache(dir_ip_origen, dir_eth_origen);

  comparacion3 = memcmp(&dir_ip_destino, &dir_ip_local, IP_ALEN);//Comparamos la Ip de la trama con la nuestra local, si no coinciden la trama no va dirigida a mi y por tanto no la proceso
    if(comparacion3 == 0 ){
      printf("Como la IP no es la mia, esta trama no va dirgida a mi y no la tengo que procesar yo\n");
      return -1;
    }

  if (tipo_arp == arptype_req){
      arp_escribe_trama(trama_respuesta, tipo_arp, dir_eth_origen, dir_ip_origen);//preparamos la trama a enviar
      EnviarDatagramaEth(dir_eth_origen, trama_respuesta, tamano, ethertype_arp);//enviamos la trama preparada

  }//peticion

  else if(tipo_arp == arptype_rep){
    comparacion4 = memcmp(&dir_ip_peticion_arp, &dir_ip_origen, IP_ALEN);
    if(comparacion4 != 0) {
      printf("La respuesta es sobre algo que no habiamos preguntado\n");
      return -1;
    }

    pthread_mutex_lock(&semaforo_globales); {
      memcpy(dir_eth_respuesta_arp, dir_eth_origen, ETH_ALEN);//copiamos en dir_eth_respuesta_arp la MAC de origen
      esperando_respuesta_arp = 0;//variable global esperando_respuesta_arp a 0
    }
    pthread_mutex_unlock(&semaforo_globales);//desbloqueamos semaforo

  }//respuesta

  else {
    printf("No se trata ni de peticion ni de respuesta\n");
    return -1;
  }

	return 0;

}

/****************************************************************************
 * Solicita la direccion Ethernet que corresponde a una direccion IP.
 * Si la direccion pedida ya esta en la cache, la devuelve sin mas.
 * En caso contrario, la solicita enviando una trama REQ, y reintentando
 * varias veces antes de desistir.
 *
 * entra:
 *    dir_ip - direccion IP
 *    dir_ether_pedida - direccion Ethernet a rellenar
 * sale:
 *    0 y dir_ether_pedida a su valor correspondiente, o -1 si error
 ****************************************************************************/
int arp_solicita_direccion(uint32_t dir_ip, uint8_t *dir_eth_pedida) {

    // comprueba si estan pidiendo la dir. propia
    if (memcmp(&dir_ip, &dir_ip_local, IP_ALEN) == 0) {
        memcpy(dir_eth_pedida, dir_eth_local, ETH_ALEN);
        return 0;
    }



    // busca en la cache antes de solicitar la direccion por si ya la teniamos en la tabla directamente
    if (arp_busca_entrada_cache(dir_ip, dir_eth_pedida) == 0) {
        // encontrada en cache
        return 0;
    }

    // busca en la red mediante ARP
    return arp_solicita_direccion_eth(dir_ip, dir_eth_pedida);
}

/****************************************************************************
 * Solicita una direccion ARP directamente al exterior; no usa cache. Esto
 * es util para implementar ARP gratuito, por ejemplo.
 *
 * entra:
 *    dir_ip - direccion IP
 *    dir_ether_pedida - direccion Ethernet a rellenar
 * sale:
 *    0 y dir_ether_pedida a su valor correspondiente, o -1 si error
 ****************************************************************************/
int arp_solicita_direccion_eth(uint32_t dir_ip, uint8_t *dir_eth_pedida) {


	int n_intentos=0;
	uint8_t trama[ETH_FRAME_MIN]={0};
    /* PRACTICA: implementa esta funcion, con ARP_REQ_RETRIES cada ARP_REQ_TIMEOUT_US */
    /*   (usa 'usleep' en lugar de 'sleep') antes de devolver error.                  */
    /* (y elimina tambien el siguiente "printf")
	Esta funcion debe hacer una peticion ARP y esperar hasta que la respuesta este disponible
	La manera de saber si la respuesta ha llegado es mirando si la variable esperando_respuesta_arp esta a 0
	Implementacion:

	-LLamar a ar_escribe_trama para construir una trama de peticion ARP con la dir_ip que se pasa como argumento a esta funcion
	-Copiar en dir_ip_peticion_arp el valor de dir_ip para saber que IP estamos solicitando
	-Poner esperando_respuesta_arp a 1 para indicar que estamos esperando la repsuesta
	-Hacer un bucle de 0 al numero máximo de intentos (ARP_REQ_RETRIES)
		-Enviar trama ARP construida
		-Esperar un tiempo con la funcion usleep. Se debe esperar el tiempo indicado en ARP_REQ_TIMEOUT_US
		-Mirar si esperando_respuesta_arp esta a 0
			-En caso afirmativo:
				- Copiar a dir_eth_pedida el contenido de dir_eth_respuesta_arp
				-Salir de la funcion
			-En caso negativo seguir con el bucle para hacer más reintentos
	-OJO las variables globales hay que protegerlas con semaforos

	*/

  arp_escribe_trama(trama, arptype_req, dir_eth_any, dir_ip);//llamamos a la funcion que nos escribe la trama
  pthread_mutex_lock(&semaforo_globales); {
    memcpy(&dir_ip_peticion_arp, &dir_ip, IP_ALEN);//copiamos en dir_ip_peticion_arp la IP solicitada
    esperando_respuesta_arp = 1;//variable global esperando_respuesta_arp a 1
  }
  pthread_mutex_unlock(&semaforo_globales);//desbloqueamos semaforo, este semaforo esta para no pisar la funcion de arp_procesa_trama()

  for(n_intentos=0; n_intentos < ARP_REQ_RETRIES; n_intentos++) {
    EnviarDatagramaEth(dir_eth_any, trama, ARP_DATA_MIN, ethertype_arp);   //ARP_DATA_MIN=28 bytes de la trama ARP
    usleep(ARP_REQ_TIMEOUT_US);//usleep suspende la ejecucion un intervalo de ARP_REQ_TIMEOUT_US microsegundos
    if(esperando_respuesta_arp == 0) {
      memcpy(dir_eth_pedida, dir_eth_respuesta_arp, ETH_ALEN);//Copiar a dir_eth_pedida el contenido de dir_eth_respuesta_arp
      return 0;
    }
  }//ARP_REQ_RETRIES nos dice cuantos intentos tendremos que hacer


    //printf("%s/%d: 'arp_solicita_direccion_eth' no implementada...\n", __FILE__, __LINE__);
    return -1;
}

/****************************************************************************
 * Inicializa ARP; debe llamarse antes de usar otras funciones de 'arp.h'
 * Se puede llamar repetidas veces sin efectos adversos
 *
 * Lee la variable de entorno 'IPLOCAL' para determinar la IP local.
 *
 * entra: nada
 * sale:
 *   0 si todo bien, -1 en caso de error
 ****************************************************************************/
int arp_inicializa() {

	uint8_t *dir_ip_aux=(uint8_t*)(&dir_ip_local);
  uint8_t MAC_aux[ETH_ALEN];// MAC aux para poder usar arp_solicita_direccion_eth()

  if ( ! arp_inicializado) {


    getMACAddr(dir_eth_local,"ens33") ;//obtenemos la MAC del emisor NOTA:Pongo ens33 porque es la unica que me reconoce wireshark, la direccion se guarda en dir_eth_origen

    // obtiene ip local
    if (lee_cadena_ip(getenv("IPLOCAL"), &dir_ip_local) != 0) {
        printf("Error obteniendo dir IP local\n");
        return -1;
    }//Para la ejecucion antes asignar IPLOCAL en la terminal usando '#Export IPLOCAL=ip_maquina'



    /* PRACTICA: implementar aqui ARP gratuito, es decir preguntar por nuestra propia IP */
    /* ... y si alguien responde, es que tiene nuestra IP: devolver error */
    /* (elimina tambien el siguiente "printf")                            */
    //printf("%s/%d: Falta por hacer un ARP gratuito...\n", __FILE__, __LINE__);

    int ret=0;//variable auxiliar para comprobar el retorno de arp_solicita_direccion_eth

    ret = arp_solicita_direccion_eth(dir_ip_local, MAC_aux);
    if (ret == 0) {
      printf("Alguien ha respondido a un gratitious ARP, entoces alguien tiene nuestra IP\n");
      ip_validada = 0;// ip_validada=0 -> alguien ha respondido a un gratitious ARP
      return -1;
    }

    else
      ip_validada=1;// ip_validada=1 -> nadie ha respondido a un gratitious ARP
     arp_inicializado = 1;
    fprintf(stderr, "Inicializado: %3.3d.%3.3d.%3.3d.%3.3d / %2.2x.%2.2x.%2.2x.%2.2x.%2.2x.%2.2x\n",
        dir_ip_aux[3], dir_ip_aux[2], dir_ip_aux[1], dir_ip_aux[0],
        dir_eth_local[0], dir_eth_local[1], dir_eth_local[2],
        dir_eth_local[3], dir_eth_local[4], dir_eth_local[5]);
  }

  return 0;

}
/****************************************************************************
 * Finaliza ARP; debe llamarse para finalizar el nivel arp
 * Se puede llamar repetidas veces sin efectos adversos
 *
 *
 *
 * entra: nada
 * sale:
 *   0 si todo bien, -1 en caso de error
 ****************************************************************************/
int arp_finaliza() {


     arp_inicializado = 0;
  return 0;
}
