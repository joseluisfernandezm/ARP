#include "funcs.h"
#include "nivelEth.h"
/*****************************************************************************
 * Convierte una cadena de texto a una direccion Ethernet
 * entra:
 *   dir - una direccion en formato aa:bb:cc:dd:ee:ff
 *   eth - puntero a un BYTE[ETH_ALEN] donde escribir la dir. Ethernet obtenida
 * sale:
 *   -1 si error, 0 si todo bien (y la dir Ethernet bien copiada)
 ****************************************************************************/
int lee_cadena_eth(char *texto, uint8_t *dir_eth) {
  int i;
  int tmp[ETH_ALEN];

  if ( ! texto)
  {
    fprintf(stderr, "Dir. 'NULL' no definida.\n");
    return(-1);
  }

  if (sscanf(texto, "%2x:%2x:%2x:%2x:%2x:%2x",
        tmp+0, tmp+1, tmp+2, tmp+3, tmp+4, tmp+5) != 6) {
      fprintf(stderr, "Dir. Ethernet '%s' no tiene formato 'aa:bb:cc:dd:ee:ff'\n", texto);
      return(-1);
  }
  for (i=0; i<ETH_ALEN; i++) {
    dir_eth[i] = tmp[i];
  }
  return 0;
}

/****************************************************************************
 * Convierte una cadena de texto a una direccion IP
 * entra:
 *   dir - una direccion en formato aaa.bbb.ccc.ddd
 *   ip - puntero a un BYTE[IP_ALEN] donde escribir la direccion IP obtenida
 * sale:
 *   -1 si error, 0 si todo bien (y la dir. IP bien copiada)
 ****************************************************************************/
int lee_cadena_ip(char *texto, uint32_t *dir_ip) {
  struct in_addr ia;


  if ( ! texto)
  {
    printf("Dir. IP 'NULL' no definida.\n");
    return(-1);
  }//se comprueba si hemos exportado a IPLOCAL la IP de la maquina en la terminal



  if(inet_aton(texto,&ia)==0)
	return -1;
  *dir_ip=ntohl(ia.s_addr);//se pasa de orden de red a orden de host para un long de 32bits como lo es la IP

  return 0;
}
