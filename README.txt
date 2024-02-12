Nombre del proyecto: AR2-4262-02-PR3
Autor: José Luis Fernández Moreno <joseluis.fernandezm@estudiante.uam.es>
Fecha:21/04/2021

Descripción: 

En esta carpeta AR2-4262-02-PR3 encontrará los diferentes archivos .c y .h para el desempeño de la práctica 

-arpt.c, programa en el que se encuentra el main y la base para las pruebas de la práctica.

-arp.c, implementación del protocolo ARP

-arp.h, archivo de cabecera de arp.c

-funcs.c, con la función de lee_cadena_ip y lee_cadena_eth. Necesarias para arp.c

-funcs.h, archivo de cabecera para funcs.c

-nivelEth.c, con la implementación de la funcionalidad comunicación capa Ethernet.

-nivelEth.h, con las declaraciones de las funciones, las constantes y definiciones de tipo
que sean necesarias para su correcta utilización, para su inclusión por el resto de los programas que utilicen el módulo.

-rcfuncs.c, relativa al cálculo de CRC

-rcfuncs.h, archivo de cabecera de rcfuncs.c

-Makefile, para compilar la práctica basta con ejecutar el comando "make"



Ejecución de la práctica:

1º Iniciar el modo superusuario con "sudo su"
2º Ejecuta"export IPLOCAL=ip_de_tu_maquina", se puede sacar la IP con un ifconfig
3º Ejecutar la práctica con “. /arpt"

NOTA: algunas veces el programa dice no encontrar la direccion eth, pero si se intenta una segunda vez lo consigue. Debe ser por algún problema con la cache ya que la construcción de tramas ARP, según wireshark, es correcta.





