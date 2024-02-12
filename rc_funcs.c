#include "rc_funcs.h"

#define           poly     0x1021

//Funcion para el calculo del crc

uint16_t crc_ccitt(uint8_t *data,int len)
{
    uint16_t i, v, xor_flag,k,crc;

	crc=0xFFFF;

    for(k=0;k<len;k++)
    {
	uint8_t ch=data[k];

   	 v = 0x80;

	    for (i=0; i<8; i++)
	    {
		if (crc & 0x8000)
		{
		    xor_flag= 1;
		}
		else
		{
		    xor_flag= 0;
		}
		crc = crc << 1;

		if (ch & v)
		{

		    crc= crc + 1;
		}

		if (xor_flag)
		{
		    crc = crc ^ poly;
		}


		v = v >> 1;
	    }
    }


    for (i=0; i<16; i++)
    {
        if (crc & 0x8000)
        {
            xor_flag= 1;
        }
        else
        {
            xor_flag= 0;
        }
        crc = crc << 1;

        if (xor_flag)
        {
            crc = crc ^ poly;
        }
    }



	return crc;
}
