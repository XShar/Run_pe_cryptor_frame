#include <iostream>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <time.h>
#include "../../modules/modules.h"
#include <boost/preprocessor.hpp>
#include <boost/preprocessor/arithmetic/add.hpp>
#include "../../modules/trash_gen_module/fake_api.h"

//Сложение двух случайных чисел
void function1(void) {
	uint32_t  x = do_Random_EAX(25, 50);
	uint32_t  y = do_Random_EAX(25, 50);
	uint32_t summ = x + y;
}

//Сложение x с y*2 (Числа случайные)
void function2(void) {

#define PRED(d, data) BOOST_PP_TUPLE_ELEM(2, 0, data)
#define OP(d, data) \
   ( \
      BOOST_PP_DEC( \
         BOOST_PP_TUPLE_ELEM(2, 0, data) \
      ), \
      BOOST_PP_ADD_D( \
         d, \
         BOOST_PP_TUPLE_ELEM(2, 1, data), \
         2 \
      ) \
   ) \
   /**/
	// increment 'x' by 2 'n' times
#define STRIDE(x, n) BOOST_PP_TUPLE_ELEM(2, 1, BOOST_PP_WHILE(PRED, OP, (n, x)))

	uint32_t  x = do_Random_EAX(25, 50);
	uint32_t  y = do_Random_EAX(25, 50);

	STRIDE(x, y)
}

//Декремент
void function3(void) {
	BOOST_PP_DEC(BOOST_PP_DEC(6)); // expands to 4
}

//Инкремент
void function4(void) {
	BOOST_PP_INC(BOOST_PP_INC(6)); // expands to 8
}

//Деление
void function5(void) {
	BOOST_PP_DIV(11, 5); // expands to 2
}

//Деление x на y и полученный результат делится ещё на два (Числа случайные)
void function6(void) {

	uint32_t  x = do_Random_EAX(50, 500);
	uint32_t  y = do_Random_EAX(2, 5);

#define PRED(d, data) BOOST_PP_TUPLE_ELEM(2, 0, data)

#define OP(d, data) \
   ( \
      BOOST_PP_DEC( \
         BOOST_PP_TUPLE_ELEM(2, 0, data) \
      ), \
      BOOST_PP_DIV_D( \
         d, \
         BOOST_PP_TUPLE_ELEM(2, 1, data), \
         2 \
      ) \
   ) \
   /**/

	// halve 'x' 'n' times
#define HALVE(x, n) BOOST_PP_TUPLE_ELEM(2, 1, BOOST_PP_WHILE(PRED, OP, (n, x)))

	HALVE(x, y)

}

//Вычисляет остаток от деления
void function7(void) {
	BOOST_PP_MOD(11, 5);
}

void function8(void) {
	BOOST_PP_MUL(4, 4); // expands to 16
}

void function9(void) {

	uint32_t  x = do_Random_EAX(50, 500);
	uint32_t  y = do_Random_EAX(2, 5);

#define PRED(d, data) BOOST_PP_TUPLE_ELEM(3, 0, data)

#define OP(d, data) \
   ( \
      BOOST_PP_DEC( \
         BOOST_PP_TUPLE_ELEM(3, 0, data) \
      ), \
      BOOST_PP_TUPLE_ELEM(3, 1, data), \
      BOOST_PP_MUL_D( \
         d, \
         BOOST_PP_TUPLE_ELEM(3, 2, data), \
         BOOST_PP_TUPLE_ELEM(3, 1, data) \
      ) \
   ) \
   /**/

	// raise 'x' to the 'n'-th power
	#define EXP(x, n) BOOST_PP_TUPLE_ELEM(3, 2, BOOST_PP_WHILE(PRED, OP, (n, x, 1)))

	EXP(x, y) // expands to 16
}

//Вычитание
void function10(void) {
	BOOST_PP_SUB(4, 3); // expands to 1
}

void function11(void) {
#define PRED(d, data) BOOST_PP_TUPLE_ELEM(2, 0, data)

#define OP(d, data) \
   ( \
      BOOST_PP_DEC( \
         BOOST_PP_TUPLE_ELEM(2, 0, data) \
      ), \
      BOOST_PP_SUB_D( \
         d, \
         BOOST_PP_TUPLE_ELEM(2, 1, data), \
         2 \
      ) \
   ) \
   /**/

	// decrement 'x' by 2 'n' times
#define STRIDE(x, n) BOOST_PP_TUPLE_ELEM(2, 1, BOOST_PP_WHILE(PRED, OP, (n, x)))

	STRIDE(10, 2); // expands to 6
	STRIDE(14, 6); // expands to 2
}

void function12(void) {
	BOOST_PP_XOR(4, 3); // expands to 0
}

void function13(void) {
	BOOST_PP_XOR(5, 0); // expands to 1
}

void function14(void) {
	BOOST_PP_OR(4, 3); // expands to 1
}