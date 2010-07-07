/** math functions **/

#define LTC_MP_LT   -1
#define LTC_MP_EQ    0
#define LTC_MP_GT    1

#define LTC_MP_NO    0
#define LTC_MP_YES   1

#ifndef LTC_MECC
   typedef void ecc_point;
#endif

#ifndef LTC_MRSA
   typedef void rsa_key;
#endif

#include <tommath.h>

typedef mp_int* mp_int_t;

