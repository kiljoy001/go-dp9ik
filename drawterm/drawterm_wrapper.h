// Wrapper to include drawterm headers safely for CGo
#ifndef DRAWTERM_WRAPPER_H
#define DRAWTERM_WRAPPER_H

#include <stdint.h>
#include <stdlib.h>  // for malloc/free

// Define what u.h provides
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef long long vlong;
typedef unsigned long long uvlong;

// Now we can include authsrv.h
#include "authsrv.h"

// Compile-time size checks
_Static_assert(sizeof(struct Ticketreq) == 141, "Ticketreq must be 141 bytes");

#endif
