/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#pragma once

typedef struct __attribute__(( packed ))
{
	ULONG_PTR RxBuffer;
	ULONG_PTR RxLength;
	ULONG_PTR ImageLength;
} TABLE, *PTABLE ;
