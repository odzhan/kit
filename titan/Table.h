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

/* Table allocated and stored on a test */
typedef struct __attribute__(( packed ))
{
	ULONG_PTR 	RxBuffer;
	ULONG_PTR 	RxLength;
	ULONG_PTR 	ImageLength;

	LIST_ENTRY	HeapList;
} TABLE_HEAP, *PTABLE_HEAP ;

typedef struct __attribute__(( packed ))
{
	PTABLE_HEAP	Table;
} TABLE, *PTABLE ;
