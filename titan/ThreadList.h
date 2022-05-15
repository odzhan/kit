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

typedef struct
{
	LIST_ENTRY	ThreadList;
	HANDLE		Thread;
} THREAD_ENTRY_BEACON, *PTHREAD_ENTRY_BEACON ;
