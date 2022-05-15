/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#include "Common.h"

typedef struct
{
	D_API( RtlNtStatusToDosError );
	D_API( RtlSetLastWin32Error );
	D_API( NtQueryVirtualMemory );
	D_API( RtlCreateUserThread );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/*!
 *
 * Purpose:
 *
 * Tracks a list of thread's created in the current
 * address space.
 *
!*/
D_SEC( D ) HANDLE WINAPI CreateThread_Hook( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T StackSize, LPTHREAD_START_ROUTINE StartRoutine, PVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
	API				Api;
	MEMORY_BASIC_INFORMATION	Mb1;
	MEMORY_BASIC_INFORMATION	Mb2;

	HANDLE				Thd = NULL;
	PTABLE				Tbl = NULL;
	PTHREAD_ENTRY_BEACON		Ent = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Mb1, sizeof( Mb1 ) );
	RtlSecureZeroMemory( &Mb2, sizeof( Mb2 ) );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Mb1, sizeof( Mb1 ) );
	RtlSecureZeroMemory( &Mb2, sizeof( Mb2 ) );
};
