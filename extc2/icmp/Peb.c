/*!
 *
 * ICMP
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

/*!
 *
 * Purpose:
 *
 * Find a module loaded in memory.
 *
!*/
D_SEC( B ) PVOID PebGetModule( _In_ UINT32 ModuleHash )
{
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PLDR_DATA_TABLE_ENTRY	Ldr = NULL;

	/* Get the InLoadOrderModuleList */
	Hdr = C_PTR( & NtCurrentPeb()->Ldr->InLoadOrderModuleList );
	Ent = C_PTR( Hdr->Flink );

	/* Enumerate over the InLoadOrderModuleList */
	for ( ; Ent != Hdr ; Ent = C_PTR( Ent->Flink ) ) {
		/* Get the LDR_DATA_TABLE_ENTRY */
		Ldr = C_PTR( CONTAINING_RECORD( Ent, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks ) );

		/* Does it match the module name */
		if ( HashString( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length ) ) {
			return C_PTR( Ldr->DllBase );
		};
	};
	/* Error */
	return NULL;
};
