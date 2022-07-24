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
 * Searches for an export in the given PE.
 *
!*/
D_SEC( B ) PVOID PeGetFuncEat( _In_ PVOID ImageBase, _In_ UINT32 ExportHash )
{
	PUINT16			Aoo = NULL;
	PUINT32			Aon = NULL;
	PUINT32			Aof = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_DATA_DIRECTORY	Dir = NULL;
	PIMAGE_EXPORT_DIRECTORY	Exp = NULL;

	/* Setup image headers */
	Dos = C_PTR( ImageBase );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	/* Is a valid EAT directory? */
	if ( Dir->VirtualAddress ) {
		Exp = C_PTR( U_PTR( Dos ) + Dir->VirtualAddress );
		Aon = C_PTR( U_PTR( Dos ) + Exp->AddressOfNames );
		Aof = C_PTR( U_PTR( Dos ) + Exp->AddressOfFunctions );
		Aoo = C_PTR( U_PTR( Dos ) + Exp->AddressOfNameOrdinals );

		/* Enumerate exports! */
		for ( INT Idx = 0 ; Idx < Exp->NumberOfNames ; ++Idx ) {
			/* Create a hash of the string and compare! */
			if ( HashString( C_PTR( U_PTR( Dos ) + Aon[ Idx ] ), 0 ) == ExportHash ) {
				/* Return Pointer */
				return C_PTR( U_PTR( Dos ) + Aof[ Aoo[ Idx ] ] );
			};
		};
	};

	/* Abort! */
	return NULL;
};
