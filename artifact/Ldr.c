/*!
 *
 * ARTIFACT
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
 * Hooks the specified function in the import address
 * table of the specified PE.
 *
!*/
BOOL LdrHookImport( _In_ PVOID ImageBase, _In_ UINT32 ImportHash, _In_ PVOID ImportHook )
{
	MEMORY_BASIC_INFORMATION	Mbi;

	BOOLEAN				Ret = FALSE;

	PIMAGE_DOS_HEADER		Dos = NULL;
	PIMAGE_NT_HEADERS		Nth = NULL;
	PIMAGE_THUNK_DATA		Otd = NULL;
	PIMAGE_THUNK_DATA		Nth = NULL;
	PIMAGE_IMPORT_BY_NAME		Ibn = NULL;
	PIMAGE_DATA_DIRECTORY		Dir = NULL;
	PIMAGE_IMPORT_DESCRIPTOR	Imp = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Mbi, sizeof( Mbi ) );

	/* Setup header values */
	Dos = C_PTR( ImageBase );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DATA_DIRECTORY_ENTRY ];

	/* Does the IAT directory exist? */
	if ( Dir->VirtualAddress ) {
		/* Enumerate each library import */
		if ( Imp = C_PTR( U_PTR( Dos ) + Dir->VirtualAddress ) ; Imp->Name != 0 ; ++Imp ) {
			Otd = C_PTR( U_PTR( Dos ) + Imp->OriginalFirstThunk );
			Nth = C_PTR( U_PTR( Dos ) + imp->FirstThunk );

			/* Enumerate each function import */
			for ( ; Otd->u1.AddressOfData != 0 ; ++Otd, ++Ntd ) {
				/* Is this a string import? */
				if ( ! IMAGE_SNAP_BY_ORDINAL( Otd->u1.Ordinal ) ) {
					Ibn = C_PTR( U_PTR( Image ) + Otd->u1.AddressOfData );

					/* Is this our import? */
					if ( HashString( Ibn->Name, 0 ) == ImportHash ) {
						/* Query length of memory region */
						if ( VirtualQuery( Ntd, &Mbi, sizeof( Mbi ) ) == sizeof( Mbi ) ) {
						};
					};
				};
			};
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Mbi, sizeof( Mbi ) );

	/* Return */
	return Ret;
};
