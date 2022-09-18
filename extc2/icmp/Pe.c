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
 * Find a export in a PE.
 *
!*/
D_SEC( B ) PVOID PeGetFuncEat( _In_ PVOID ImageBase, _In_ UINT32 FunctionHash )
{
	PUINT16			Aoo = NULL;
	PUINT32			Aof = NULL;
	PUINT32			Aon = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_DATA_DIRECTORY	Dir = NULL;
	PIMAGE_EXPORT_DIRECTORY	Exp = NULL;

	Dos = C_PTR( ImageBase );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	/* Does the export table exist? */
	if ( Dir->VirtualAddress != 0 ) {
		Exp = C_PTR( U_PTR( Dos ) + Dir->VirtualAddress );
		Aon = C_PTR( U_PTR( Dos ) + Exp->AddressOfNames );
		Aof = C_PTR( U_PTR( Dos ) + Exp->AddressOfFunctions );
		Aoo = C_PTR( U_PTR( Dos ) + Exp->AddressOfNameOrdinals );

		/* Enumerate export directory */
		for ( INT Idx = 0 ; Idx < Exp->NumberOfNames ; ++Idx ) {
			/* Compare the hash */
			if ( HashString( C_PTR( U_PTR( Dos ) + Aon[ Idx ] ), 0 ) == FunctionHash ) {
				/* Return a pointer */
				return C_PTR( U_PTR( Dos ) + Aof[ Aoo[ Idx ] ] );
			};
		};
	};
	/* Return NULL */
	return NULL;
};
