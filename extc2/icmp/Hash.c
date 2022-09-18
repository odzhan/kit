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
 * Creates a DJB2 hash representation of the 
 * input buffer.
 *
!*/
D_SEC( B ) UINT32 HashString( _In_ PVOID Buffer, _In_ UINT32 Length )
{
	UINT8	Val = 0;
	UINT32	Hsh = 5381;
	PUINT8	Ptr = C_PTR( Buffer );

	while ( TRUE ) {
		/* Get the current character */
		Val = *Ptr;

		if ( ! Length ) {
			/* Terminated by a null character? */
			if ( ! * Ptr ) {
				break;
			};
		} else {
			/* Position exceed the length of the buffer? */
			if ( ( UINT32 )( Ptr - ( PUINT8 ) Buffer ) >= Length ) {
				break;
			};
			/* Terminated by a null character? */
			if ( ! * Ptr ) {
				/* Increment and restart loop */
				++Ptr; continue;
			};
		};

		/* Force to uppercase */
		if ( Val >= 'a' ) {
			Val -= 0x20;
		};

		/* Create the hash */
		Hsh = ( ( Hsh << 5 ) + Hsh ) + Hsh; ++Ptr;
	};
	return Hsh;
};
