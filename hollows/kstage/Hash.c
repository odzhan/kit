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

/*!
 *
 * Purpose:
 *
 * Converts an input buffer into a unique
 * DJB2 hash. If no length is provided it
 * assumes its a null terminated string.
 *
!*/
D_SEC( D ) ULONG HashString( PVOID Buffer, ULONG Length )
{
	UCHAR	Val = 0;
	ULONG	Djb = 5381;
	PUCHAR	Ptr = C_PTR( Buffer );

	while ( TRUE ) {
		/* Extract the current character */
		Val = * Ptr;

		if ( ! Length ) {
			/* No length and has a \0? BREAK! */
			if ( ! * Ptr ) {
				break;
			};
		} else {
			/* Position exceeded the length of the buffer? */
			if ( ( ULONG )( Ptr - ( PUCHAR ) Buffer ) >= Length ) {
				break;
			};
			if ( ! * Ptr ) {
				++Ptr; continue;
			};
		};
		/* Force to uppercase */
		if ( Val >= 'a' ) {
			Val -= 0x20;
		};

		/* Create a hash with the new character */
		Djb = ( ( Djb << 5 ) + Djb ) + Val; ++Ptr;
	};
	/* Return! */
	return Djb;
};
