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
 * Hashes an input buffer. ANSI strings do not 
 * need a length if they are null terminated.
 * Unicode string requires the complete length
 *
!*/
UINT32 HashString( _In_ PVOID Buffer, _In_ UINT32 Length )
{
	UINT8	Cur = 0;
	UINT32	Djb = 5381;
	PUINT8	Ptr = C_PTR( Buffer );

	while ( TRUE ) {
		/* Get the current character */
		Cur = * Ptr;

		/* No length provided? */
		if ( ! Length ) {
			/* Abort if we reach a null terminator */
			if ( ! * Ptr ) {
				break;
			};
		} else 
		{
			/* Position exceed the length of the buffer? */
			if ( ( UINT32 )( Ptr - ( PUINT8 ) Buffer ) >= Length ) {
				break;
			};
			/* 'NULL' character */
			if ( ! * Ptr ) {
				++Ptr; continue;
			};
		};

		/* Is this value lowercase? */
		if ( Cur >= 'a' ) {
			/* Force to uppercase */
			Cur -= 0x20;
		};

		/* Hash the character */
		Djb = ( ( Djb << 5 ) + Djb ) + Cur; ++Ptr;
	};

	/* Return Hash */
	return Djb;
};
