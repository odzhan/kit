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
 * Creates a DJB2 hash representation of the input 
 * buffer. If a length is not provided, it is presumed 
 * to be a ANSI string that is NULL terminated.
 *
!*/
D_SEC( B ) UINT32 HashString( _In_ PVOID Buffer, _In_ UINT32 Length )
{
	UINT8	Chr = 0;
	PUINT8	Ptr = C_PTR( Buffer );
	UINT32	Hsh = 5381;

	/* Infinite loop until complete */
	while ( TRUE ) {
		/* Get the current character */
		Chr = * Ptr;

		/* No length provided? Must be ANSI */
		if ( ! Length ) {
			/* Did we find the NULL terminator */
			if ( ! * Ptr ) {
				/* Abort */
				break;
			};
		} else {
			/* Position exceeds the length of the buffer? */
			if ( ( UINT32 )( Ptr - ( PUINT8 ) Buffer ) >= Length ) {
				/* Abort */
				break;
			};

			/* NULL terminator? */
			if ( ! * Ptr ) {
				/* Increment to next pointer! */
				++Ptr; continue;
			};
		};

		/* Force to lowercase */
		if ( Chr >= 'a' ) {
			/* Decrement */
			Chr -= 0x20;
		};

		/* Hash the character */
		Hsh = ( ( Hsh << 5 ) + Hsh ) + Chr; ++Ptr;
	};

	/* Return */
	return Hsh;
};
