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

#pragma once

/*!
 *
 * Purpose:
 *
 * Creates a DJB2 hash representation of the input 
 * buffer. If a length is not provided, it is presumed 
 * to be a ANSI string that is NULL terminated.
 *
!*/
D_SEC( B ) UINT32 HashString( _In_ PVOID Buffer, _In_ UINT32 Length );
