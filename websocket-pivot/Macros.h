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

/* Cast as a function or data in a specific region of memory */
#define D_SEC( x )	__attribute__(( section( ".text$" #x ) ))

/* Cast as a pointer with the same name/typedef */
#define D_API( x )	__typeof__( x ) * x

/* Cast as a pointer-wide integer */
#define U_PTR( x )	( ( ULONG_PTR ) x )

/* Cast as a pointer */
#define C_PTR( x )	( ( PVOID ) x )
