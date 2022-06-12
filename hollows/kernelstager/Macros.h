/*!
 *
 * KERNELDOOR
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

/* Gets a pointer to the function or string via its relative offset to GetIp() */
#define G_PTR( x )	( ULONG_PTR )( GetIp( ) - ( ( ULONG_PTR ) & GetIp - ( ULONG_PTR ) x ) )

/* Cast as a funciton or region of memory to be stored in a specific location */
#define D_SEC( x )	__attribute__(( section( ".text$" #x ) ))

/* Cast as a function with a specified typedef */
#define D_API( x )	__typeof__( x ) * x

/* Cast as a pointer-wide integer */
#define U_PTR( x )	( ( ULONG_PTR ) x )

/* Cast as a pointer */
#define C_PTR( x )	( ( PVOID ) x )
