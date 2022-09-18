/*!
 *
 * ICMP
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

/* Helps with locating functions or globals virtual memory address */
#define G_SYM( x )	( ULONG_PTR )( GetIp ( ) - ( ( ULONG_PTR ) & GetIp - ( ULONG_PTR ) x ) )

/* Cast as a variable or section in a specific order */
#define D_SEC( x )	__attribute__(( section( ".text$" #x ) ))

/* Cast as a pointer with a specific typedef */
#define D_API( x )	__typeof__( x ) * x

/* Cast as a integer pointer */
#define U_PTR( x )	( ( ULONG_PTR ) x )

/* Cast as a pointer */
#define C_PTR( x )	( ( PVOID ) x )
