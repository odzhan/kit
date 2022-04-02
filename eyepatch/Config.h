/*!
 *
 * EYEPATCH
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	ULONG	AddressOfEntryPoint;
	ULONG	Length;
	UCHAR	Buffer[0];
} CONFIG, *PCONFIG ;
