/*!
 *
 * PostEx
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

/*!
 *
 * Purpose:
 *
 * Replaces SysAllocString to reduce the use of 
 * the OLEAUT32 import requirement for RPC.
 *
!*/
PVOID WINAPI ComCreateString( _In_ PCHAR Buffer );

/*!
 *
 * Purpose:
 *
 * Reaplces SysFreeString to reduce the use of
 * the OLEAUT32 import requirement for RPC.
 *
!*/
VOID WINAPI ComFreeString( _In_ PCHAR Buffer );
