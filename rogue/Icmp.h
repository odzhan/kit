/*!
 *
 * ROGUE
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
 * Sends a buffer over ICMP back to the listener.
 * Uses ICMP Echo requests to safely operate 
 * without issue. Data is returned if it matches
 * the specification.
 *
!*/
D_SEC( B ) BOOL IcmpSend( _In_ PCHAR HostName, _In_ PVOID InBuffer, _In_ UINT32 InLength, _Out_ PVOID* OuBuffer, _Out_ PUINT32 OuLength );
