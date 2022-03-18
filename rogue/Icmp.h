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
 * Sends a ICMP Echo request to a listener, and
 * returns a task if one is available. Chunked
 * requests will result in rogue sleeping for
 * periods at a time.
 *
!*/
D_SEC( B ) BOOL IcmpSendRecv( _In_ PCHAR HostName, _In_ PVOID InBuffer, _In_ UINT32 InLength, _Out_ PVOID* OuBuffer, _Out_ PUINT32 OuLength, _In_ PBOOL OuSuccess );
