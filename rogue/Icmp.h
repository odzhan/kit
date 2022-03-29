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
 * Sends a buffer over ICMP to the Navi listener.
 *
!*/
D_SEC( B ) BOOL IcmpSend( _In_ PCHAR HostName, _In_ PROGUE_CTX Context, _In_ PVOID Buffer, _In_ ULONG Length );

/*!
 *
 * Purpose:
 *
 * Recieves a buffer over ICMP from Navi.
 *
!*/
D_SEC( B ) BOOL IcmpRecv( _In_ PCHAR HostName, _In_ PROGUE_CTX Context, _In_ PVOID* Buffer, _In_ ULONG* Length );
