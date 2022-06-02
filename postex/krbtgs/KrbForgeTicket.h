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
 * Forges a ticket to the DC using the specified 
 * encryption algorithm. Returns a pointer to the
 * AP-REP blob and the session key.
 *
!*/
BOOL KrbForgeTicket( _In_ PWCHAR ServicePrincipalName, _In_ ULONG EncryptionType, _In_ PVOID* Req, _In_ PULONG ReqLen, _In_ PVOID* Key, _In_ PULONG KeyLen );
