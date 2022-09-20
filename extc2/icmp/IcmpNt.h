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

/*!
 *
 * Purpose:
 *
 * Sends an ICMP request over the \Device\Ip driver. Mimics
 * the behavior of IcmpSendEcho to avoid confliction issues
 *
!*/
D_SEC( B ) DWORD IcmpNtSendEcho
(
        _In_            HANDLE                  IcmpHandle,
        _In_            IPAddr                  DestinationAddress,
        _In_            LPVOID                  RequestData,
        _In_            WORD                    RequestSize,
        _Out_           LPVOID                  ReplyBuffer,
        _In_            DWORD                   ReplySize,
        _In_            DWORD                   Timeout
);
