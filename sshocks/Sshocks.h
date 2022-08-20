/*!
 *
 * SSHOCKS
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
 * Connects back to the SSH server and establishes
 * a reverse port forward back to our socks target
 *
 * The socks server portion then reads any incoming
 * requests, and forwards them to the respective
 * destinations.
 *
!*/
__declspec( dllexport ) BOOL SshocksInit( VOID );
