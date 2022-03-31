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

typedef struct
{
	/* Static */
	UCHAR		Id[ 10 ];

	/* Settings */
	UINT32		SleepTime;
	UINT32		Jitter;

	/* Callback */
	LPVOID		Exit;

	/* On / Off */
	BOOLEAN		Established;
} ROGUE_CTX, *PROGUE_CTX;
