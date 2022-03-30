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

VOID
RogueOutput(
	_In_ PVOID RogueContext,
	_In_ USHORT Uid,
	_In_ PVOID Buffer,
	_In_ UINT32 Length
);

VOID 
RoguePrintf(
	_In_ PVOID RogueContext,
	_In_ USHORT Uid,
	_In_ PCHAR Format,
	...
);

typedef struct
{
	__typeof__( RogueOutput ) * RogueOutput;
	__typeof__( RoguePrintf ) * RoguePrintf;
} ROGUE_API, *PROGUE_API ;
