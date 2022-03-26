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
 * Dispatches a raw message to the Navi web
 * server. If a client is listening in the
 * logs, it will print the data out.
 *
!*/
D_SEC( B ) VOID RogueOutput( _In_ PROGUE_CTX Context, _In_ PCHAR Buffer, _In_ UINT32 Length );

/*!
 *
 * Purpose:
 *
 * Dispatches a formatted message to the Navi
 * webserver. If a client is listening in the
 * logs, it will print the data out.
 *
!*/
D_SEC( B ) VOID RoguePrintf( _In_ PROGUE_CTX Context, _In_ PCHAR Format, ... );
