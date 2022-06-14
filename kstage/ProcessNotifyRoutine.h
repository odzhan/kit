/*!
 *
 * KSTAGE
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
 * Checks if Lsa is being created and installs a
 * InstrumentationCallback to be executed when
 * the next system call is run.
 *
!*/
D_SEC( B ) VOID ProcessNotifyRoutine( HANDLE PrId, HANDLE CrId, BOOLEAN Create );
