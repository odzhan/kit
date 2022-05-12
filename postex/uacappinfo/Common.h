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

#include <windows.h>
#include <ntstatus.h>
#include "Native.h"
#include "Beacon.h"
#include "Macros.h"
#include "ComStr.h"

/* Arch-specific include */
#if defined( _WIN64 )
	#include "x64/appinfo64.h"
#else
	#include "x86/appinfo32.h"
#endif
