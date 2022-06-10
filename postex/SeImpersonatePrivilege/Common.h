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

#if defined( _WIN64 )
#include "rprn/x64/ms-rprn.h"
#else
#include "rprn/x86/ms-rprn.h"
#endif
