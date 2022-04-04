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

#include <windows.h>
#include <ntstatus.h>
#include "Context.h"
#include "Native.h"
#include "Macros.h"
#include "Labels.h"
#include "Buffer.h"
#include "Rogue.h"
#include "Hash.h"
#include "Peb.h"
#include "Pe.h"

#ifndef ROGUE_RETURN_SUCCESS
#define ROGUE_RETURN_SUCCESS 0
#endif

#ifndef ROGUE_RETURN_FAILURE
#define ROGUE_RETURN_FAILURE 1
#endif
