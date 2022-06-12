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

#define __INTRINSIC_DEFINED__InterlockedBitTestAndSet
#define __INTRINSIC_DEFINED__InterlockedAdd64
#include <intrin.h>
#include <ntddk.h>
#include <ntifs.h>
#include <ntimage.h>
#include <stdint.h>
#include "Macros.h"
#include "Labels.h"
#include "Table.h"
#include "Hash.h"
#include "Pcr.h"
#include "Pe.h"

#include "InstrumentationCallback.h"
#include "ProcessNotifyRoutine.h"
