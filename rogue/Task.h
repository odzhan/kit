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

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	UINT32	TaskCode;
	UINT32	TaskId;
	UINT32	Length;
	UCHAR	Buffer[0];
} TASK_REQ_HDR, *PTASK_REQ_HDR ;

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	UINT32	TaskId;
	UINT32	ReturnCode;
	UINT32	ErrorValue;
	UCHAR	Buffer[0];
} TASK_RET_HDR, *PTASK_RET_HDR ;

typedef enum 
{
	Hello         = 0,
	Exit          = 1,
	InlineExecute = 2
} TASK_CODE ;

typedef enum
{
	NoAction          = 0,
	ErrorAction       = 1,
	ExitFreeAction    = 2,
	PrintOutputAction = 3
} TASK_RETURN_CALLBACK ;
