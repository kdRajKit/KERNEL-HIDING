#include "ntddk.h"

// The following value is arbitrarily chosen from the space defined by Microsoft
//as being "for non-Microsoft use"

#define FILE_DEVICE_NOTHING 0xCF53

// Device control codes - values between 2048 and 4095 arbitrarily chosen
#define IOCTL_NOTHING CTL_CODE(FILE_DEVICE_NOTHING, 2049, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _MMPTE_HARDWARE
{
	ULONGLONG Valid : 1;
	ULONGLONG Writable : 1;
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Accessed : 1;
	ULONGLONG Dirty : 1;
	ULONGLONG LargePage : 1;
	ULONGLONG Global : 1;
	ULONGLONG CopyOnWrite : 1;
	ULONGLONG Prototype : 1;
	ULONGLONG WriteSoftware : 1;
	ULONGLONG PageFrameNumber : 36;
	ULONGLONG ReservedHardware : 4;
	ULONGLONG ReservedSoftware : 4;
	ULONGLONG WsleAge : 4;
	ULONGLONG WsleProtection : 3;
	ULONGLONG NoExecute : 1;
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;

typedef struct _MMPTE
{
	union
	{
		ULONG_PTR Long;
		MMPTE_HARDWARE Hard;
	} u;
} MMPTE;
typedef MMPTE* PMMPTE;

typedef struct _HIDING_INFO
{
	int PID;
	DWORD64 VADtargetStartAddress;
	DWORD64 VADtargetEndAddress;
	DWORD64 PTEtargetStartAddress;
	DWORD64 PTEtargetEndAddress;
	DWORD64 VADPTEtargetStartAddress;
	DWORD64 VADPTEtargetEndAddress;
	DWORD64 cleanStartAddress;
	DWORD64 cleanEndAddress;

} HIDING_INFO, * PHIDING_INFO;


