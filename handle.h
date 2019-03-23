#ifndef _ENUM2_H_
 #define _ENUM2_H_


#include <stdio.h>
//#include <sddl.h>
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

typedef struct _credenciales{
   HANDLE hToken;
   DWORD pid; //Identificador de proceso del que se ha extraido el Token
   char user[256];
   SYSTEMTIME SystemTime;
} CREDENCIALES;

#define MAX_USERS 1000
   
typedef LONG   NTSTATUS;
typedef VOID   *POBJECT;


typedef struct _IO_STATUS_BLOCK {
   union {
      NTSTATUS Status;
      PVOID Pointer;
   };
   ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;


typedef void (WINAPI * PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, DWORD);

typedef LONG TDI_STATUS;
typedef PVOID CONNECTION_CONTEXT;       // connection context

typedef struct _TDI_REQUEST {
   union {
      HANDLE AddressHandle;
      CONNECTION_CONTEXT ConnectionContext;
      HANDLE ControlChannel;
   } Handle;
   
   PVOID RequestNotifyObject;
   PVOID RequestContext;
   TDI_STATUS TdiStatus;
} TDI_REQUEST, *PTDI_REQUEST;

typedef struct _TDI_CONNECTION_INFORMATION {
   LONG UserDataLength;        // length of user data buffer
   PVOID UserData;             // pointer to user data buffer
   LONG OptionsLength;         // length of following buffer
   PVOID Options;              // pointer to buffer containing options
   LONG RemoteAddressLength;   // length of following buffer
   PVOID RemoteAddress;        // buffer containing the remote address
} TDI_CONNECTION_INFORMATION, *PTDI_CONNECTION_INFORMATION;

typedef struct _TDI_REQUEST_QUERY_INFORMATION {
   TDI_REQUEST Request;
   ULONG QueryType;                          // class of information to be queried.
   PTDI_CONNECTION_INFORMATION RequestConnectionInformation;
} TDI_REQUEST_QUERY_INFORMATION, *PTDI_REQUEST_QUERY_INFORMATION;

#define TDI_QUERY_ADDRESS_INFO                  0x00000003
#define IOCTL_TDI_QUERY_INFORMATION             CTL_CODE(FILE_DEVICE_TRANSPORT, 4, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)


typedef struct _SYSTEM_HANDLE {
   ULONG           uIdProcess;
   UCHAR           ObjectType;
   UCHAR           Flags;
   USHORT          Handle;
   POBJECT         pObject;
   ACCESS_MASK     GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
   ULONG                   uCount;
   SYSTEM_HANDLE   Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _UNICODE_STRING {
   USHORT Length;
   USHORT MaximumLength;
   PWSTR  Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef UNICODE_STRING OBJECT_NAME_INFORMATION;
typedef UNICODE_STRING *POBJECT_NAME_INFORMATION;


typedef enum _OBJECT_INFORMATION_CLASS{
   ObjectBasicInformation,
      ObjectNameInformation,
      ObjectTypeInformation,
      ObjectAllTypesInformation,
      ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;

#define STATUS_SUCCESS                          ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH             ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW                  ((NTSTATUS)0x80000005L)
#define SystemHandleInformation                 16


typedef enum _PROCESSINFOCLASS {
   ProcessBasicInformation,
      ProcessQuotaLimits,
      ProcessIoCounters,
      ProcessVmCounters,
      ProcessTimes,
      ProcessBasePriority,
      ProcessRaisePriority,
      ProcessDebugPort,
      ProcessExceptionPort,
      ProcessAccessToken,
      ProcessLdtInformation,
      ProcessLdtSize,
      ProcessDefaultHardErrorMode,
      ProcessIoPortHandlers,          // Note: this is kernel mode only
      ProcessPooledUsageAndLimits,
      ProcessWorkingSetWatch,
      ProcessUserModeIOPL,
      ProcessEnableAlignmentFaultFixup,
      ProcessPriorityClass,
      MaxProcessInfoClass
} PROCESSINFOCLASS;


typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    MaxThreadInfoClass
    } THREADINFOCLASS;



typedef struct _PROCESS_BASIC_INFORMATION {
   DWORD ExitStatus;
   PVOID PebBaseAddress;
   DWORD AffinityMask;
   DWORD BasePriority;
   DWORD UniqueProcessId;
   DWORD InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS {

FileDirectoryInformation, 
FileFullDirectoryInformation, 
FileBothDirectoryInformation, 
FileBasicInformation, 
FileStandardInformation, 
FileInternalInformation, 
FileEaInformation, 
FileAccessInformation, 
FileNameInformation, 
FileRenameInformation, 
FileLinkInformation, 
FileNamesInformation, 
FileDispositionInformation, 
FilePositionInformation, 
FileFullEaInformation, 
FileModeInformation, 
FileAlignmentInformation, 
FileAllInformation, 
FileAllocationInformation, 
FileEndOfFileInformation, 
FileAlternateNameInformation, 
FileStreamInformation, 
FilePipeInformation, 
FilePipeLocalInformation, 
FilePipeRemoteInformation, 
FileMailslotQueryInformation, 
FileMailslotSetInformation, 
FileCompressionInformation, 
FileCopyOnWriteInformation, 
FileCompletionInformation, 
FileMoveClusterInformation, 
FileQuotaInformation, 
FileReparsePointInformation, 
FileNetworkOpenInformation, 
FileObjectIdInformation, 
FileTrackingInformation, 
FileOleDirectoryInformation, 
FileContentIndexInformation, 
FileInheritContentIndexInformation, 
FileOleInformation, 
FileMaximumInformation

} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;


typedef struct _FILE_NAME_INFORMATION {
  ULONG  FileNameLength;
  WCHAR  FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;


typedef 	NTSTATUS (WINAPI *NTQUERYINFORMATIONPROCESS) (
                                                       HANDLE ProcessHandle,
                                                       PROCESSINFOCLASS ProcessInformationClass,
                                                       PVOID ProcessInformation,
                                                       DWORD ProcessInformationLength,
                                                       DWORD *ReturnLength);

typedef NTSTATUS (WINAPI *NTQUERYSYSTEMINFORMATION)(DWORD SystemInformationClass, 
                                                    PVOID SystemInformation,
                                                    DWORD SystemInformationLength, 
                                                    PDWORD ReturnLength);

typedef NTSTATUS (WINAPI *NTQUERYOBJECT)(
                                         HANDLE ObjectHandle, 
                                         OBJECT_INFORMATION_CLASS ObjectInformationClass, 
                                         PVOID ObjectInformation,
                                         DWORD Length, 
                                         PDWORD ResultLength);

typedef NTSTATUS (WINAPI *NTDEVICEIOCONTROLFILE)(HANDLE FileHandle, 
                                                 HANDLE Event, 
                                                 PIO_APC_ROUTINE ApcRoutine, 
                                                 PVOID ApcContext,
                                                 PIO_STATUS_BLOCK IoStatusBlock, 
                                                 DWORD IoControlCode,
                                                 PVOID InputBuffer, 
                                                 DWORD InputBufferLength,
                                                 PVOID OutputBuffer, 
                                                 DWORD OutputBufferLength);

typedef NTSTATUS (WINAPI * NTQUERYINFORMATIONTHREAD) (
                                 HANDLE hthread,
											THREADINFOCLASS ThreadInfoClass,
											PVOID ThreadInformation,
											DWORD Length,
											DWORD *ReturnLength);


typedef 	NTSTATUS (WINAPI *NTQUERYINFORMATIONFILE )(
                                                    HANDLE FileHandle,
                                                    PVOID IoStatusBlock,
                                                    PVOID FileInformation,
                                                    DWORD Length,
                                                    DWORD FileInformationClass);


typedef NTSTATUS (WINAPI *NTCOMPARETOKENS) (
  HANDLE FirstTokenHandle,
  HANDLE SecondTokenHandle,
  PBOOLEAN Equal
);


#define OBJTOKEN 1
#define OBJTHREAD 2
#define OBJPROCESS 3
#define OBJFILE 4
#define OBJUNKNOWN 5

#endif