/*
* Handle Information for Win32
* Author: Andres Tarasco Acuña ( http://www.514.es )
* Email: atarasco @ 514.es - atarasco @ gmail.com
*/

#include "handle.h"

NTQUERYOBJECT              NtQueryObject ;
NTQUERYSYSTEMINFORMATION   NtQuerySystemInformation; 
NTQUERYINFORMATIONPROCESS  NtQueryInformationProcess;
NTDEVICEIOCONTROLFILE      NtDeviceIoControlFile ;
NTQUERYINFORMATIONTHREAD   NtQueryInformationThread;
NTQUERYINFORMATIONFILE     NtQueryInformationFile ;


void           banner(void);
void           EnableDebugPrivilege();
LPWSTR         GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass);
DWORD          QueryObjectName (HANDLE handle,char *txt);
DWORD WINAPI   FilenameFromHandle (PVOID  lpParameter);
void           process_owner(HANDLE htoken);



/********************************************************************/

DWORD GetOption (LPWSTR lpwsType, LPWSTR lpwsName) {
   if (lpwsType==NULL) {
      return(0);
   } else {            
      if (!wcscmp(lpwsType, L"Token") ) return OBJTOKEN;
      if (!wcscmp(lpwsType, L"Thread")) return OBJTHREAD;
      if(!wcscmp(lpwsType, L"Process")) return OBJPROCESS;
      if(!wcscmp(lpwsType, L"File"))    return OBJFILE;                
   }
   return (OBJUNKNOWN);
   
}
/********************************************************************/
char crap[512];
/********************************************************************/

int main(int argc, char *argv[])
{
   
   DWORD i,total,dwSize = sizeof(SYSTEM_HANDLE_INFORMATION);
   PSYSTEM_HANDLE_INFORMATION pHandleInfo ;
   NTSTATUS ntReturn;
   HANDLE hProcess ; 


   //load exported functions..
   NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQuerySystemInformation");
   NtQueryObject= (NTQUERYOBJECT)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQueryObject");
   NtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQueryInformationProcess");
   NtDeviceIoControlFile  = (NTDEVICEIOCONTROLFILE)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtDeviceIoControlFile");
   NtQueryInformationThread  = (NTQUERYINFORMATIONTHREAD)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQueryInformationThread");
   NtQueryInformationFile  = (NTQUERYINFORMATIONFILE)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQueryInformationFile");
   
   if ( (!NtQuerySystemInformation) || (!NtQueryObject) || (!NtQueryInformationProcess) || 
      (!NtDeviceIoControlFile) || (!NtQueryInformationThread) || (!NtQueryInformationFile) ) {
      printf("Error chungo!\n"); exit(1);
      
   }
   
   EnableDebugPrivilege();
   pHandleInfo = (PSYSTEM_HANDLE_INFORMATION) malloc(dwSize);
   ntReturn = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, dwSize, &dwSize);
   
   if(ntReturn == STATUS_INFO_LENGTH_MISMATCH){
      free(pHandleInfo);
      pHandleInfo = (PSYSTEM_HANDLE_INFORMATION) malloc(dwSize);
      ntReturn = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, dwSize, &dwSize);
   }
   if(ntReturn != STATUS_SUCCESS) return(0);
   
   
   
#ifdef _DBG_  
   printf("Found %i Handles\n", pHandleInfo->uCount);
#endif
   printf("--------------------------------------------------------------------------------\n");
   printf("  PID       PROCCESS    HANDLE        TYPE    DATA\n");
   printf("--------------------------------------------------------------------------------\n");
   
   
   for(i = 0; i < pHandleInfo->uCount; i++)
   {          
      hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE, pHandleInfo->Handles[i].uIdProcess); //PROCESS_ALL_ACCESS
      if(hProcess != INVALID_HANDLE_VALUE)
      {
         char lpszProcess[MAX_PATH]="";
         HANDLE hObject = NULL;
         GetModuleFileNameEx(hProcess, NULL, lpszProcess, MAX_PATH); 
         
         if(DuplicateHandle(hProcess, (HANDLE)pHandleInfo->Handles[i].Handle,GetCurrentProcess(), &hObject, DUPLICATE_SAME_ACCESS, FALSE, DUPLICATE_SAME_ACCESS) != FALSE)              
         {
            //Información del Path
            LPWSTR lpwsType=NULL;
            LPWSTR lpwsName=NULL;
            DWORD ret;
            PROCESS_BASIC_INFORMATION pbi;  
            HANDLE dst;
            char  path[MAX_PATH];
            DWORD buff[7] = {0,0,0,0,0,0,0};    
            
            //Informacion del tipo de objeto
            lpwsType = GetObjectInfo(hObject, ObjectTypeInformation);              
            printf("%5d %16s %4.x\t%12ws  ",//  %-16ws%-18s%ws",
               pHandleInfo->Handles[i].uIdProcess,                                     
               ((lstrlen(lpszProcess) > 0)?PathFindFileName(lpszProcess):"[System]"),
               pHandleInfo->Handles[i].Handle,
               lpwsType);
            
            
            ret=GetOption(lpwsType,lpwsName);
            
            switch (ret) {
            case 0: //NULL lpwsType..
               break;
               
            case OBJTOKEN:
               process_owner(hObject);
               break;
               
            case OBJPROCESS:               
               ZeroMemory (&pbi, sizeof (PROCESS_BASIC_INFORMATION));                                 
               if (NtQueryInformationProcess (hObject,ProcessBasicInformation,&pbi,
                  sizeof (PROCESS_BASIC_INFORMATION),NULL)==0) 
               {                  
                  //path = malloc(MAX_PATH);                     
                  //ZeroMemory(path, MAX_PATH);
                  
                  dst=OpenProcess( PROCESS_ALL_ACCESS, TRUE,pbi.UniqueProcessId);
                  if (dst!=INVALID_HANDLE_VALUE) {
                     GetModuleFileNameEx(dst, NULL, path, MAX_PATH); 
                     printf ("PID: 0x%04x - %s\n", pbi.UniqueProcessId, 
                        (lstrlen(path) > 0)?PathFindFileName(path):"[System]"); 
                     CloseHandle(dst);
                  } else {
                     printf ("PID: 0x%04x - %s\n", pbi.UniqueProcessId,"<Error Opening Id>");
                  }
               } else
               {
                  printf("Error con NtQueryInformationProcess() %x\n",GetLastError());
               } 
               break;
               
            case OBJTHREAD:               
               NtQueryInformationThread (hObject,ThreadBasicInformation,buff,28,NULL);
               printf("TID: 0x%04x\n",buff[3]);
               break;
               
            case OBJFILE:               
               memset(crap,0,256);
               if (  (QueryObjectName(hObject,crap)!=0) && (strlen(crap)==0) ){
                  lpwsName = GetObjectInfo(hObject, ObjectNameInformation);
                  printf("%ws ",lpwsName);
                  if ( (lpwsName!=NULL)  && (!wcscmp(lpwsName, L"\\Device\\Tcp") || !wcscmp(lpwsName, L"\\Device\\Udp")) )
                  {
                     IO_STATUS_BLOCK IoStatusBlock;
                     TDI_REQUEST_QUERY_INFORMATION tdiRequestAddress = {{0}, TDI_QUERY_ADDRESS_INFO};
                     BYTE tdiAddress[128];
                     HANDLE hEvent2 = CreateEvent(NULL, TRUE, FALSE, NULL);
                     NTSTATUS ntReturn2 = NtDeviceIoControlFile(hObject, hEvent2, NULL, NULL, &IoStatusBlock, IOCTL_TDI_QUERY_INFORMATION,
                        &tdiRequestAddress, sizeof(tdiRequestAddress), &tdiAddress, sizeof(tdiAddress));
                     if(hEvent2) CloseHandle(hEvent2);
                     
                     if(ntReturn2 == STATUS_SUCCESS){
                        struct in_addr *pAddr = (struct in_addr *)&tdiAddress[14];
                        printf("@%s:%d", inet_ntoa(*pAddr), ntohs(*(PUSHORT)&tdiAddress[12]));
                     }
                  }
               }
               printf("\n");                           
               break;
            default:
               lpwsName = GetObjectInfo(hObject, ObjectNameInformation);         
               if (lpwsName){
                  printf("%ws",lpwsName);
                  free(lpwsName);
               }
               
               printf("\n");
               break;
            }
            CloseHandle(hObject);
            if (lpwsType) free(lpwsType);
         } else {
            //Objeto no duplicado....
         }
         free(lpszProcess);
         CloseHandle(hProcess);
      } else {
         //No se ha podido abrir el handle... :?
         
      }
      
      }
      
      free(pHandleInfo);
      return(0);
}

/***************************************************************************************/
void process_owner(HANDLE htoken)
{
/*
Extract information from a process Token and dumps owner information.
   */
   DWORD 	dwLen;
   PSID	pSid=0;	// contains the owning user SID
   TOKEN_USER *pWork;
   SID_NAME_USE	use;//=0;
   TCHAR username[256];
   TCHAR domainname[256];
   
   //printf(" HTOKEN: %x",&htoken);
   
   GetTokenInformation(htoken, TokenUser, NULL, 0, &dwLen);
   pWork= (TOKEN_USER *)LocalAlloc( LMEM_ZEROINIT,dwLen);
   if (GetTokenInformation(htoken, TokenUser, pWork, dwLen, &dwLen)) {
      dwLen = GetLengthSid(pWork->User.Sid);
      pSid= (PSID)LocalAlloc( LMEM_ZEROINIT,dwLen);
      CopySid(dwLen, pSid, pWork->User.Sid);
      dwLen=256;
      LookupAccountSid(NULL, pSid, &username[0], &dwLen, &domainname[0], &dwLen, &use);
      printf("\\\\%s\\%s\n",domainname,username);
   }
}
/***************************************************************************************/

LPWSTR GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass)
{
   LPWSTR data = NULL;
   DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
   POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION) malloc(dwSize);
   
   NTSTATUS ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);   
   if((ntReturn == STATUS_BUFFER_OVERFLOW) || (ntReturn == STATUS_INFO_LENGTH_MISMATCH)){
      pObjectInfo =realloc(pObjectInfo ,dwSize);
      ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
   }
   if((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != NULL))
   {
      data = (LPWSTR) malloc(pObjectInfo->Length + sizeof(WCHAR));
      memset(data,0,pObjectInfo->Length + sizeof(WCHAR));   
      CopyMemory(data, pObjectInfo->Buffer, pObjectInfo->Length);
   }
   free(pObjectInfo);
   return data;
}
/**************************************/

DWORD WINAPI  GetFileNameThread(void *handle)
{
   //TODO: Fix crap as parameter
   DWORD iob[2];
   
   NtQueryInformationFile (handle, &iob, crap, 512, 9);
   printf("%S",&crap[4]);
   return(1);
}
/**************************************/

DWORD QueryObjectName (HANDLE handle, char *txt)
{
   DWORD num_bytes = 0;
   char tmp[512] = {0,0,0,0};
   
   DWORD tid;
   HANDLE hthread;
   hthread = CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE)GetFileNameThread,handle, 0, &tid);
   if (WaitForSingleObject (hthread, 50) == WAIT_TIMEOUT)
   {	
      TerminateThread (hthread, 0);
      CloseHandle (hthread);
      printf("THREAD BLOCKED... ACCESS DENIED!");
      return(0);
   }
   else
   {		
      CloseHandle (hthread);        
   }
   
   return (1);
}

/******************************************************************************/
void banner(void){
   printf(" Handle Information for Windows (c) 2006\n");
   printf(" Author: Andres Tarasco ( atarasco @ sia . es )\n");
   printf(" URL: http://www.514.es\n\n");
}
/******************************************************************************/
/********************************************************************/
void EnableDebugPrivilege()
{
   HANDLE hToken;
   TOKEN_PRIVILEGES tokenPriv;
   LUID luidDebug;
   if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) != FALSE) {
      if(LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug) != FALSE)
      {
         tokenPriv.PrivilegeCount           = 1;
         tokenPriv.Privileges[0].Luid       = luidDebug;
         tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
         AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL);
      }
   }
}
/******************************************************************************/