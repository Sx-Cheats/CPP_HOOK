#define SUPPORT_HOOK 32

#include<Windows.h>
#include <iostream>
#include "../header/Hook.cpp"
using namespace std;

void WriteWordChar(BYTE*base,BYTE*text)
{
    int idx=0;
    DWORD OldProtect;
    do
    {
        OldProtect=ModifyPageAccess((void*)(base+idx),PAGE_EXECUTE_READWRITE);
        *(base+idx)=*(text+idx);
        ModifyPageAccess((void*)(base+idx),OldProtect);
       
        idx++;
    } while (*(text+idx));
    OldProtect=ModifyPageAccess((void*)(base+idx),PAGE_EXECUTE_READWRITE);
   *(base+idx)=0;
    ModifyPageAccess((void*)(base+idx),OldProtect);
}

P_x32_RegisterFunctionHooked RFH;
HOOK_FUNCTION_BODY HookMessageBoxA()
{
    DWORD EBP;
    x32_M_GetCurrentEBP(EBP);
    P_x32_GetRegisterFunctionHooked(EBP,RFH);
    WriteWordChar((BYTE*)*(DWORD*)((*RFH.esp)+0x10),(char*)"HOOKED");
    WriteWordChar((BYTE*)*(DWORD*)((*RFH.esp)+0xC),(char*)"IS HOOKED !");   
    return;
}

int main(int argc,char* argv[])
{
    StructHook MessageBoxHOOKED =  x32_Hook((DWORD)GetProcAddress(GetModuleHandleA("USER32.dll"),"MessageBoxA")+5,(DWORD)HookMessageBoxA,7);
    
    cout << " Tunnel Base Address : " << hex << (DWORD)MessageBoxHOOKED.BaseTunnel  << endl;
    cout << " HOOK ! " << endl;
   
    MessageBoxA(NULL," NOT HOOKED "," Simple Hook ",MB_OK);
   
    cout << " DETACH ! " << endl;
    MessageBoxHOOKED.Detach();

    MessageBoxA(NULL,"NOT HOOKED","Simple Hook",MB_OK);
    
    cout << " ATTACH ! " << endl;
    MessageBoxHOOKED.Attach();
    
    MessageBoxA(NULL," NOT HOOKED "," Simple Hook ",MB_OK);
    cout << " DESTROY ! " << endl;
    MessageBoxHOOKED.Destroy();
    
    cin.get();
}
