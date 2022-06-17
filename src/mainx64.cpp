#define SUPPORT_HOOK 64

#include <Windows.h>
#include <iostream>
#include "../header/Hook.cpp"

MEMORY_BASIC_INFORMATION args_src_plage_data; //


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

P_x64_RegisterFunctionHooked RFH;
HOOK_FUNCTION_BODY HookMessageBoxA()
{ 
    Q_WORD EBP;
    x64_M_GetCurrentEBP(EBP);
    P_x64_GetRegisterFunctionHooked(EBP,RFH);

    WriteWordChar((BYTE*)*RFH.r8,(char*)"HOOKED");
    WriteWordChar((BYTE*)*RFH.rdx,(char*)"IS HOOKED !");


    return;
} 

int main(int argc,char* argv[])
{

    StructHook MessageBoxHOOKED =  x64_Hook((Q_WORD)GetProcAddress(GetModuleHandleA("USER32.dll"),"MessageBoxTimeoutA")+0x3,(Q_WORD)HookMessageBoxA,13);
    
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
    return 0; 
}
