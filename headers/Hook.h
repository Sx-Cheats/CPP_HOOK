
#include "./Ntapi.h"

int TunnelOffsetInstruction=0;

#define DUMMY_FUNCTION __declspec(naked) void __cdecl
#define HOOK_FUNCTION_BODY void __cdecl

typedef unsigned __int64 Q_WORD;

DWORD ModifyPageAccess(void*base,DWORD ID)
{
    MEMORY_BASIC_INFORMATION src_plage_data; 
    DWORD OldProtect;
    NtQueryVirtualMemory(NtCurrentProcess(),base,NULL,&src_plage_data,sizeof(src_plage_data),NULL);
    NtProtectVirtualMemory(GetCurrentProcess(),&src_plage_data.BaseAddress,&src_plage_data.RegionSize,ID,&OldProtect); 
    return OldProtect;
}

#if SUPPORT_HOOK==64

  int Base_Tunnel_Size = 94;
  BYTE ValidOpCodeSrc  = 0x57; //  push rdi

    #define x64_M_GetCurrentEBP(buffer)\
      asm("movq %0, rbp":"=r"(buffer));

    template<typename RT>
    struct _REGISTER_FUNCTION_HOOKED_x64
    {
        RT rax=0;
        RT rbx=0;
        RT rcx=0;
        RT rdx=0;
        RT rsi=0;
        RT rdi=0;
        RT rbp=0;

        RT r8=0;
        RT r9=0;
        RT r10=0;
        RT r11=0;
        RT r12=0;
        RT r13=0;
        RT r14=0;
        RT r15=0;

    };

    typedef _REGISTER_FUNCTION_HOOKED_x64 <Q_WORD> x64_RegisterFunctionHooked;
    typedef _REGISTER_FUNCTION_HOOKED_x64 <Q_WORD*> P_x64_RegisterFunctionHooked;

  struct  _Rx64_
{
    struct _mov_
    {
        DWORD RAX = 0xb8;
        DWORD RBX = 0xbb;
        DWORD RCX = 0xb9;
        DWORD RDX = 0xba;
        DWORD RSI = 0xbe;
        DWORD RDI = 0xbf;

    } mov;

    struct _push_
    {
        DWORD RAX = 0x50;
        DWORD RBX = 0x53;
        DWORD RCX = 0x51;
        DWORD RDX = 0x52;
        DWORD RSI = 0x56;
        DWORD RDI = 0x57;

    } push;

     struct _pop_
    {
        DWORD RAX = 0x58;
        DWORD RBX = 0x5b;
        DWORD RCX = 0x59;
        DWORD RDX = 0x5a;
        DWORD RSI = 0x5e;
        DWORD RDI = 0x5f;

    } pop;

    struct  _jmp_
    {
        DWORD RAX = 0xe0;
        DWORD RBX = 0xe3;
        DWORD RCX = 0xe1;
        DWORD RDX = 0xe2;
        DWORD RSI = 0xe6;
        DWORD RDI = 0xe7;

     } jmp; 

} Rx64;

void inline __cdecl x64_GetRegisterFunctionHooked(Q_WORD CurrentEBP,x64_RegisterFunctionHooked & RFH)
{
    // CurrentEBP = ebp =  ebp from callback function hooked (fixed align between tunnel & callback)
    RFH.r15 = (Q_WORD)(*(Q_WORD*)(CurrentEBP+16));
    RFH.r14 = (Q_WORD)(*(Q_WORD*)(CurrentEBP+24));
    RFH.r13 = (Q_WORD)(*(Q_WORD*)(CurrentEBP+32));
    RFH.r12 = (Q_WORD)(*(Q_WORD*)(CurrentEBP+40));
    RFH.r11 = (Q_WORD)(*(Q_WORD*)(CurrentEBP+48));
    RFH.r10 = (Q_WORD)(*(Q_WORD*)(CurrentEBP+56));
    RFH.r9  = (Q_WORD)(*(Q_WORD*)(CurrentEBP+64));
    RFH.r8  = (Q_WORD)(*(Q_WORD*)(CurrentEBP+72));

    RFH.rsi =  (Q_WORD)(*(Q_WORD*)(CurrentEBP+80));
    RFH.rdx =  (Q_WORD)(*(Q_WORD*)(CurrentEBP+88));
    RFH.rcx =  (Q_WORD)(*(Q_WORD*)(CurrentEBP+96));
    RFH.rbx =  (Q_WORD)(*(Q_WORD*)(CurrentEBP+104));
    RFH.rax =  (Q_WORD)(*(Q_WORD*)(CurrentEBP+112));
    RFH.rbp  = (Q_WORD)(*(Q_WORD*)(CurrentEBP+120));
    RFH.rdi =  (Q_WORD)(*(Q_WORD*)(CurrentEBP+128));

}

void inline __cdecl P_x64_GetRegisterFunctionHooked(Q_WORD CurrentEBP,P_x64_RegisterFunctionHooked & RFH)
{
    RFH.r15 = (Q_WORD*)(CurrentEBP+16);
    RFH.r14 = (Q_WORD*)(CurrentEBP+24);
    RFH.r13 = (Q_WORD*)(CurrentEBP+32);
    RFH.r12 = (Q_WORD*)(CurrentEBP+40);
    RFH.r11 = (Q_WORD*)(CurrentEBP+48);
    RFH.r10 = (Q_WORD*)(CurrentEBP+56);
    RFH.r9  = (Q_WORD*)(CurrentEBP+64);
    RFH.r8  = (Q_WORD*)(CurrentEBP+72);

    RFH.rsi =  (Q_WORD*)(CurrentEBP+80);
    RFH.rdx =  (Q_WORD*)(CurrentEBP+88);
    RFH.rcx =  (Q_WORD*)(CurrentEBP+96);
    RFH.rbx =  (Q_WORD*)(CurrentEBP+104);
    RFH.rax =  (Q_WORD*)(CurrentEBP+112);
    RFH.rbp  = (Q_WORD*)(CurrentEBP+120);
    RFH.rdi =  (Q_WORD*)(CurrentEBP+128);
    
}

DUMMY_FUNCTION  TopBodyTunnel_x64()
{ 
   asm("pushq    rbp");
   asm("pushq    rax");
   asm("pushq    rbx");
   asm("pushq    rcx");
   asm("pushq    rdx");
   asm("pushq    rsi");

   asm("pushq    r8");
   asm("pushq    r9");
   asm("pushq    r10");
   asm("pushq    r11");
   asm("pushq    r12");
   asm("pushq    r13");
   asm("pushq    r14");
   asm("pushq    r15");
   asm("movq     rbp,rsp");
   asm("ret");
 
}

DUMMY_FUNCTION BottomBodyTunnel_x64()
{
    asm("movq     rsp,rbp"); //size : (mov)3 + (operande)7 = 10

    asm("popq     r15");
    asm("popq     r14");
    asm("popq     r13");
    asm("popq     r12");
    asm("popq     r11");
    asm("popq     r10");
    asm("popq     r9");
    asm("popq     r8");
    
    asm("popq     rsi");
    asm("popq     rdx");
    asm("popq     rcx");
    asm("popq     rbx");
    asm("popq     rax");
    asm("popq     rbp");
    asm("popq     rdi"); // size : 1
    asm("ret");
}

void jmp_from_register(DWORD rg,BYTE*to)
{
  *to= 0xFF;
  *(to+1)=(BYTE)rg;
  TunnelOffsetInstruction +=2;

}

void push_register(BYTE rg,BYTE * to)
{
   *to = rg;
   TunnelOffsetInstruction +=1;

}

template<typename T>
void mov_in_register(BYTE rg,BYTE * to,T op)
{
    *to=0x48; // mov
    *(to+1)=rg;
    *(T*)(to+2)=(T)op;
    TunnelOffsetInstruction+=2+sizeof(T);
}

void pop_in_register(BYTE *to,BYTE rg)
{
  *to=rg;
  TunnelOffsetInstruction +=1;
}

void mov_in_stack_from_register(BYTE*to,BYTE op,size_t offset)
{
    BYTE RealRegister = (op== Rx64.mov.RAX) ? 0x44 : (op== Rx64.mov.RBX) ? 0x5C : (op== Rx64.mov.RCX) ? 0x4C : (op== Rx64.mov.RDI) ? 0x7C : (op== Rx64.mov.RDX) ? 0x54  : (op== Rx64.mov.RSI) ? 0x74 : 0;

   if(!RealRegister)
          return;

   *(to)=0x48;
   *(to+1)=0x89;
   *(to+2)=RealRegister;
   *(to+3)=0x24;
   *(to+4)=offset;

   TunnelOffsetInstruction+=5;


}

  #elif SUPPORT_HOOK==32

  int Base_Tunnel_Size = 34;
  BYTE ValidOpCodeSrc = 0xE9;
 
  #define x32_M_GetCurrentEBP(buffer)\
      asm("mov %0, ebp":"=r"(buffer));
  
    template<typename RT>
    struct _REGISTER_FUNCTION_HOOKED_x32
    {
        RT eax=0;
        RT ebx=0;
        RT ecx=0;
        RT edx=0;
        RT esi=0;
        RT edi=0;
        RT esp=0;
    };

    typedef _REGISTER_FUNCTION_HOOKED_x32 <DWORD> x32_RegisterFunctionHooked;
    typedef _REGISTER_FUNCTION_HOOKED_x32 <DWORD*> P_x32_RegisterFunctionHooked;

void inline x32_GetRegisterFunctionHooked(DWORD CurrentEBP,x32_RegisterFunctionHooked & RFH)
{
    // CurrentEBP = ebp =  ebp from callback function hooked (fixed align between tunnel & callback)

    RFH.edi =  (DWORD)(*(DWORD*)(CurrentEBP+8));
    RFH.esi =  (DWORD)(*(DWORD*)(CurrentEBP+12));
    RFH.edx =  (DWORD)(*(DWORD*)(CurrentEBP+16));
    RFH.ecx =  (DWORD)(*(DWORD*)(CurrentEBP+20));
    RFH.ebx =  (DWORD)(*(DWORD*)(CurrentEBP+24));
    RFH.eax =  (DWORD)(*(DWORD*)(CurrentEBP+28));
    RFH.esp  = (DWORD)(*(DWORD*)(CurrentEBP+32));

}

void inline P_x32_GetRegisterFunctionHooked(DWORD CurrentEBP,P_x32_RegisterFunctionHooked & RFH)
{
        RFH.edi =  (DWORD*)(CurrentEBP+8);
        RFH.esi =  (DWORD*)(CurrentEBP+12);
        RFH.edx =  (DWORD*)(CurrentEBP+16);
        RFH.ecx =  (DWORD*)(CurrentEBP+20);
        RFH.ebx =  (DWORD*)(CurrentEBP+24);
        RFH.eax =  (DWORD*)(CurrentEBP+28);
        RFH.esp  = (DWORD*)(CurrentEBP+32);
}

DUMMY_FUNCTION void __cdecl TopBodyTunnel_x32()
{
   asm("push    ebp");
   asm("push    eax");
   asm("push    ebx");
   asm("push    ecx");
   asm("push    edx");
   asm("push    esi");
   asm("push    edi");
   asm("mov     ebp,esp");
   asm("ret");
}

DUMMY_FUNCTION void __cdecl BottomBodyTunnel_x32()
{
    asm("mov     esp,ebp");
    asm("pop     edi");
    asm("pop     esi");
    asm("pop     edx");
    asm("pop     ecx");
    asm("pop     ebx");
    asm("pop     eax");
    asm("pop     ebp");
    asm("ret");
}

template<typename T>
void asm_jump(BYTE * dest,T operande)
{
    *dest=0xE9;
    *(T*)(dest+1) = (T)operande;
    TunnelOffsetInstruction += 1+sizeof(T);
}

template<typename T>
void asm_push(BYTE * dest,T operande)
{
    *dest=0x68;
    *(T*)(dest+1) = (T)operande;
    TunnelOffsetInstruction += 1+sizeof(T);
}

#endif

void PaddingMemory(BYTE*src,size_t size)
{
  for(int x=0;x<=(size-1);x++)
  {
      *(src+x)=0x90;
  }
};

void ByteCpy(BYTE * dest,BYTE * src,int size)
{
      for(int x=0;x<size;x++)
      {
        *(dest+x)= *(src+x);
      }
      TunnelOffsetInstruction+=size;
} 

size_t funccpy( BYTE * dest, BYTE*src,int stop=0xC3) 
{
   size_t x=0;
   do
   {
       *(dest+x)=*(src+x);
       x++;
   } while (*(src+x)!=stop);
   TunnelOffsetInstruction+=x;
   return x;
};

void asm_ret(BYTE *dest)
{
    *dest=0xC3;
    TunnelOffsetInstruction=0;
}

typedef struct StructHook
{

  void Detach();
  void Attach(); 
  void LockTunnelRegion();
  void UnLockTunnelRegion();
  void Destroy();
  bool IsNotNull();

  bool Destroyed=false;
  BYTE *src, *Tunnel,*BaseTunnel;
  DWORD NByteSteal,TunnelSize;

  StructHook(BYTE* _src=nullptr,BYTE*_Tunnel=nullptr,DWORD _NByteSteal=0,DWORD _TunnelSize=0):src(_src),Tunnel(_Tunnel), NByteSteal(_NByteSteal),TunnelSize(_TunnelSize) 
  {
    #if SUPPORT_HOOK==64
       
        Base_Tunnel_Size = 94;
        int Offset=74;

    #elif SUPPORT_HOOK == 32
        
        Base_Tunnel_Size = 34;
        int Offset=28;
    
    #endif
    
    if (_Tunnel!=nullptr)
        this->BaseTunnel=(_Tunnel-Offset);
    else if (_Tunnel==nullptr)
        this->BaseTunnel=nullptr;

       };
  
  
};

bool StructHook::IsNotNull()
{
    return (this->src!=nullptr&&this->Tunnel!=nullptr&&this->NByteSteal!=0&&this->TunnelSize!=0 && this->Destroyed==false) ? true:false;
}

void StructHook::LockTunnelRegion()
{
    if(!this->IsNotNull())
       return;

    ModifyPageAccess((void*)this->BaseTunnel,PAGE_NOACCESS);
 
}
void StructHook::UnLockTunnelRegion()
{
    if(!this->IsNotNull())
       return;

    ModifyPageAccess((void*)this->BaseTunnel,PAGE_EXECUTE_READ);
    
}
void StructHook::Detach()
{
    if(!this->IsNotNull() || *this->src!=ValidOpCodeSrc)
       return;
     
    DWORD OldProtect=ModifyPageAccess((void*)this->src,PAGE_EXECUTE_READWRITE);
    
    PaddingMemory((BYTE*)(this->src),this->NByteSteal);
    
    ByteCpy(this->src,this->Tunnel,this->NByteSteal);

    ModifyPageAccess((void*)this->src,OldProtect);
}

void StructHook::Attach()
{
    if(!this->IsNotNull() || *this->src==ValidOpCodeSrc)
       return;
   
    DWORD OldProtect=ModifyPageAccess((void*)this->src,PAGE_EXECUTE_READWRITE);
   
    PaddingMemory((BYTE*)(this->src),this->NByteSteal);

    #if SUPPORT_HOOK==64

    push_register(Rx64.push.RDI,(BYTE*)this->src);  // size : 1 
    mov_in_register(Rx64.mov.RDI,(BYTE*)(this->src+1),(Q_WORD)(this->BaseTunnel)); // size : 10
    jmp_from_register(Rx64.jmp.RDI,(BYTE*)(this->src+1+10)); // size : 2

    #elif SUPPORT_HOOK==32

      asm_jump(this->src,(DWORD)(((DWORD)this->BaseTunnel-(DWORD)this->src)-5));

    #endif
    ModifyPageAccess((void*)this->src,OldProtect);
}

void StructHook::Destroy()
{
    if(!this->IsNotNull())
       return;

    this->Detach();
    this->Destroyed=true;
    ModifyPageAccess((void*)this->BaseTunnel,PAGE_EXECUTE_READWRITE);
    NtFreeVirtualMemory(NtCurrentProcess(),(PVOID*)&this->BaseTunnel,(PSIZE_T)&this->TunnelSize,MEM_RELEASE|MEM_DECOMMIT);
    ZeroMemory(this->BaseTunnel,this->TunnelSize);
}
