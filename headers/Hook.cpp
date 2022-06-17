#include "./Hook.h"

#if SUPPORT_HOOK == 64

StructHook x64_Hook(Q_WORD h_src,Q_WORD h_dest,int NByteSteal)
{
      if(NByteSteal<13)
      {
            return StructHook();
      }

      Base_Tunnel_Size +=NByteSteal;
      TunnelOffsetInstruction=0;
      DWORD RegionSize=Base_Tunnel_Size;  
      BYTE * Tunnel=nullptr;

      NtAllocateVirtualMemory(NtCurrentProcess(),(PVOID*)&Tunnel,0,(PSIZE_T)&RegionSize,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
      
      DWORD SrcOldProtect = ModifyPageAccess((void*)h_src,PAGE_EXECUTE_READWRITE);
     
      // save all registers
      funccpy(Tunnel,(BYTE*)((Q_WORD)TopBodyTunnel_x64)); //
      
      // ret address of dest
      mov_in_register(Rx64.mov.RDI,Tunnel+TunnelOffsetInstruction,(Q_WORD)(Tunnel+TunnelOffsetInstruction+23));
      
      // push ret address of dest
      push_register(Rx64.push.RDI,Tunnel+TunnelOffsetInstruction); 
     
      // movq rdi,dest 
      mov_in_register(Rx64.mov.RDI,Tunnel+TunnelOffsetInstruction,h_dest); 

      // jmp rdi 
      jmp_from_register(Rx64.jmp.RDI, Tunnel+TunnelOffsetInstruction);
      
      // restore default registers value
      funccpy((Tunnel+TunnelOffsetInstruction),(BYTE*)(BottomBodyTunnel_x64)); 

      ByteCpy((Tunnel+TunnelOffsetInstruction),(BYTE*)(h_src),NByteSteal);

      // Mov ret addres qword (word*4) = (16*4) = 64B
      push_register(Rx64.push.RDI, Tunnel+TunnelOffsetInstruction);
      push_register(Rx64.push.RDI, Tunnel+TunnelOffsetInstruction);
 
      mov_in_register(Rx64.mov.RDI,Tunnel+TunnelOffsetInstruction,h_src+NByteSteal);
       
      // movq [rsp+8],RDI
      mov_in_stack_from_register(Tunnel+TunnelOffsetInstruction,Rx64.mov.RDI,8);
      
       // pop RDI
      pop_in_register(Tunnel+TunnelOffsetInstruction,Rx64.pop.RDI);
    
      // ret
      asm_ret(Tunnel+TunnelOffsetInstruction);    
      
      ModifyPageAccess((void*)Tunnel,PAGE_EXECUTE_READ);
 
      // Create padding to write jmp ()
      PaddingMemory((BYTE*)((h_src)),NByteSteal);   

      // push RDI (save RDI value)
      push_register(Rx64.push.RDI,(BYTE*)h_src);
     
      // movq rdi,Tunnel
      mov_in_register(Rx64.mov.RDI,(BYTE*)(h_src+TunnelOffsetInstruction),(Q_WORD)(Tunnel)); 
      
      // jmp rdi
      jmp_from_register(Rx64.jmp.RDI,(BYTE*)(h_src+TunnelOffsetInstruction));

      ModifyPageAccess((void*)h_src,SrcOldProtect);
      
      return StructHook((BYTE*)(h_src),(BYTE*)(Tunnel+74),NByteSteal,Base_Tunnel_Size);
}

#elif SUPPORT_HOOK ==32
StructHook x32_Hook(DWORD h_src,DWORD h_dest,int NByteSteal)
{
   if(NByteSteal<5)
      {
            return StructHook();
      }
     
      Base_Tunnel_Size +=NByteSteal;
      TunnelOffsetInstruction=0;
      DWORD RegionSize=Base_Tunnel_Size; 
      BYTE * Tunnel=NULL;

      NtAllocateVirtualMemory(NtCurrentProcess(),(PVOID*)&Tunnel,0,(PSIZE_T)&RegionSize,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
      
      DWORD SrcOldProtect = ModifyPageAccess((void*)h_src,PAGE_EXECUTE_READWRITE);
      
      funccpy(Tunnel,(BYTE*)(TopBodyTunnel_x32+3)); 
      
      asm_push(Tunnel+TunnelOffsetInstruction,(DWORD)(Tunnel+19));
     
      asm_jump((Tunnel+TunnelOffsetInstruction),(DWORD)(((h_dest-(DWORD)Tunnel)-5)-14));
      
      funccpy((Tunnel+TunnelOffsetInstruction),(BYTE*)(BottomBodyTunnel_x32+3)); 
      
      ByteCpy((Tunnel+TunnelOffsetInstruction),(BYTE*)(h_src),NByteSteal); 
      
      asm_push((Tunnel+TunnelOffsetInstruction),(DWORD)(h_src+NByteSteal));
      
      asm_ret((Tunnel+TunnelOffsetInstruction));
      
      ModifyPageAccess((void*)Tunnel,PAGE_EXECUTE_READ);
      
      PaddingMemory((BYTE*)((h_src)),NByteSteal);
      
      asm_jump((BYTE*)(h_src),(DWORD)(((DWORD)Tunnel-(h_src))-5));
      
      ModifyPageAccess((void*)h_src,SrcOldProtect);

      return StructHook((BYTE*)(h_src),(BYTE*)(Tunnel+28),NByteSteal,Base_Tunnel_Size);

} 

#endif
