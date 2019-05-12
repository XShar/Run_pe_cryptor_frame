format MS COFF

;http://www.manhunter.ru/assembler/1101_raschet_murmurhash_na_assemblere.html

include 'win32ax.inc'

public  Murmur3 as '_Murmur3@12'

    ;-----------------------------------------------------------------------
    ; Функция вычисления хеша Murmur3 (32-bit)
    ; Автор: ManHunter / PCL
    ; http://www.manhunter.ru
    ;-----------------------------------------------------------------------
    ; Параметры:
    ;       lpData - указатель на строку
    ;       dSize  - длина строки
    ;       dSeed  - соль
    ; На выходе:
    ;       EAX = полученный хеш
    ;-----------------------------------------------------------------------
    proc    Murmur3 lpData:DWORD, dSize:DWORD, dSeed:DWORD
            push    ebx ecx edx esi edi
     
            MAGIC1 = 0xCC9E2D51
            MAGIC2 = 0x1B873593
     
            mov     ebx,[dSize]
            mov     ecx,[dSeed]
     
            mov     esi,[lpData]
     
    .loc_loop:
            cmp     ebx,4
            jb      .loop_done
     
            mov     eax,dword [esi]
            imul    eax,MAGIC1
     
            mov     edx,eax
            shr     edx,17
            shl     eax,15
            or      eax,edx
     
            imul    eax,MAGIC2
     
            xor     ecx,eax
     
            mov     edx,ecx
            shr     edx,19
            shl     ecx,13
            or      ecx,edx
            imul    ecx,5
            add     ecx,0xE6546B64
     
            add     esi,4
            sub     ebx,4
            jmp     .loc_loop
     
    .loop_done:
            mov     edx,0
     
            cmp     ebx,3
            je      .loc_tail_3
            cmp     ebx,2
            je      .loc_tail_2
            cmp     ebx,1
            je      .loc_tail_1
            jmp     .loc_finish
     
    .loc_tail_3:
            movzx   eax,byte[esi+2]
            shl     eax,16
            xor     edx,eax
    .loc_tail_2:
            movzx   eax,byte[esi+1]
            shl     eax,8
            xor     edx,eax
    .loc_tail_1:
            movzx   eax,byte[esi]
            xor     edx,eax
     
            imul    edx,MAGIC1
     
            mov     eax,edx
            shr     eax,17
            shl     edx,15
            or      edx,eax
     
            imul    edx,MAGIC2
     
            xor     ecx,edx
     
    .loc_finish:
            mov     eax,[dSize]
            xor     ecx,eax
     
            mov     eax,ecx
            shr     eax,16
            xor     ecx,eax
            imul    ecx,0x85EBCA6B
            mov     eax,ecx
            shr     eax,13
            xor     ecx,eax
            imul    ecx,0xC2B2AE35
            mov     eax,ecx
            shr     eax,16
            xor     eax,ecx
     
            pop     edi esi edx ecx ebx
            ret
    endp

