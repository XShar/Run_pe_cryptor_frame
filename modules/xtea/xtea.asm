format MS COFF

;http://www.manhunter.ru/assembler/1330_algoritmi_shifrovaniya_tea_i_xtea_na_assemblere.html

include 'win32ax.inc'

public  XTEA_encrypt as '_XTEA_encrypt@16'
public  XTEA_decrypt as '_XTEA_decrypt@16'

TEA_MAGIC1 = 09E3779B9h ; sqr(5)-1 * 2^31
TEA_MAGIC2 = 0C6EF3720h ; TEA_MAGIC1 shl 5
TEA_ROUNDS = 32

    ;-------------------------------------------------------
    ; XTEA Encryption
    ;-------------------------------------------------------
    ; Параметры:
    ;     lpData - указатель на шифруемые данные
    ;     ddSize - размер данных, выравненный до кратности 8
    ;     lpKey - указатель на строку ключа
    ;     dkSize - длина ключа
    ;-------------------------------------------------------
    proc XTEA_encrypt lpData:DWORD, ddSize:DWORD, lpKey:DWORD, dkSize:DWORD
            locals
                    XTEA_key rb 16
            endl
     
            pusha
     
            ; Скопировать ключ шифрования
            xor     eax,eax
            mov     ecx,4
            lea     edi,[XTEA_key]
            cld
            rep     stosd
            mov     ecx,[dkSize]
            cmp     ecx,16
            jbe     @f
            mov     ecx,16
    @@:
            mov     esi,[lpKey]
            lea     edi,[XTEA_key]
            rep     movsb
     
            ; Цикл шифрования
            mov     ebx,[lpData]
            xor     ecx,ecx
    .loc_encrypt:
            cmp     ecx,[ddSize]
            jae     .loc_ret
     
            push    ecx
            push    ebx
     
            mov     esi,[ebx+ecx+0]
            mov     edi,[ebx+ecx+4]
     
            xor     edx,edx
            mov     ecx,TEA_ROUNDS
    @@:
            push    ecx
            mov     eax,edi
            mov     ebx,edi
            shl     eax,4
            shr     ebx,5
            mov     ecx,edx
            xor     eax,ebx
            and     ecx,3
            add     eax,edi
            lea     ebx,[XTEA_key]
            mov     ebx,[ebx+4*ecx]
            add     ebx,edx
            xor     eax,ebx
            add     edx,TEA_MAGIC1
            add     esi,eax
            mov     ecx,edx
            mov     eax,esi
            mov     ebx,esi
            shl     eax,4
            shr     ebx,5
            shr     ecx,11
            xor     eax,ebx
            and     ecx,3
            mov     ebx,edx
            add     eax,esi
            push    edx
            lea     edx,[XTEA_key]
            add     ebx,[edx+4*ecx]
            pop     edx
            xor     eax,ebx
            add     edi,eax
            pop     ecx
            dec     ecx
            jnz     @b
     
            pop     ebx
            pop     ecx
     
            mov     [ebx+ecx+0],esi
            mov     [ebx+ecx+4],edi
     
            add     ecx,8
            jmp     .loc_encrypt
    .loc_ret:
            popa
            ret
    endp
        
        

    ;-------------------------------------------------------
    ; XTEA Decryption
    ;-------------------------------------------------------
    ; Параметры:
    ;     lpData - указатель на расшифровываемые данные
    ;     ddSize - размер данных, выравненный до кратности 8
    ;     lpKey - указатель на строку ключа
    ;     dkSize - длина ключа
    ;-------------------------------------------------------
    proc XTEA_decrypt lpData:DWORD, ddSize:DWORD, lpKey:DWORD, dkSize:DWORD
            locals
                    XTEA_key rb 16
            endl
     
            pusha
     
            ; Скопировать ключ шифрования
            xor     eax,eax
            mov     ecx,4
            lea     edi,[XTEA_key]
            cld
            rep     stosd
            mov     ecx,[dkSize]
            cmp     ecx,16
            jbe     @f
            mov     ecx,16
    @@:
            mov     esi,[lpKey]
            lea     edi,[XTEA_key]
            rep     movsb
     
            ; Цикл расшифровки
            mov     ebx,[lpData]
            xor     ecx,ecx
    .loc_decrypt:
            cmp     ecx,[ddSize]
            jae     .loc_ret
     
            push    ecx
            push    ebx
     
            mov     esi,[ebx+ecx+0]
            mov     edi,[ebx+ecx+4]
     
            mov     edx,TEA_MAGIC2
            mov     ecx,TEA_ROUNDS
    @@:
            push    ecx
            mov     eax,esi
            mov     ebx,esi
            shl     eax,4
            shr     ebx,5
            mov     ecx,edx
            xor     eax,ebx
            shr     ecx,11
            add     eax,esi
            mov     ebx,edx
            and     ecx,3
            sub     edx,TEA_MAGIC1
            push    edx
            lea     edx,[XTEA_key]
            add     ebx,[edx+4*ecx]
            pop     edx
            xor     ebx,eax
            sub     edi,ebx
            mov     eax,edi
            mov     ebx,edi
            shl     eax,4
            shr     ebx,5
            mov     ecx,edx
            xor     eax,ebx
            and     ecx,3
            mov     ebx,edx
            add     eax,edi
            push    edx
            lea     edx,[XTEA_key]
            add     ebx,[edx+4*ecx]
            pop     edx
            xor     ebx,eax
            sub     esi,ebx
            pop     ecx
            dec     ecx
            jnz     @b
     
            pop     ebx
            pop     ecx
     
            mov     [ebx+ecx+0],esi
            mov     [ebx+ecx+4],edi
     
            add     ecx,8
            jmp     .loc_decrypt
    .loc_ret:
            popa
            ret
    endp