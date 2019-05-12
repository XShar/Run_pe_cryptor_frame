format MS COFF

include 'win32ax.inc'

public  do_Random_EAX as '_do_Random_EAX@8'
public  do_fake_instr as '_do_fake_instr'


section '.text' code readable executable

regw1   db 03h, 0C0h ;add reg1, reg2
regw2   db 2Bh, 0C0h ;sub reg1, reg2
regw3   db 33h, 0C0h ;xor reg1, reg2
regw4   db 8Bh, 0C0h ;mov reg1, reg2
regw5   db 87h, 0C0h ;xchg reg1, reg2
regw6   db 0Bh, 0C0h ;or reg1, reg2
regw7   db 23h, 0C0h ;and reg1, reg2
regw8   db 0F7h, 0D0h ;not reg1
regw9   db 0D1h, 0E0h ;shl reg1, 1
regw10  db 0D1h, 0E8h ;shr reg1, 1
regw11  db 081h, 0E8h ;sub reg1, rnd
regw12  db 081h, 0C0h ;add reg1, rnd
regw13  db 081h, 0F0h ;xor reg1, rnd
regw14  db 081h, 0C8h ;or reg1, rnd
regw15  db 081h, 0E0h ;and reg1, rnd
regw16  db 0F7h, 0D8h ;neg reg1
regw17  db 0D1h, 0C0h ;rol reg1, 1
regw18  db 0D1h, 0C8h ;ror reg1, 1
regw19  db 08Dh, 00h  ;lea reg1, [reg2]
regd1   db 0B8h; mov reg1, rnd

extrn _debug_print ;Для дебага, обычный std_out в си, меняет регистры, не забывайте сохранять и восстанавливать их.)))
;Пример использования ccall _debug_print,38 (Напечатает "Debug 38" в консоле)

;---------------------------------------------
; Интерфейсная функция, для получения случайного числа в нужном интервале
; stdcall do_Random_EAX,min,max
; на выходе EAX - случайное число    
;---------------------------------------------
proc    do_Random_EAX rmin:dword,rmax:dword

        ;Сохранение регистров (На всякий случай)
        push ebx
        push ecx
                
        ;Инициализация генератора
        stdcall  WRandomInit

        mov     ebx,[rmin]
        mov     ecx,[rmax]

        mov   [value_min],ebx
        mov   [value_max],ecx

        ;Получить случайное число от 0 до19
        stdcall WIRandom,[value_min],[value_max]

        ;Восстановление регистров
        pop ecx
        pop ebx

        ret
endp

;---------------------------------------------
; Инициализация генератора случайных чисел
; stdcall WRandomInit 
;---------------------------------------------
proc    WRandomInit
        push    eax edx
        rdtsc
        xor     eax,edx
        mov     [random_seed],eax
        pop     edx eax
        ret
endp

;---------------------------------------------
; Park Miller random number algorithm
; Получить случайное число 0 ... 99999
; stdcall Random_EAX
; на выходе EAX - случайное число 
;---------------------------------------------
Random_EAX:
        push    edx ecx
        mov     eax,[random_seed]
        xor     edx,edx
        mov     ecx,127773
        div     ecx
        mov     ecx,eax
        mov     eax,16807
        mul     edx
        mov     edx,ecx
        mov     ecx,eax
        mov     eax,2836
        mul     edx
        sub     ecx,eax
        xor     edx,edx
        mov     eax,ecx
        mov     [random_seed],ecx
        mov     ecx,100000
        div     ecx
        mov     eax,edx
        pop     ecx edx
        ret

;---------------------------------------------
; Получить случайное число в нужном интервале
; Требуется процедура WRandom
; stdcall WIRandom,min,max
; на выходе EAX - случайное число   
;---------------------------------------------
proc    WIRandom rmin:dword,rmax:dword
        push    edx ecx
        mov     ecx,[rmax]
        sub     ecx,[rmin]
        inc     ecx
        stdcall Random_EAX
        xor     edx,edx
        div     ecx
        mov     eax,edx
        add     eax,[rmin]
        pop     ecx edx
        ret
endp

;________________________________________________________
;Генерация фейковых инструкций
;________________________________________________________

proc do_fake_instr

        push esi
        push edi
        push edx
        push ebp
        push ecx

        ; Инициализация генератора
        stdcall  WRandomInit

        ;Получить случайное число от 0 до19
        stdcall WIRandom,0,19

        .if eax=0
                call make_rorreg
        .elseif eax=1
                call make_rolreg
        .elseif eax=2
                call make_addreg
        .elseif eax=3
                call make_subreg 
        .elseif eax=4
                call make_xorreg 
        .elseif eax=5
                call make_movreg
        .elseif eax=6
                call make_xchgreg 
        .elseif eax=7
                call make_orreg 
        .elseif eax=8
                call make_andreg 
        .elseif eax=9
                call make_notreg 
        .elseif eax=10
                call make_shlreg 
        .elseif eax=11
                call make_shrreg 
        .elseif eax=12
                call make_addrnd 
        .elseif eax=14
                call make_xorrnd
        .elseif eax=15
                call make_orrnd 
        .elseif eax=16
                call make_andrnd
        .elseif eax=17
                call make_negreg
        .elseif eax=18
                call make_movrnd
        .elseif eax=19
                call make_leareg
        .endif

        pop ecx
        pop ebp
        pop edx
        pop edi
        pop ecx
        ret
endp

;---------------------------------------------
;Функции для генерации инструкций
;---------------------------------------------
proc make_addreg
        mov esi, regw1
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        Ret
endp
proc make_subreg
        mov esi,regw2
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        Ret
endp
proc make_xorreg
        mov esi,regw3
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        Ret
endp
proc make_movreg
        mov esi,regw4
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        Ret
endp
proc make_xchgreg
        mov esi,regw5
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        Ret
endp
proc make_orreg
        mov esi,regw6
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        Ret
endp
proc make_andreg
        mov esi,regw7
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        Ret
endp
proc make_notreg
        mov esi,regw8
        lodsw
        add ah, cl
        stosw
        Ret
endp
proc make_shlreg
        mov esi,regw9
        lodsw
        add ah, dl
        stosw
        Ret
endp
proc make_shrreg
        mov esi,regw10
        lodsw
        add ah, cl
        stosw
        Ret
endp
proc make_subrnd
        mov esi,regw11
        lodsw
        add ah, dl
        stosw
        mov eax, -1
        stosd
        Ret
endp
proc make_addrnd
        or edx, edx
        mov al, 05h
        stosb
        mov eax, -1
        stosd
        Ret
endp
proc make_xorrnd
        or edx, edx
        mov al, 35h
        stosb
        mov eax, -1
        stosd
        Ret
endp
proc make_orrnd
        mov esi,regw14
        lodsw
        add ah, cl
        stosw
        mov eax, -1
        stosd
        Ret
endp
proc make_andrnd
        or edx, edx
        mov al, 25h
        stosb
        mov eax, -1
        stosd
        Ret
endp
proc make_negreg
        mov esi,regw16
        lodsw
        add ah, cl
        stosw
        Ret
endp
proc make_rolreg
        mov esi,regw17
        lodsw
        add ah, cl
        stosw
        Ret
endp
proc make_rorreg
        mov esi,regw18
        lodsw
        add ah, cl
        stosw
        Ret
endp
proc make_leareg
        mov esi, regw19
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        Ret
endp
proc make_movrnd
        mov esi, regd1
        lodsb
        add al, cl
        stosb
        mov eax, -1
        stosd
        Ret
endp

section '.data' data readable writeable
random_seed     dd 0
value_min       dd 0
value_max       dd 0