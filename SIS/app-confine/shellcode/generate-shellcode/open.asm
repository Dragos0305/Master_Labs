BITS 32

    ; Open file ../../jail/a.txt
    jmp short string_open_a       ; Jump to the string for file a.
open_file_a:
    pop ebx                       ; Pop the address of the filename into ebx.
    xor ecx, ecx                  ; O_RDONLY flag is typically 0.
    mov eax, 5                    ; System call number for 'open'.
    int 0x80                      ; Make the system call.

    ; Open file ../../b.txt
    jmp short string_open_b       ; Jump to the string for file b.
open_file_b:
    pop ebx                       ; Pop the address of the filename into ebx.
    xor ecx, ecx                  ; O_RDONLY flag.
    mov eax, 5                    ; System call number for 'open'.
    int 0x80                      ; Make the system call.

    ; Exit the program
   ; xor ebx, ebx                  ; Exit status 0.
   ; mov eax, 1                    ; System call number for 'exit'.
   ; int 0x80                      ; Make the system call.

string_open_a:
    call open_file_a
    db "../../jail/a.txt", 0      ; Filename for file a.

string_open_b:
    call open_file_b
    db "../../b.txt", 0           ; Filename for file b.
