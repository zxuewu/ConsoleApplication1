//
// FILE: asmtest.asm
// Description: 汇编源文件。当前文件仅在x64平台上编译，并不包含于x86平台，可通过设置源文件的属性实现。
// 
 
.CODE // 文件开始
 
// 函数原型： void Int_3()
// 函数描述：
Int_3 PROC
		pushad
		xor eax, eax
		mov ebx, fileSize
		mov ecx, ebx
		push ecx
		shr ecx, 1
		mov esi, lpBase
		clc
		cal_checksum :
		adc ax, word ptr[esi]
			inc esi
			inc esi
			loop cal_checksum
			adc ax, 0

			pop ecx
			test ecx, 1
			jz __end
			xor edi, edi
			movzx di, byte ptr[esi]
			clc
			add ax, di
			__end :
		add eax, ebx;
		mov checksum2, eax
			popad
Int_3 ENDP
 
END