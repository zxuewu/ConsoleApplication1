//
// FILE: asmtest.asm
// Description: ���Դ�ļ�����ǰ�ļ�����x64ƽ̨�ϱ��룬����������x86ƽ̨����ͨ������Դ�ļ�������ʵ�֡�
// 
 
.CODE // �ļ���ʼ
 
// ����ԭ�ͣ� void Int_3()
// ����������
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