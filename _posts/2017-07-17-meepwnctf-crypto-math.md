---
layout: post
title: "[MeePwnCTF][Crypto] MATH"
---
`| \ / | / -\ T | - |`

It's quite a ez chall but don't know why some guys stuck with it :/

> I hack your brain!
>
> [hack.py](https://gist.github.com/quandqn/687f28c123f9a1594db254f7891fd774)

```python
from Crypto.Util.number import *
from hashlib import md5

flag = "XXX"
assert len(flag) == 14
pad = bytes_to_long(md5(flag).digest())

hack = 0

for char in flag:
	hack+= pad
	hack*= ord(char)
	
print hack
#hack = 64364485357060434848865708402537097493512746702748009007197338675
#flag_to_submit = "MeePwnCTF{" + flag + "}"
```

Following the code we know that length of flag = 14 and `hack` has format like :

`hack = ...((ord(flag[0]).pad+pad).ord(flag[1]))+pad).ord(flag[2]))....)+pad).ord(flag[13])`

flag is ASCII strings and printable so :  $32 <= ord(flag[i]) <= 127$

### Solution: 

1. We will find last char of flag ( using mod ). Then `hack/ord(flag[13]) = pad.[((ord(flag[0])+1).ord(flag[1]+1)...)]`
2. Length of `pad` will be `>=32` but after run this script i guess length of `pad` is 39. 
3. Factor the `hack/ord(flag[13])` then finding all combinations of it to find `pad`.
4. After finding `pad`, I use recursion algorithm to find all possible flag.

### Code : 

I find last char first (just using mod) and `flag[13]={"i","k","K","?"}`

(some chars were removed because have no case have it at last (eg : `#`))

I wrote a quick script and don't optimize it :P

```python
from itertools import combinations
hack=64364485357060434848865708402537097493512746702748009007197338675


def re(x,d):
	if x<=32:
		return 0
	if x==0:
		return 1
	temp=d
	for i in xrange(48,128):
		if x%i==0:
			temp=chr(i)+d
			if len(temp)==13 and x==i:
				print temp
			re(x/i-1,temp)

def check(x):
	if len(str(x))==39:
		return True
	else:
		return False
    
def prd(a):
	s=1
	for i in a:
		s=s*i
	return s

def gen(f,a):
	for i in xrange(len(a)-1):
		l=list(combinations(a,i))
		for j in l:
			pr=prd(j)
			if check(pr):
				print "-"*20
				div=f/pr-1
				re(div,"")

				

factor=[107,3,3,5,5,7,487,607, 28429 , 29287, 420577267963, 3680317203978923,1002528655290265069]

#change this arr for each last char
ft=[107,5,5,487,607, 28429 , 29287, 420577267963, 3680317203978923,1002528655290265069]

#change hack/ord(flag[13]) for each last char
gen(hack/ord('?'),ft)
'''
d0y0ul1keM@TH?
'''
```



### Result : 

![flag](http://i.imgur.com/WbW8uu0.png)

**FLAG :** `MeePwnCTF{d0y0ul1keM@TH?}`

