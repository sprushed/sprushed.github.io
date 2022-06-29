---
title:  "ACTF 2022 Crypto Writeups"
date:   2022-06-29 16:09:57 +0300
layout: single
categories: post
tags: [posts]
---

<h2>ACTF 2022</h2>

ACTF 2022 left overall good impressions with nice task ideas. So we decided to publish our writeups for few categories. Here you can see writeups for crypto challenges.

*Author: [Sarkoxed](https://github.com/Sarkoxed)*
<br />
*Attachments for all challenges: [Sarkoxed Github repo](https://github.com/Sarkoxed/ctf-writeups/tree/master/actf2022)*

<h3>SECURE CONNECTION (487 points)</h3>
<h4>Task Description:</h4><p>We leak some packets log in author’s PC and get part of the secureconn software, can you get the flag? (software is buggy, don`t mind it and just get your flag)</p>
<h4>Attachments:</h4><p>The big client.py and core.py files are in directory. Also there's a log file master.txt, that contains:</p>
```
>	01 03 6c 69 fa 95 c5 e6
<	01 03 6c 69 fa 95 c5 e6
>	08 30 53 47 56 73 62 47 38 67 64 47 68 6c 63 6d
	55 73 49 47 78 76 62 6d 63 67 64 47 6c 74 5a 53
	42 75 62 79 42 7a 5a 57 55 73 49 48 70 79 59 58
	68 34 9e ab 52
<	08 44
	65 57 56 68 61 43 77 67 53 53 42 68 62 53 42 78
	64 57 6c 30 5a 53 42 69 64 58 4e 35 49 47 31 68
	61 32 6c 75 5a 79 42 42 51 31 52 47 49 47 4e 79
	65 58 42 30 62 79 42 6a 61 47 46 73 62 47 56 75
	5a 32 56 7a
	ab 08 96
>	08 40 64 32 56 73 62 43 77 67 53 53 42 6a 59 57
	34 67 62 32 5a 6d 5a 58 49 67 65 57 39 31 49 47
	45 67 62 6d 39 30 49 47 4a 68 5a 43 42 7a 61 57
	64 75 61 57 34 67 59 32 68 68 62 47 78 6c 62 6d
	64 6c d1 e8 ac
<	08 0c
	63 32 68 76 64 79 42 74 5a 51 3d 3d
	06 eb 3b
>	08 34 62 47 56 30 4a 33 4d 67 5a 6d 6c 79 63 33
	51 67 5a 47 6c 32 5a 53 42 70 62 6e 52 76 49 48
	4e 6c 59 33 56 79 5a 53 42 6a 62 32 35 75 5a 57
	4e 30 61 57 39 75 2a 85 95
>	81 03 d9 b2 df e9 3b f9
<	81 03 d9 b2 df e9 3b f9
>	82 10 ec 36 e5 b0 69 55 d9 95 56 7e e5 de 45 07
	37 f8 7d d5 57
<	83 10 68 b3 de d5 b8 40 14 dc f3 fb 75 02 d9 39
	0e 34 a6 bf 63
>	84 10 9f 51 36 ca cd 9f 2a 53 87 39 4b 7d 0c 1c
	XX XX 58 46 05
<	85 10 XX d6 e4 XX XX 5c XX b7 ba 90 6e 57 05 5a
	8e c8 2d db b8
>	86 10 4b d2 09 24 f0 c3 cd 30 ba 64 a0 f1 d9 64
	69 1e fa a2 d5
<	87 10 dd 76 51 4f 57 36 81 3a a8 c2 17 8e XX f8
	2d 5b 6f 68 ec
>	88 44 ee 49 1a 84 62 41 16 fb 68 5e 5d 47 14 94
aa 6d 3e ac 7c 53 70 7c 46 50 50 90 7e a2 01 12
	04 06 90 02 5e 92 a6 1d d8 29 1b 50 d0 c1 69 13
	b9 cd 0f f5 29 0e da d9 c2 3d 69 38 46 49 76 5b
	84 7f 15 f2 21 ce 3e 4f b4
<	c8 ff
...
```
<h4>Solution</h4>
<p>First of all, I've written a parser for this dump file</p><p>It was not hard, since all the instructions for decomposing were in core.py file</p><p>Here's the result:</p>
```c
1 from, hello, no_enc,  len: 3, data: b'li\xfa', crc: 95c5e6

2 to,   hello, no_enc,  len: 3, data: b'li\xfa', crc: 95c5e6

3 from, data, no_enc,  len: 48, data: <strong>b'Hello there, long time no see, zraxx'</strong>, crc: 9eab52

4 to,   data, no_enc,  len: 68, data: <strong>b'yeah, I am quite busy making ACTF crypto challenges'</strong>, crc: ab0896

5 from, data, no_enc,  len: 64, data: <strong>b'well, I can offer you a not bad signin challenge'</strong>, crc: d1e8ac

6 to,   data, no_enc,  len: 12, data: <strong>b'show me'</strong>, crc: 06eb3b

7 from, data, no_enc,  len: 52, data: <strong>b"let's first dive into secure connection"</strong>, crc: 2a8595

8 from, hello, enc,  len: 3, data: d9b2df, crc: e93bf9

9 to,   hello, enc,  len: 3, data: d9b2df, crc: e93bf9

10 from, sc_req, enc,  len: 16, data: ec36e5b06955d995567ee5de450737f8, crc: 7dd557

11 to,   sc_rsp, enc,  len: 16, data: 68b3ded5b84014dcf3fb7502d9390e34, crc: a6bf63

12 from, m_confirm, enc,  len: 16, data: 9f5136cacd9f2a5387394b7d0c1cXXXX, crc: 584605

13 to,   s_confirm, enc,  len: 16, data: XXd6e4XXXX5cXXb7ba906e57055a8ec8, crc: 2ddbb8

14 from, m_random, enc,  len: 16, data: 4bd20924f0c3cd30ba64a0f1d964691e, crc: faa2d5

15 to,   s_random, enc,  len: 16, data: dd76514f5736813aa8c2178eXXf82d5b, crc: 6f68ec

16 from, data, enc,  len: 68, data: ee491a84624116fb685e5d471494aa6d3eac7c53707c465050907ea20112040690025e92a61dd8291b50d0c16913b9cd0ff5290edad9c23d69384649765b847f15f221ce, crc: 3e4fb4

17 to,   data, enc, more_data,  len: 255, data: ea4d61864a515fe478413b4c1294b57a388207145b56224a50916abe01121f1280106fc5a577a83a1d40af897a07a18d0cdf1318f2d2d27e424c55575c20907d2df2478a0519c8170633f1a94db615ac37bba648c133dff426c20a28f9125fe1fd35d0af550701851692626b6ffac7434f92b568c266533652de21864323033898f514fd5cb0ef2059fe9ab68e2917d75d5ccfc6a8c21dba69d73bb79944c38bb5208ffe67e028649a406a2bd71d8670f19fefa719cfdbe672f4c58a1e2d1c092c3f21db23bf63f7da5d78905602f222e458a5ca7a04835d4cd90a1a5d900a78f67516ea443289971a7fe2da157d60ce1b6331acc87ef69ce9589efa9c5469, crc: 10b531

18 to,   data, enc, more_data,  len: 255, data: 8411de79f3a0cfb304f6dfec305c00ca30d769829e559b428dc6f0ae6d8b73d9afbbbfa8b4f4e5ad6bbe553beb3497882b8a413feee320f63869b79b98ac6a6783e0e5dee5e18e804313e22e56383afdb4eaa54487ad8aec5a5e016e5ddb3944813957e70524e058e85641fa4dcdb2714d6aa479160b4368c8dbadd66d8d8a9e4c8a7f584554f31522823559381e754e8cc8c6a00be26d750d7849366eccb224909dc98bda4e5181153c6707c0f65c9c6da1148cfefdc77a65636917f93c8c0d447ebd7e49894fb4617ab6b3709e2ab3b9c9fe18947eb45085e7b9e72cdbc01092ac603cc2f7cbfbfbb69ff9affaba609b99cf35694b9b9ef4cab3dfbc1d7b, crc: 30a6be

19 to,   data, enc, more_data,  len: 255, data: 4a21065d5ab2a0e2cb4f31e22bddd9576e81cd3105dc91a9fb9db0dcec197be84e441a79ecb41553852f1558785dc31f036208a452c357b1524cf56dbcdf985e6435b8f6174cfd28d92e3d30abe982ee10d80a753155bed89c85bad3649bed2f2e41a53c1a1edd6547227014868235ac5ebbe6e8c7cb92640d0cdd81a69135ad3b3639bee246285cc513cb6d216447342c596d77dfe64a06667b64f4b75ac7c603cb5c02aceaf4f780ec1cc43fed5fb8cf194b029d8e485fff93695f37862102b76060549ea9d0c5f852be7ced74e30dcda4bb9513a957fae08e41aa0974b5b04567f8a49da94c0fc8f2820a457118daece75a4ed45d0db8757c47a9d185e5, crc: 64276a

20 to,   data, enc,  len: 91, data: a6367b6aa555af69a9a97d0e09aa4886d52720c77465e33718768d1489d9d1cc84d0ed7bd60455002e04ee7fae368c478382a2ef264bdd9173d28c29315b8f3e3c19248950bed65fe788e4ac137126851bc88d4794e641859e6fb2, crc: 0b3768

21 from, data, enc, more_data,  len: 255, data: b729d427d4a9d5952ec3cecc1e70159c27c6638d8a03ed6cf1e4f5b143961ed9a79faee890f5ecad639e4f09ce13cfbc33d84f27c8ea3ace1178a8b18e9f6b5face2e8ebedc48fae7a36d500600a53ea89e8c61a95c5fcd85445711563fe1664d12142ee112af26dcb7340a345d0996a4952b13f1f703d4c99b1b3e902878ff745ac61216b49d838058d0a6837001b11bcc6c48231eb51445f74483558ddbc119ff7b985cb1e69b00b424875e2d04d9665f20185e997bc4872474254e12d99547659b75852ba5e994164b7cf459049f280ffff1db370bd7290edb3c537d6a735fa993e09e8c5debcd5858a98f8f4aa4dc9cece013d6f958fdad787e0993644, crc: de2274

22 from, data, enc,  len: 29, data: 1013375c5ca983e3905a58f705de88337fb3fc341cdaab9eaecf90ab8b, crc: 8c601f

23 to,   data, enc,  len: 40, data: 18aee95ecac09ee63dd28707b8942d4f2a7052d71bfd27d81bcceffd208a1463f9a135248def5781, crc: eca094

24 from, data, enc,  len: 96, data: a2162539df5bac459586535812db74a6cb541dd71f64ec4d12719f32a6def899e3d7eb62c4127702173ec242bc32aa5e82fee8ea335bc4ad7dc8f22e2059a30419171abe73afe65bfaa6ada32a15788d0db6b359b0be7fa6af68cde6e24ca95d, crc: 0b4acb

25 to,   data, enc,  len: 8, data: fd81d2b58c5e3206, crc: e78a0e
```
<p>You will not find any valuable information in client.py</p>
<p>Now we can draw a few conclusions, based on dump file and core.py file</p>
<p>Obviously the first of them is master and the second is slave</p>
<p>First 7 messages are not interesting. All we get from them is that they are using a secure connection from now on</p>
<p>Messages from 8 to 15 are a handshake between sockets. From which we can get:</p>
<p>8-9: crc seed 0xd9b2df to check that connection was not interrupted by anyone</p>
<p>10: master's IV = ec36e5b06955d995 and Secret = 567ee5de450737f8</p>
<p>11: slave's  IV = 68b3ded5b84014dc and Secret = f3fb7502d9390e34</p>
<p>12: master's confirm = 9f5136cacd9f2a5387394b7d0c1cXXXX (note that we don't know the last two bytes)</p>
<p>13: slave's  confirm = XXd6e4XXXX5cXXb7ba906e57055a8ec8 (now we don't know 4 bytes)</p>
<p>14: master's random_value = 4bd20924f0c3cd30ba64a0f1d964691e</p>
<p>15: slave's  random_value = dd76514f5736813aa8c2178eXXf82d5b(1 byte unknown)</p>
<p>Then they send data to each other in which we are not interested for now</p>

```python
from Crypto.Cipher import AES
import base64
import libscrc
from multiprocessing import Pool
from time import time
from Crypto.Util.number import long_to_bytes
from copy import copy
```

<p>The key to the solution is the fact that their shared key is very small(it's mod(0x1000000) hence we can iterate over this key</p>

```python
def calc_crc(crc, pdu):
    initvalue = int.from_bytes(crc, "little")
    crc = libscrc.hacker24(data=pdu, poly=0x00065B, init=initvalue,
                            xorout=0x00000000, refin=True, refout=True)
    return crc.to_bytes(3, "little")

def bytes_xor_16(bytes1, bytes2):
    v1 = int.from_bytes(bytes1, 'big')
    v2 = int.from_bytes(bytes2, 'big')
    v3 = v1 ^ v2
    return (v3).to_bytes(16, 'big')

def secure_decrypt_packet(key, plain, nonce):
    aes = AES.new(key=key, mode=AES.MODE_CCM, nonce=nonce)
    return aes.decrypt(plain)

def secure_encrypt(key, plain):
    aes = AES.new(key=key, mode=AES.MODE_ECB)
    return aes.encrypt(plain)

def secure_confirm(key, r, p1, p2):
    return secure_encrypt(key, bytes_xor_16(secure_encrypt(key, bytes_xor_16(r, p1)), p2))
```
<br>

```python
crc_seed = bytes.fromhex('d9b2df')

m_IV =     bytes.fromhex('ec36e5b06955d995')
m_Secret = bytes.fromhex('567ee5de450737f8')
s_IV =     bytes.fromhex('68b3ded5b84014dc')
s_Secret = bytes.fromhex('f3fb7502d9390e34')
m_random = bytes.fromhex('4bd20924f0c3cd30ba64a0f1d964691e')
```

<p>Now let's find out what are the XX unknown values using simple iteration</p>

```python
def get_m_confirm(crc_seed, crc):
    for i in range(256):
        for j in range(256):
            x, y = hex(i)[2:].zfill(2), hex(j)[2:].zfill(2)
            s = bytes.fromhex(f'84109f5136cacd9f2a5387394b7d0c1c{x}{y}')  # note that we use the whole message,
                                                                          # including first two bytes 0x84 and 0x10 + data
            if(crc == calc_crc(crc_seed, s)):
                return s
m_confirm_crc = bytes.fromhex('584605')
m_confirm = get_m_confirm(crc_seed, m_confirm_crc)[2:]
print(m_confirm)
```

```python
b'\x9fQ6\xca\xcd\x9f*S\x879K}\x0c\x1c\x16\xfa'
```

<p>We know that m_confirm = aes(key=shared_key, mode=ECB, plain=plain), where</p>
```python
plain = aes(key=shared_key, mode=ECB, plain=plain1)
```
<p>plain1 = b'\xff' * 16 <b>XOR</b> aes(key = shared_key, mode=ECB, plain=m_random <b>XOR</b> 0)</p>
<p>Hence we can iterate over [0, 0x1000000] to find the key</p>

```python
def get_key(g):
    for x in g:
        x = x.to_bytes(16, "little")
        if secure_confirm(x, m_random, b"\x00"*16, b"\xff"*16) == m_confirm:
            print(f"shared key = {x}")
gs = [range(i, 256**3, 32) for i in range(32)]
with Pool(10) as pool:
    pool.map(get_key, gs)
```

```python
shared_key = b'%=\x8c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
assert m_confirm == secure_confirm(shared_key, m_random, b"\x00"*16, b"\xff"*16)
```

<p>The rest is quite clear: we have to find s_random to calculate:</p>
```python
storekey = secure_encrypt(numeric_key, m_random[:8] + s_random[8:])
```
<p>And then</p>

```python
sessionkey = secure_encrypt(storekey, m_secret + s_secret)
```
<p>Finding s_random is very easy, since we have already done it with m_confrim.</p>


```python
def get_s_random(crc_seed, crc):
    for i in range(256):
        x = hex(i)[2:].zfill(2)
        s = bytes.fromhex(f'8710dd76514f5736813aa8c2178e{x}f82d5b')  # note that we use the whole message,
                                                                     # including first two bytes 0x87 and 0x10 + data
        if(crc == calc_crc(crc_seed, s)):
            return s
s_random_crc = bytes.fromhex('6f68ec')
s_random = get_s_random(crc_seed, s_random_crc)[2:]
```

<p>We could also calculate s_confirm, but this is only necessary for verification, and there are many values that correspond to crc = '2ddbb8'.It is not surprising, since we have to iterate over 3 unknown bytes.</p>

```python
store_key = secure_encrypt(shared_key, m_random[:8] + s_random[8:])
sessionkey = secure_encrypt(store_key, m_Secret + s_Secret)
```
<br>

```python
known_ciphertexts = [
    "ee491a84624116fb685e5d471494aa6d3eac7c53707c465050907ea20112040690025e92a61dd8291b50d0c16913b9cd0ff5290edad9c23d69384649765b847f15f221ce",
    "ea4d61864a515fe478413b4c1294b57a388207145b56224a50916abe01121f1280106fc5a577a83a1d40af897a07a18d0cdf1318f2d2d27e424c55575c20907d2df2478a0519c8170633f1a94db615ac37bba648c133dff426c20a28f9125fe1fd35d0af550701851692626b6ffac7434f92b568c266533652de21864323033898f514fd5cb0ef2059fe9ab68e2917d75d5ccfc6a8c21dba69d73bb79944c38bb5208ffe67e028649a406a2bd71d8670f19fefa719cfdbe672f4c58a1e2d1c092c3f21db23bf63f7da5d78905602f222e458a5ca7a04835d4cd90a1a5d900a78f67516ea443289971a7fe2da157d60ce1b6331acc87ef69ce9589efa9c5469",
    "8411de79f3a0cfb304f6dfec305c00ca30d769829e559b428dc6f0ae6d8b73d9afbbbfa8b4f4e5ad6bbe553beb3497882b8a413feee320f63869b79b98ac6a6783e0e5dee5e18e804313e22e56383afdb4eaa54487ad8aec5a5e016e5ddb3944813957e70524e058e85641fa4dcdb2714d6aa479160b4368c8dbadd66d8d8a9e4c8a7f584554f31522823559381e754e8cc8c6a00be26d750d7849366eccb224909dc98bda4e5181153c6707c0f65c9c6da1148cfefdc77a65636917f93c8c0d447ebd7e49894fb4617ab6b3709e2ab3b9c9fe18947eb45085e7b9e72cdbc01092ac603cc2f7cbfbfbb69ff9affaba609b99cf35694b9b9ef4cab3dfbc1d7b",
    "4a21065d5ab2a0e2cb4f31e22bddd9576e81cd3105dc91a9fb9db0dcec197be84e441a79ecb41553852f1558785dc31f036208a452c357b1524cf56dbcdf985e6435b8f6174cfd28d92e3d30abe982ee10d80a753155bed89c85bad3649bed2f2e41a53c1a1edd6547227014868235ac5ebbe6e8c7cb92640d0cdd81a69135ad3b3639bee246285cc513cb6d216447342c596d77dfe64a06667b64f4b75ac7c603cb5c02aceaf4f780ec1cc43fed5fb8cf194b029d8e485fff93695f37862102b76060549ea9d0c5f852be7ced74e30dcda4bb9513a957fae08e41aa0974b5b04567f8a49da94c0fc8f2820a457118daece75a4ed45d0db8757c47a9d185e5",
    "a6367b6aa555af69a9a97d0e09aa4886d52720c77465e33718768d1489d9d1cc84d0ed7bd60455002e04ee7fae368c478382a2ef264bdd9173d28c29315b8f3e3c19248950bed65fe788e4ac137126851bc88d4794e641859e6fb2",
    "b729d427d4a9d5952ec3cecc1e70159c27c6638d8a03ed6cf1e4f5b143961ed9a79faee890f5ecad639e4f09ce13cfbc33d84f27c8ea3ace1178a8b18e9f6b5face2e8ebedc48fae7a36d500600a53ea89e8c61a95c5fcd85445711563fe1664d12142ee112af26dcb7340a345d0996a4952b13f1f703d4c99b1b3e902878ff745ac61216b49d838058d0a6837001b11bcc6c48231eb51445f74483558ddbc119ff7b985cb1e69b00b424875e2d04d9665f20185e997bc4872474254e12d99547659b75852ba5e994164b7cf459049f280ffff1db370bd7290edb3c537d6a735fa993e09e8c5debcd5858a98f8f4aa4dc9cece013d6f958fdad787e0993644",
    "1013375c5ca983e3905a58f705de88337fb3fc341cdaab9eaecf90ab8b",
    "18aee95ecac09ee63dd28707b8942d4f2a7052d71bfd27d81bcceffd208a1463f9a135248def5781",
    "a2162539df5bac459586535812db74a6cb541dd71f64ec4d12719f32a6def899e3d7eb62c4127702173ec242bc32aa5e82fee8ea335bc4ad7dc8f22e2059a30419171abe73afe65bfaa6ada32a15788d0db6b359b0be7fa6af68cde6e24ca95d",
    "fd81d2b58c5e3206"]
```

Well, you can just count the number of messages sent by each side or iterate over [0, 10] to get a one-time number for aes encryption.

```python
for cip in known_ciphertexts:
    for n in range(10):
        try:
            pl = base64.b64decode(secure_decrypt_packet(sessionkey, bytes.fromhex(cip), n.to_bytes(13, "little")) + b'====')
            if(pl.decode()):
                print(pl, n)
        except Exception as e:
            continue
```

```python
b'I will tell you my flag after you finish your poem' 4
b"You mean this one? Shall I compare thee to a summer's day? Thou art more lovely and more temperate: Rough winds do shake the darling buds of May, And summer's lease hath all too short a date:" 4
b'No I mean this one, I never saw a Moor-I never saw the Sea-Yet know I how the Heather looksAnd what a Billow be.I never spoke with GodNor visited in Heaven-Yet certain am I of the spotAs if t' 5
b'q;cM8' 1
b'Nevermind, long live the AAA' 8
b'You got your flag: ACTF{ShORt_NUmeR1c_KEY_1s_Vuln3R4bLe_TO_e@V3sDropPEr}' 7
b'\x07' 7
b'\x06' 8
b'Cool' 9
```

<h2>RSA LEAK(357 points)</h2>
<h3>Task Description:</h3>
<p>We leak something for you~</p>
<h3>Attachments:</h3>

```python
from sage.all import *
from secret import flag
from Crypto.Util.number import bytes_to_long


def leak(a, b):
    p = random_prime(pow(2, 64))
    q = random_prime(pow(2, 64))
    n = p*q
    e = 65537
    print(f"new_n = {n}")
    print(f"leak = {(pow(a, e) + pow(b, e) + 0xdeadbeef) % n}")


def gen_key():
    while(True):
        a = randrange(0, pow(2,256))
        b = randrange(0, pow(2,256))
        p = pow(a, 4)
        q = pow(b, 4)
        rp = randrange(0, pow(2,24))
        rq = randrange(0, pow(2,24))
        pp = next_prime(p+rp)
        qq = next_prime(q+rq)
        if pp % pow(2, 4) == (pp-p) % pow(2, 4) and qq % pow(2, 4) == (qq-q) % pow(2, 4):
            print(f"rp, rq = {rp}, {rq}")
            print(f"pp, qq = {pp}, {qq}")
            n = pp*qq
            rp = pp-p
            rq = qq-q
            print(f"rp, rq = {rp}, {rq}")
            print(f"p, q = {p}, {q}")
            print("sdohla mat")
            return n, rp, rq

n, rp, rq = gen_key()
e = 65537
c = pow(bytes_to_long(flag), e, n)
print("n =", n)
print("e =", e)
print("c =", c)
leak(rp, rq)

'''
n = 3183573836769699313763043722513486503160533089470716348487649113450828830224151824106050562868640291712433283679799855890306945562430572137128269318944453041825476154913676849658599642113896525291798525533722805116041675462675732995881671359593602584751304602244415149859346875340361740775463623467503186824385780851920136368593725535779854726168687179051303851797111239451264183276544616736820298054063232641359775128753071340474714720534858295660426278356630743758247422916519687362426114443660989774519751234591819547129288719863041972824405872212208118093577184659446552017086531002340663509215501866212294702743
e = 65537
c = 48433948078708266558408900822131846839473472350405274958254566291017137879542806238459456400958349315245447486509633749276746053786868315163583443030289607980449076267295483248068122553237802668045588106193692102901936355277693449867608379899254200590252441986645643511838233803828204450622023993363140246583650322952060860867801081687288233255776380790653361695125971596448862744165007007840033270102756536056501059098523990991260352123691349393725158028931174218091973919457078350257978338294099849690514328273829474324145569140386584429042884336459789499705672633475010234403132893629856284982320249119974872840
=======leak=======
new_n = 122146249659110799196678177080657779971
leak = 90846368443479079691227824315092288065
'''

```
<h3>Solution</h3>
<p>First of all, let's talk about leak. As we can see the original rp and rq are very small, comparing tp p and q, and we expect the final rp and rq to have the same order(due to the density of the prime numbers). On the other hand, new n in the leak is not to big, and we are able to factor it out</p>

```python
from multiprocessing import Pool
from sage.all import factor
from gmpy2 import iroot, is_prime
from Crypto.Util.number import long_to_bytes
```

```python
n1 = 122146249659110799196678177080657779971
leak = 90846368443479079691227824315092288065
e = 65537
print(factor(n1))
```

```
8949458376079230661 * 13648451618657980711
```

<p>Now we can brute force the rq and rp values:</p>

```python
p1, q1 = 8949458376079230661, 13648451618657980711
c1 = (leak - 0xdeadbeef) % n1
d1 = pow(e, -1, (p1 -1) * (q1 - 1))

num_threads = 20

def check(g):
    for x in g:
        a = pow(c1 - pow(x, e, n1), d1, n1)
        if(a <= 2**24 and ((pow(a, e, n1) + pow(x, e, n1)) % n1 == c1)):
            print(f"rp = {a}, rq = {x}")

gens = [range(i, 2**24+1, 32) for i in range(32)]
with Pool(num_threads) as pool:
    pool.map(check, gens)
```

```
rp = 11974933, rq = 405771
```

```python
rp, rq = 11974933,  405771
```

<p>The second key idea is the relation between n and p*q. n = (p + rp) * (q + rq) = p * q + p * rq + q * rp + rp * rq. And we observe that p * q is a huge number, comparing to the rest part of n.</p>
<p>p * q ~ 2^2048, when p * rq + q * rp + rp * rq ~ 2^(1024 + 24) * 2 = 2^1049</p>
<p>Also we know that p * q is a perfect 4th power of some number(a * b), let's compute the distance between two perfect 4th powers of this order:</p><p>(x + 1)^4 - x^4 = ((x + 1)^2 - x^2) * ((x+1)^2 + x^2) = x * (2*x + 1) * (2*x^2 + x + 1). x = a * b ~ 2^512 => (x + 1)^4 - x^4 ~ 2^512 * 2^513 * (2 * 2^1024 + 2^512 + 1) ~ 2^2050 > 2^1049 ~ p * rq + q * rp + rp * rq</p>Now we expect the round(n^(1/4)) to be the exact product of a and b!!!</p>

```python
n = 3183573836769699313763043722513486503160533089470716348487649113450828830224151824106050562868640291712433283679799855890306945562430572137128269318944453041825476154913676849658599642113896525291798525533722805116041675462675732995881671359593602584751304602244415149859346875340361740775463623467503186824385780851920136368593725535779854726168687179051303851797111239451264183276544616736820298054063232641359775128753071340474714720534858295660426278356630743758247422916519687362426114443660989774519751234591819547129288719863041972824405872212208118093577184659446552017086531002340663509215501866212294702743
e = 65537
c = 48433948078708266558408900822131846839473472350405274958254566291017137879542806238459456400958349315245447486509633749276746053786868315163583443030289607980449076267295483248068122553237802668045588106193692102901936355277693449867608379899254200590252441986645643511838233803828204450622023993363140246583650322952060860867801081687288233255776380790653361695125971596448862744165007007840033270102756536056501059098523990991260352123691349393725158028931174218091973919457078350257978338294099849690514328273829474324145569140386584429042884336459789499705672633475010234403132893629856284982320249119974872840
```

```python
ab = int(iroot(n, 4)[0])
pq = pow(ab, 4)
```

<p> Using the fact that N = (p + rp) * (q + rq), and the relating pq = p * q we can construct a quadratic equation:</p>
<p> N = pq + (pq / q) * rq + rp * q + rp * rq => q^2 * rp - (N - pq - rp * rq) * q + rq * pq = 0</p>

```python
a, b, c = rp, pq - n + rp * rq, rq * pq
D = b**2 - 4 * c * a
D = int(iroot(D, 2)[0])
if((-b + D) % (2 * a) == 0):
    q = (-b + D) // (2 * a)
else:
    q = (-b - D) // (2 * a)
```

```python
p = pq // q
assert pq == p * q
```

```python
pp = p + rp
qq = q + rq
assert is_prime(pp)
assert is_prime(qq)
assert pp * qq == n

phi = (pp - 1) * (qq - 1)
d = pow(e, -1, phi)
c = 48433948078708266558408900822131846839473472350405274958254566291017137879542806238459456400958349315245447486509633749276746053786868315163583443030289607980449076267295483248068122553237802668045588106193692102901936355277693449867608379899254200590252441986645643511838233803828204450622023993363140246583650322952060860867801081687288233255776380790653361695125971596448862744165007007840033270102756536056501059098523990991260352123691349393725158028931174218091973919457078350257978338294099849690514328273829474324145569140386584429042884336459789499705672633475010234403132893629856284982320249119974872840
m = pow(c, d, n)
print(long_to_bytes(m))
```

```python
b'ACTF{lsb_attack_in_RSA|a32d7f}'
```

<h2>IMPOSSIBLE RSA(150 points)</h2>
<h3>Task Description</h3>
<p>Impossible</p>
<h3>Attachments:</h3>

```
-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB+pWAiyLgiiDUmsUJs4sGi
BJeEwLvitqUvBVtcgPEFK4vO4G6CNAd3JlN8zBqJRBVn1FRlcxGPPXuJgIjMOkyV
G4vo3mLr/v/pER79JrPgP8E5hShao5rujsue8NUq9+r1dUsnqU3gEiPyZspAG+//
8P7TW0XcvCy5olRZqkV/QD6dlqjBaufWgTL2iMCtkadXT99ETmmgDVJ/GE51xErz
pE8poKXjJqnwZEWEjdcqO1RXHKLAcmm3mpQEGbFOXWlb2cqSnKTbtJ0cVQ93y3gA
mjCCBJrQLulx+5Oyn2+1rkRlHuMSq82DC0qAMvbc/DTjlTVYSC+GvIpEEFR344/5
AgMBAAE=
-----END PUBLIC KEY-----
```

```python
flag: b'A\x89\x14\xaf\x03\xdd\x95]\xa3\xda\x08\xf3l\x93\x14\xa7i\x89\x8d&\xc9l\x14\xf5\x99(s=0\xb5\xd1\xdf\xf7\xc7\x07\x9c\xf1\x0e\x97\xa9\x9f6&\xf9\xf8Wbm\x116\xa6\x99 \xcd\x05\xb4\\.\n\xf4&\x1a@\x01\xdcjo%;g\x8ft\xdb\x96><A\xfd\x04\x8e\x9e\xf5\x9eA\xf8Y\xd0`\xfc\x80\x89\x88C\x1c\xee\x8e\xaf/\xa8\x1fO\xb4\x175\xads{x;\x02\xc1\x13x\xd2\xabg\xc7\xe4\xc6\xa6\x81\x99*\xf1l\xe38\xb6X\x9e\xd5\xed\xd0\x89\xb1\x1b\xaf\xd8thw\xd5\xff\xb9\xee;\xda5\xe5Se_\x81\xa9\x13\x7fx,\xda-\xfe\xb9\x93\xf6!\x94g~WKh\xe7\x08\xfbn\xaa\xeb\xce\xce\xed$\xf0\xbd7^\x92\xe4\x84`N\x987V\x93\x97\x12F\x98\xba\x11L\xbfo\ni\xe90{\x9a)_=\xfa\xd8\xca`\xaa+J\xa1\xc9KEK\x9aC\xe0d\xb11\xa8\xb0Z\xfd\xf1\xb6\xe2j\xe3\xccLS\x19\x13\xb9?Yub\xf5\x99\xf7\xe5\xe6\x02\xfe'
```
```python
from Crypto.Util.number import *
from Crypto.PublicKey import RSA

e = 65537
flag = b'ACTF{...}'

while True:
    p = getPrime(1024)
    q = inverse(e, p)
    if not isPrime(q):
        continue
    n = p * q;
    public = RSA.construct((n, e))
    with open("public.pem", "wb") as file:
        file.write(public.exportKey('PEM'))
    with open("flag", "wb") as file:
        file.write(long_to_bytes(pow(bytes_to_long(flag), e, n)))
    break
```

<h3>Solution:</h3>
<p>Firstly, let's extract the public key from the .pem file.</p>
```python
from Crypto.PublicKey import RSA
key = RSA.import_key('-----BEGIN PUBLIC KEY-----\nMIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB+pWAiyLgiiDUmsUJs4sGi\nBJeEwLvitqUvBVtcgPEFK4vO4G6CNAd3JlN8zBqJRBVn1FRlcxGPPXuJgIjMOkyV\nG4vo3mLr/v/pER79JrPgP8E5hShao5rujsue8NUq9+r1dUsnqU3gEiPyZspAG+//\n8P7TW0XcvCy5olRZqkV/QD6dlqjBaufWgTL2iMCtkadXT99ETmmgDVJ/GE51xErz\npE8poKXjJqnwZEWEjdcqO1RXHKLAcmm3mpQEGbFOXWlb2cqSnKTbtJ0cVQ93y3gA\nmjCCBJrQLulx+5Oyn2+1rkRlHuMSq82DC0qAMvbc/DTjlTVYSC+GvIpEEFR344/5\nAgMBAAE=\n-----END PUBLIC KEY-----\n')
n, e = key.n, key.e
print(n, e)
```
```
n =  15987576139341888788648863000534417640300610310400667285095951525208145689364599119023071414036901060746667790322978452082156680245315967027826237720608915093109552001033660867808508307569531484090109429319369422352192782126107818889717133951923616077943884651989622345435505428708807799081267551724239052569147921746342232280621533501263115148844736900422712305937266228809533549134349607212400851092005281865296850991469375578815615235030857047620950536534729591359236290249610371406300791107442098796128895918697534590865459421439398361818591924211607651747970679849262467894774012617335352887745475509155575074809
e =  65537
```
<p>First thing to noitice is the relation between p and q. q = e^-1(mod p)</p><p>Hence q * e = 1 + p * r, where r is some integer</p><p>There's a relation N = p * q, so N * e = p * q * e = p * (1 + p * r) = p + p^2 * r</p>Now we can compute the bounds for r. Since r = (N*e - p)/p^2, and we know that p is in [2^1023, 2^1024) </p>

```python
b1 = (n * e - 2**1023)/(2**1023)**2
b2 = (n * e - 2**1024)/(2**1024)**2
print(b1, b2)
```
```
b1 = 129687.48096677188
b2 = 32421.87024169297<p>Well, it is not so big, and we can simply check all the r values from 0 to 32422</p><p>Now we have an equation:</p><p>p^2 * r + p - N * e = 0, and we know that it has integer solutions. The discriminant is D = 1 + 4 * N * e * r, and we want it to be the perfect square. </p>
```
```python
import gmpy2
from math import ceil, floor
for r in range(floor(b2), ceil(b1)):
    D = 1 + 4 * n * e * r
    if(gmpy2.is_square(D)):
        print(D, r)
        break
```
```
D = 193964622160442418549075900540350386740557588845604305818540274399912663097404497033627390587172639557536736414300379825267728931631283890957722223953655562240782185741111470138184976601413493327655235429021466480708620276010228550791636531461272201139766573165139611001327579873352244991159377518194501310396072668967354515945629297811300617532621122117624770228496269388956222886804460132882581690682460789176015264000978117868212271173849182564437425641119711236135868951756902904297428533353177085267807626521599701668024464562724007193176056510427830910112962382910439890030674202542715075950436918289466074351226455996961
r = 46280
```
<p>Now we can solve the quadratic equation p^2 * r + p - N * e = 0. The roots are: p = (-1 +- sqrt(D)) / (2 * r)</p><p>The second one will give us a negative result, hence it is not a solution</p>

```python
p = (-1 + int(gmpy2.isqrt(D))) // (2 * r)
print(p)
```
```
150465840847587996081934790667651610347742504431401795762471467800785876172317705268993152743689967775266712089661128372295606682852482012493939368044600366794969553828079064622047080051569090177885299781981209120854290564064662058027679075401901717932024549311396484660557278975525859127898004619405319768113
```

```python
q = n // p
assert n == p * q
```

```python
d = pow(e, -1, (p - 1) * (q - 1))  # RSA Thing
c = bytes_to_long(flag)
m = pow(c, d, n)
print(long_to_bytes(m))
```
```python
b'ACTF{F1nD1nG_5pEcia1_n_i5_nOt_eA5y}'
```
