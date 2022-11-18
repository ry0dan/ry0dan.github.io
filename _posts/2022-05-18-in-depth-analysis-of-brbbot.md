---
title: "In-depth analysis of brbbot malware"
last_modified_at: 2016-03-09T16:20:02-05:00
classes: wide
header:
  teaser: /assets/images/pinkpanther.jpg
description: "IcedID , also known as BokBot, was among one of the most active malware families and has been known for loading different types of payloads such as Cobalt Strike."
categories:
  - Malware Analysis
ribbon: DodgerBlue
tags:
  - BRBBOT
---
Sample:
```
F47060D0F7DE5EE651878EB18DD2D24B5003BDB03EF4F49879F448F05034A21E
```
This is a fairly simple malware sample that can be a great start for beginners in Malware Analysis!
<br>
As it combines different kinds of techniques and at the same time a simple implementation, So let's start digging into it! 🔥.

# Extracting Strings
I prefer always to start by viewing the strings as it gives me a general insight on what this sample is doing
![Screenshot1](/img/brbbot1.png)
the information we get from this screenshot is that:
1. this malware might be doing some persistence by placing itself in <mark>Software\Microsoft\Windows\CurrentVersion\Run</mark> registry key.
2. <mark>Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)</mark> is a User-Agent so there might be a possible network activity.
3. <mark>Reg*</mark> WinAPIs shows that there is some registry activity.
4. <mark>Crypt*</mark> WinAPIs shows that there might be some encryption.

# Behaviour Analysis

let's start executing the sample and monitor its HOST behaviours with ProcMon and ProcDOT.
![Screenshot2](/img/brbbot2.png)

loading the CSV from ProcMon into ProcDOT we can see two important events happening
1. the sample moves itself to <mark>C:\Users\REM\AppData\Roaming</mark> with the same old name.
2. the sample drops a file <mark>brbconfig.tmp</mark>.

viewing the dropped file content we see that it is encrypted.
![Screenshot3](/img/brbbot3.png)

if you take a look at the brbbot.exe's resource section you'll understand where did this file came from.
![Screenshot4](/img/brbbot4.png)

let's fire wp wireshark and monitor this sample's network activity<br>
- *Note: Iam using FakeNet to simulate some network services*
![Screenshot5](/img/brbbot5.png)

we notice first looking at the packet number 3 a DNS query to resolve the hostname <mark>brb.3dtuts.by</mark> and this can be used as an IOC, we also see at packet number 8 an HTTP request to <mark>ads.php</mark> with some parameters, here is the full URL:

```
 /ads.php?i=10.0.2.15&c=DESKTOP-2C3IQHO&p=123f373e600822282f3e366028362828753e233e603828292828753e233e602c32353235322f753e233e603828292828753e233e602c323537343c3435753e233e60283e292d32383e28753e233e6037283a2828753e233e60282d383334282f753e233e603d34352f3f292d3334282f753e233e603d34352f3f292d3334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e603f2c36753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e600d193423083e292d32383e753e233e602d363a382f33372b753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60163e363429227b1834362b293e282832343560282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282b343437282d753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60083e382e29322f22133e3a372f33083e292d32383e753e233e60282d383334282f753e233e600d1c1a2e2f33083e292d32383e753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e6028323334282f753e233e60282d383334282f753e233e60282d383334282f753e233e602f3a28303334282f2c753e233e60282d383334282f753e233e60282d383334282f753e233e60382f3d363435753e233e603e232b3734293e29753e233e6008333e37371e232b3e29323e35383e1334282f753e233e60083e3a2938330e12753e233e60092e352f32363e192934303e29753e233e60092e352f32363e192934303e29753e233e60083e3a29383312353f3e233e29753e233e60282d383334282f753e233e60282d383334282f753e233e600d1934230f293a22753e233e60282d383334282f753e233e60282d383334282f753e233e600c36320b292d081e753e233e601a2b2b3732383a2f3234351d293a363e1334282f753e233e600c3235082f34293e751a2b2b753e233e60092e352f32363e192934303e29753e233e60092e352f32363e192934303e29753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e60282d383334282f753e233e603f37373334282f753e233e60282d383334282f753e233e60282d383334282f753e233e6028363a292f2838293e3e35753e233e60282d383334282f753e233e60282d383334282f753e233e601d3a303e153e2f753e233e603834353334282f753e233e60322b3834353d323c753e233e60393a38303c29342e353f0f3a28301334282f753e233e60083e3a2938330b29342f343834371334282f753e233e60083e3a2938331d32372f3e291334282f753e233e603f37373334282f753e233e603f37373334282f753e233e6039293939342f753e233e
```
![Screenshot6](/img/6.png)

we see the User-Agent we've collected from strings used here in this request.<br>
also there are three parameters in this query:
1. **i**: which is clearly an IP address (our host's IP address).
![Screenshot7](/img/brbbot7.png)
2. **c**: the hostname of our host.
![Screenshot8](/img/brbbot8.png)
3. **p**: which is a long hex strem (if we tried to convert it to ASCII we won't understand anything, it might be encrypted).

let's save this hex data to a file for further analysis.
# Code Analysis (FUN Part!🤩)

I always start my analysis with IDA from the strings window, firts as we saw before there is a resource section that is called CONFIG, let's find it in strings and see where is it used.
![Screenshot9](/img/brbbot9.png)

AHA! as we expected! this sample finds the resource named CONFIG then drops it to the disk under the name <mark>brbconfig.tmp</mark> (the encrypted file we saw before)
the next step I would do is to try to decrypt the file content, as we also saw earlier there is a lot of Crypt* function in this sample, let's look for them in the imports and examine the code.
![Screenshot10](/img/brbbot10.png)
![Screenshot11](/img/brbbot11.png)
first we see that it opens a handle to *brbconfig.tmp* into v5 and v6.<br>
next we see a group of cryptographic functions that sets the key and algorithm for decryption.<br>
then at line 57 it reads the content of the file v5 into the buffer v14 (which is allocated in Heap).<br>
next if <mark>ReadFile</mark> is successful and the number of bytes to read is less than 1000 bytes it will call <mark>CryptDecrypt</mark> with the key that was previously crafted.

what we need to know now are two things:
1. what algorithm is used for encryption?.
2. what is the key of encryption?.

to get the answer of those two questions we have to analyse the cryptography functions.
the three important functions we have to take a look at are:
- [x] CryptCreateHash<br>
a good place to search for information about any WinAPI function is MSDN, so looking at the function's documentation [here](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash) we see the following:
```C++
BOOL CryptCreateHash(
  [in]  HCRYPTPROV hProv,
  [in]  ALG_ID     Algid,
  [in]  HCRYPTKEY  hKey,
  [in]  DWORD      dwFlags,
  [out] HCRYPTHASH *phHash
);
```
So what's important for us now is the second argument <mark>Algid</mark> which has a value of **0x8003**, reveiwng MSDN again for the Algid we see that it is MD5 Algorithm.
![Screenshot12](/img/brbbot12.png)
- [x] CryptHashData<br>

Again we review the function's definition in MSDN:
```C++
BOOL CryptHashData(
  [in] HCRYPTHASH hHash,
  [in] const BYTE *pbData,
  [in] DWORD      dwDataLen,
  [in] DWORD      dwFlags
);
```
this time we are interested in the <mark>pbData</mark> parameter which is in oure case the string ``YnJiYm90``.


*notice that hHash parameter is the return value from <mark>CryptCreateHash</mark>.*

so the coclution of the two functions analysis is that an MD5 hash from the string ``YnJiYm90`` will be created.
- [x] CryptDeriveKey

```C++
BOOL CryptDeriveKey(
  [in]      HCRYPTPROV hProv,
  [in]      ALG_ID     Algid,
  [in]      HCRYPTHASH hBaseData,
  [in]      DWORD      dwFlags,
  [in, out] HCRYPTKEY  *phKey
);
```
this function will generate the decryption key (<mark>phKey</mark>), the Algid here represents the decryption algorithm used and since in our case it holds **0x6801**
we can serach MSDN for it.
![Screenshot13](/img/brbbot13.png)
NICE! so it's RC4, but what is the key?
As this function recieves a handle to a hash object created by <mark>CryptHasahData</mark> it generates the key based on this hash (for further information review MSDN's documentation)

So our key will be the MD5 hash of ``YnJiYm90``

```
e2834a5bba1c28b7f536bd3ec5f1d8e0
```

and our decryption algorithm is RC4.
let's fire up CyberChef and verify our results 👀.
![Screenshot14](/img/brbconfig14.png)
AND indeed we decrypted the file!
```
uri=ads.php;exec=cexe;file=elif;conf=fnoc;exit=tixe;encode=5b;sleep=30000
```
now let's reaname this function to *decrypt_brbconf* and move on with our analysis
the next step is to know how is this data used in the sample, for that we can see cross-references to *decryptbrbconf* function and start analysing from there.
![Screenshot15](/img/brbbot15.png)

in the above screenshot we can see that *decrypt_brbconf* is executed and it will return the buffer containing the configuration data in the **Src** Parameter,then the variable is used several time as a parameter to the function **sub_7ff709751000**

I did a quick dynamic analysis of the function output and noticed that it parses the config string and looks for the value of the third parameter passed to it and extracts it to the last parameter, for example when the third parameter is **uri** the function will extract **ads.php** (because in the config we see uri=ads.php).

let's rename the variables based on their values and continue with the analysis.

next I investigated the call to <mark>HttpOpenRequestA</mark> and came up with the request function.
![Screenshot16](/img/brbbot16.png)

If we move back to see the cross-references and locate the subdomain value we see that it is obtained by XORing the value "#3#or%5452o#8A" with 0x41 (becomes: brb.3dtuts.by.)
![Screenshot17](/img/brbbot17.png)
Also in the same function we can see the parameters being assigned.
![Screenshot18](/img/brbbot18.png)
![Screenshot19](/img/brbbot19.png)

We are only interested in the last parameter which is v5 as it will contain our encoded hex data.
so let's move back and see where does this varible gets assigned.

![Screenshot20](/img/brbbot20.png)

In the above screenshot we see that v5=v15 and v15 is a memory address in heap.

next we see that v17=v15 so now we have v5, v17, v15 all with the same pointer address.

we also see that <mark>sprintf</mark> prints some hex data pointed to by v16 into v17.

v16=v8, let's go back and see v8
- Note: there are a lot of assigns and "=" signs for the purpose of obfuscating the code.

![Screenshot21](/img/brbconf21.png)

v8 = lpMem but lpMem is passed as a parameter for the function <mark>sub_7ff70975330</mark>, let's decompile the function and analyse it.
![Screenshot22](/img/brbbot22.png)
what happens in this function is:
1. it obtains a handle to <mark>ntdll.dll</mark>.
2. it resolves <mark>ZwQuerySystemInformatin</mark> address from NTDLL.
3. it calls <mark>ZwQuerySystemInformatin</mark>.

<mark>ZwQuerySystemInformatin</mark> can be used to get different system information like basic system information and processors information etc.

but how can we determine what information it is trying to collect here? the answer is: by seeing the first argument **SystemInformationClass**
```C++
NTSTATUS WINAPI ZwQuerySystemInformation(
  _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Inout_   PVOID                    SystemInformation,
  _In_      ULONG                    SystemInformationLength,
  _Out_opt_ PULONG                   ReturnLength
);
```
In our case it is 0x05 so if we googled it we can determine what type of information it wants:
![Screenshot23](/img/brbbot23.png)
0x05 is the value of **SystemProcessInformation**

so now we can cearly say that the hex data that was sent is just the processes on the system.

but how was it encrypted?

let's get out of this function and move a step back to <mark>sub_7ff709751c10</mark> we see lpMem assigned to v13 then v13 is XORed with some value.
![Screenshot24](/img/brbbot24.png)

in order to know the XOR key we have to know the parameter <mark>a1</mark> address then add 0x514 and the value we get will be our XOR key.

![Screenshot25](/img/brbbot25.png)
the first parameter is the address <mark>&unk_7ff709764560</mark>, if we tried to view it we will get nothing because it gets its value during the execution time, we can easily put a breakpoint on this line then see what value it holds.
![Screenshot26](/img/brbbot26.png)

the address starts at 0x00007FF709764560 but our key is at this address + 0x514 = 0x7ff709764a74.
![Screenshot27](/img/brbbot27.png)

COOL! 0x5b ! we got the key.

- Note: remember that in the config we decrypeted before we saw encode=5b (that was obviously the decryption key but it is always more fun to figure it out by code analysis 🤣).

And now let's come back to the hex data we saved and decrypt it with CyberChef.
![Screenshot29](/img/brbbot29.png)

names of processes? that was expected!.
