---
title: "Digging into memory"
classes: wide
header:
  teaser: /assets/images/forensics/Defcon_ctf_2019/logo.jpg
ribbon: red
description: "I’m solving memory forensics challenge with volatility2 framework from Defcon DFIR CTF 2019"
categories:
  - Forensics
toc: false
---

Hi folks,

I'm solving memory  forensics challenge with `volatility 2` framework from **Defcon DFIR CTF 2019** [here](https://defcon2019.ctfd.io/challenges)

You can download the snapshot from [here](https://drive.google.com/drive/folders/1JwK8duNnrh12fo9J_02oQCz8HlILKAdW)

***************************************

### 01. get your volatility on - 5 Points

“What is the SHA1 hash of triage.mem?”

Solve:-

We just can use a tool `sha1sum` to get the hash.

```python
sha1sum Triage.mem
```

### **`flag<C95E8CC8C946F95A109EA8E47A6800DE10A27ABD>`**


*************

*************


### 02. pr0file - 10 Points

"What profile is the most appropriate for this machine? (ex: Win10x86_14393)"

Solve:-

We can use a plug-in `imageinfo` and choose the first suggestion.

```python
python2 /opt/volatility/vol.py -f Triage.mem imageinfo
```

#### ![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-07 18-08-53.png)

## `flag<Win7SP1x64>`

This is essential step in the discovery process and we will use the `profile` 4ever with volatility 2.


*************

*************


### 03. hey, write this down - 12 Points

“What was the process ID of notepad.exe?”

Solve:-

We can use plug-in `pslist`  it list all processes run in the memory.

```python
python2 /opt/volatility/vol.py -f Triage.mem pslist
```

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-07 18-27-51.png)

### `flag<3032>`


*************

*************

### 04. wscript can haz children - 14 Points

“Name the child processes of wscript.exe.”


Solve:-

Just use `pstree` plug-in and you will see the parents and children but I will `grep` the processes to save effort and I used `A1` to see 1 line under wscript process.

```python
python2 /opt/volatility/vol.py -f Triage.mem pstree |grep -A1 wscript.exe
```

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-07 18-38-16.png)

### `flag<UWkpjFjDzM.exe>`

It seems like a **malicious** **process**  Hmmmmmmmm .. Let's continue...


*************

*************

### 05. tcpip settings - 18 Points

“What was the IP address of the machine at the time the RAM dump was created?”


Solve:-

`netscan` plug-in is used to discover IPs and protocols in the memory and look under 'Local Address' column.

```python
python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 netscan
```

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-07 18-48-48.png)

### **`flag<10.0.0.101> `**

*************

*************


### 06. intel - 18 Points

“Based on the answer regarding to the infected PID, can you determine what the IP of the attacker was?”


Solve:-

We still in `netscan` solution.. Just scroll down and look to **Foreign Address** column.

```python
python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 netscan
```

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-07 18-56-24.png)

### `flag<10.0.0.106>`


*************

*************

### 07. i <3 windows dependencies - 20 Points

“What process name is VCRUNTIME140.dll associated with?”


Solve:-

Look to name, this is a dll file so we use `dlllist` plug-in and explore it's results at the first then..

use `grep` to specify the flag

```python
python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 dlllist | grep VCRUNTIME140.dll -B 30
```

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-08 14-49-33.png)

### `flag<OfficeClickToR>`

We used  ***-B 30*** to get previous 30 line before the dll file.


*************

*************


### 08. mal-ware-are-you - 20 Points

“What is the md5 hash value the potential malware on the system?”


Solve:-

First, we will dump the executable file for malicious process.

second, we will calculate the hash.

```python
python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 procdump -p 3496 --dump-dir=./ 
```

```python
md5sum executable.3496.exe
```

  ![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-08 14-56-41.png)

### `flag<690ea20bc3bdfb328e23005d9a80c290>`


*************

*************

### 09. lm-get bobs hash - 24 Points

“What is the LM hash of bobs account?”

Solve:-

Use `hashdump` and check bob.

result =  name : :id: : account hash : pass hash

```python
python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 hashdump
```

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-08 15-05-16.png)

### `flag<aad3b435b51404eeaad3b435b51404ee>`



*************

*************


### 10. vad the impaler - 25 Points

“What protections does the VAD node at 0xfffffa800577ba10 have?”

Solve:-

Just explore with `vadinfo` then use grep.

```python
python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 vadinfo | grep "0xfffffa800577ba10" -A3
```

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-08 15-10-55.png)

### `flag<PAGE_READONLY>`


*************

*************

### 11. more vads?! - 25 Points

“What protections did the VAD starting at 0x00000000033c0000 and ending at 0x00000000033dffff have?"

Solve:-

From previous plug-in we can understand the results so we can grep with the right text.

```python
python2 /opt/volatility/vol.py -f Triage.mem--profile=Win7SP1x64 vadinfo | grep "Start 0x00000000033c0000 End 0x00000000033dffff" -A3
```

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-08 15-17-46.png)

#### `flag<PAGE_NOACCESS>`


*************

*************

### 12. vacation bible school - 25 Points

“There was a VBS script run on the machine. What is the name of the script? (submit without file extension)”

Solve:-

With `cmdline`  plug-in we will get the result directly :dancer:

```python
python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 cmdline |grep ".vbs"
```

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-08 15-20-35.png)

### `flag<vhjReUDEuumrX>`


*************

*************

### 13. thx microsoft - 25 Points

“An application was run at 2019-03-07 23:06:58 UTC, what is the name of the program? (Include extension)”

Solve:-

`shimache` plug-in gets it directly with grep.

```python
python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 shimcache | grep "2019-03-07"
```

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-08 15-27-03.png)

### `flag<Skype.exe>`


*************

*************

### 14. lightbulb moment - 35 Points

“What was written in notepad.exe in the time of the memory dump?”

Solve:-

First, we will dump the memory space with contain the notepad content then.. We will search in the dumped file.

After trying The flag is encoded :)  so we used `-e l`.

```python
python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 memdump -p 3032 --dump-dir=./
```

#### `strings -e l 3032.dmp | grep "flag"`

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-08 15-37-00.png)

#### `flag<REDBULL_IS_LIFE>`



*************

*************


### 15. 8675309 - 35 Points

“What is the shortname of the file at file record 59045?”

Solve:-

Did you heard about **Master file table**?
This hold information about all files and the directories in the NTFS system, this includes the record number.
For more about mft information look at [here](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

`mftparser` plug-in can do our job.

```python
python2 /opt/volatility/vol.py -f Triage.mem --profile=Win7SP1x64 mftparser | grep "59045" -A 20
```

![](/assets\images\forensics\Defcon_ctf_2019\Screenshot from 2021-06-08 16-01-44.png)

#### `flag<EMPLOY~1.XLS>`


*************

*************

### 16. whats-a-metasploit? - 50 Points

“This box was exploited and is running meterpreter. What PID was infected?”


Solve:-

From previous questions we already know the infected process but we can dump the executable file with `procdump` and check its hash on  [VirusTotal Report](https://www.virustotal.com/gui/file/b6bdfee2e621949deddfc654dacd7bb8fce78836327395249e1f9b7b5ebfcfb1/detection)

### `flag<3496>`

*************

*************

Thank you for reading ^_^ 

​									![](\assets\images\forensics\Defcon_ctf_2019\GoodJob.png)
