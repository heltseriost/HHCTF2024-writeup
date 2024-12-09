# HHCTF2024-writeup
Solved challenges for HHCTF 2024

Timespan: 5 hours

Part of team: mystery-masters (2nd place)

---

### ***The First Cuts***

*Category: Memory-forensics*,  *Points: 241*, *Difficulty: Easy*

The first challenge for analyzing the memory dump `memory.dmp`.

In the end of the description for the challenge, there was a text:  
After all, the first "**Cuts**" are the deepest. The word **Cuts** is highlighted in bold.

A simple `strings` command on the `.dmp` file with `grep` got me the flag.

<img width="393" alt="SCR-20241207-mqfz" src="https://github.com/user-attachments/assets/1600628d-b047-44d9-8b2b-a40378969f02">


`The flag is HHCTF{the_knife}`.

---

### ***Code of Misconduct***

*Category: Memory-forensics*,  *Points: 482*, *Difficulty: Easy*

In this challenge, we were tasked with finding a malicious executable.

This was the description:

"You receive a communique from Sherlock, Lestrade has been in touch about a potential lead for evidence in the RAM dump.

It appears that the Consortium of Criminal Fellowes has been targeting people in prominent positions, like judges and politicians. They group has created a new piece of malware which they are using to steal sensitive data, encrypt it and ransom the owners. Find the name of the executable file that is being run so it can be traced and investigated."

**Flag format:** `HHCTF{name-of-executable-without-file-extension}`

Here, I started using Volatility3.

I checked to see any malicious executed commands with the `cmdline` plugin:

`python3 vol.py -f memory.dmp windows.cmdline`  

I found this:

<img width="1260" alt="SCR-20241207-lawv" src="https://github.com/user-attachments/assets/34d2d7f9-199e-427f-a7d3-3f37c34ce430">

`The flag is HHCTF{delicious-malicious}`.

---

### ***Zip-a-Dee-Doo-Dah***

*Category: Memory-forensics*, *Points: 498*, *Difficulty: Hard* 

In this challenge this text was in the description:

"Dear God M, do not open that file called ideas_plans.zip you received this morning, the police are on their way! If you did, scrub it and encrypt your drive asap then cut power to your computer!"

So we are looking for a file called `ideas_plans.zip`.

I Used `filescan` with `grep` to get the virtual address of the file: 

<img width="681" alt="SCR-20241207-mqtr" src="https://github.com/user-attachments/assets/268c61e5-ece0-4bd4-9fd6-874d0da03133">

I found the virtual address `0xa58d2bd08130` so now we can dump out the file with `dumpfiles`

I ran : `python3 vol.py -f memory.dmp windows.dumpfiles --virtaddr 0xa58d2bd08130`

I then renamed it from `file.0xa58d2bd08130.0xa58d2bc32230.DataSectionObject.ideas_plans.zip.dat` to `ideas_plans.zip`.

The zipfile was password protected. 

I did not notice any hints of a password so I decided to use `fcrackzip` with the `rockyou.txt` wordlist.

<img width="839" alt="SCR-20241207-ljgc" src="https://github.com/user-attachments/assets/132cede7-990e-486d-a68f-ba2a7763994f">

`Password = Sherlock`.

Running the `file` command on the extracted file `maniacal_plans.zip` revealed that it was not a zip file but a text-file.

I checked it's contents:

<img width="1270" alt="SCR-20241207-llla" src="https://github.com/user-attachments/assets/336437e9-57b1-4dd8-969b-302b8a31c7f1">

There was information about a passcode and after that I noticed `any_harder` which looked weird and might be a passcode.

So I tried entering it as a flag, and it worked!

`The flag is HHCTF{any_harder}`

---

### ***Goodtimes with the Gang***

**THIS CHALLENGE WAS SOLVED AFTER THE CTF HAD ENDED!**

*Category: Memory-forensics*,  *Points: 482 (0 DUE TO LATE SUBMISSION)*, *Difficulty: Medium*

In this challenge, we were got this description: 

"An email was found on a remote server that alludes to a hidden file that may incriminate Moriarty.

"Dear M please find the sensitive keepsake you requested attached to this message, I had been turning myself inside out looking for it.

Regards, Sebastian

attachment name: "goodtimes.jpg""

So we are looking to maybe dump out a file called `goodtimes.jpg`.

Same method as earlier, I used `filescan` with `grep` to get the virtual address of the file:

<img width="659" alt="SCR-20241207-lqyp" src="https://github.com/user-attachments/assets/992bb2d4-54db-4f5a-a161-4408f8b303b0">

Found the virtual address `0xa58d2bd06830` so I dumped it out.

I opened it up:

<img width="1155" alt="SCR-20241207-lscg" src="https://github.com/user-attachments/assets/0cc51861-e1ab-4b2c-8054-ab50e1f74880">

Nothing interesting yet, so I threw it into Aperisolve:

<img width="1058" alt="SCR-20241207-ltab" src="https://github.com/user-attachments/assets/8b139ae9-63d6-4f20-9c58-bc427a52f62b">

Steghide showed a hidden file so I downloaded it and opened it:

<img width="1139" alt="SCR-20241207-ltht" src="https://github.com/user-attachments/assets/bdb4c8f4-c9d6-41f4-98a0-c6c2d615a4e8">

`The flag is HHCTF{judge_reinhold_lives}`.

---

### ***Quiz***

*Category: Programming*,  *Points: 50*, *Difficulty: Easy*

In this challenge, we were tasked with connecting to a server with netcat to answer a quiz.

We were provided with a file called `answers.txt` to every question. However the timer was to short to enter manually so it required a script.

I converted the contents in answers.txt to a dictionary format and used `pwntools` and a for-loop to iterate through it:

```python
from pwn import *

p = remote("ctfeh.hh.se", 7005)

questions_and_answers = {
    "Who is the author of *Sherlock Holmes*?": "Arthur Conan Doyle",
    "Which fictional detective is known for saying, 'Elementary, my dear Watson'?": "Sherlock Holmes",
    "In *The Maltese Falcon*, who is the private detective?": "Sam Spade",
    "Who created the character Hercule Poirot?": "Agatha Christie",
    "Who is the detective in *The Girl with the Dragon Tattoo*?": "Mikael Blomkvist",
    "What is the first name of Holmes’s brother?": "Mycroft",
    "In what year was *The Hound of the Baskervilles* published?": "1902",
    "Who wrote *The Moonstone*, one of the first detective novels?": "Wilkie Collins",
    "Which fictional detective is associated with the city of Yoknapatawpha?": "Gavin Stevens",
    "Who was the first to write 'locked-room' mysteries?": "Edgar Allan Poe",
    "What is the profession of the protagonist in *Gone Girl*?": "Writer",
    "What is the title of Arthur Conan Doyle’s final Sherlock Holmes novel?": "His Last Bow",
    "Who created the character Philip Marlowe?": "Raymond Chandler",
    "What is the fictional address of Sherlock Holmes?": "221B Baker Street",
    "In what year did Agatha Christie disappear for 11 days?": "1926",
}

for question, answer in questions_and_answers.items():
    p.sendlineafter(question, answer)

p.interactive()
```

<img width="840" alt="SCR-20241207-lxyx" src="https://github.com/user-attachments/assets/261cd2be-c638-4158-91fc-5cb00f9b3c5c">


`The flag is HHCTF{QuiZZy_m4st3R_oF_s3crets}`.

### ***Bolted chest***

*Category: Forensics*,  *Points: 50*, *Difficulty: Easy*

In this challenge, we got a .tiff file and this description:

"The chest, once strong, now creaks with age, Its weight a burden, a tired stage. Step by step, to the bin it walks, A relic lost, where the trash heap grows. Its secrets fade, its tale now done, Discarded under the setting sun."

This challenge has a hint of using `binwalk`

so i extracted it with `binwalk -e seamenschest.tiff` and I found a text file called `hidden_stream.txt` and checked it's content:

<img width="328" alt="SCR-20241207-mcnv" src="https://github.com/user-attachments/assets/0683a181-5bf0-429f-80a7-bd7bdcfd305f">

`The flag is HHCTF{open_says_me}`.

---

### ***Russian_Doll***

*Category: Misc*,  *Points: 50*, *Difficulty: Medium*

In this challenge, we got a zip file with a directory containing the following contents:

<img width="467" alt="SCR-20241207-meyg" src="https://github.com/user-attachments/assets/d5a868ba-d7b2-48d7-81ca-e656e70df246">

The Start.zip was password protected so I used `exiftool` on the jpg file to see if it contained anything interesting.

I found a comment: 

`Hint: Use the password 'StartHere' to.open the Start.zip file`

so i unzipped it and i got another password protected zip file and a .html file:

<img width="259" alt="SCR-20241207-mgqz" src="https://github.com/user-attachments/assets/e0d7d594-b6e2-4331-8f15-300127212af4">

I opened the html file and viewed the page source:

<img width="642" alt="SCR-20241207-mhmt" src="https://github.com/user-attachments/assets/e60221bd-afe6-428b-a31b-8ad625187aad">

Probably the password to the zip file. 

Opening `python3` and converting it to ascii using the command `print(bytes([110, 101, 120, 116, 83, 116, 101, 112]).decode())` I got the string "nextStep".

So I used that password to open up the zip file.

It contained another zip file and an executable:

<img width="706" alt="SCR-20241207-mkgr" src="https://github.com/user-attachments/assets/4b7cd17f-6f12-4fd4-8ec8-abcd929ab5de">

I just used `strings` on the executable and I found the text `Correct! The next hint is: DollRussian`

So i used "DollRussian" as a password to open the next zip file.

It showed yet another zip file and a db file.

So i opened the db file in `sqlitebrowser`

Browsing the table `users` I found a possible password `68wS&03G`:

<img width="209" alt="SCR-20241207-mlzq" src="https://github.com/user-attachments/assets/e7493c51-e1a1-4c67-9f95-362b3e043757">

I unlocked the zip file and this contained a txt file called `combination.txt`:

<img width="168" alt="SCR-20241207-mmti" src="https://github.com/user-attachments/assets/642c5710-3b90-4eb2-9fb3-d5bb718a0257">

I checked it's contents and found a base64 encoded string:

<img width="265" alt="SCR-20241207-mnkw" src="https://github.com/user-attachments/assets/7d041e7c-905c-4a02-9774-f46264d01e0f">

I decoded it and got the flag:

<img width="425" alt="SCR-20241207-mocg" src="https://github.com/user-attachments/assets/40da5d78-3ec3-49e6-8e3c-96ba9152e3cd">

`The flag is HHCTF{DollHunter007}`.

---

### ***Bit By Bit***

*Category: Forensics*,  *Points: 50*, *Difficulty: Easy*

A simple `strings` command on the file with `grep` got me the flag.

<img width="306" alt="SCR-20241207-ubyv" src="https://github.com/user-attachments/assets/66c93526-1499-44e4-8e32-4ab2adf4e8a6">


`The flag is HHCTF{th4t_w4s_A_8it_3aSy}`.

---


