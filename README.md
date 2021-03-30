- [PicoCTF 2021 Writeups](#picoctf-2021-writeups)
  - [General SKills](#general-skills)
    - [Obedient Cat](#obedient-cat)
    - [Python Wrangling](#python-wrangling)
    - [Wave a flag](#wave-a-flag)
    - [Nice netcat](#nice-netcat)
    - [Static ain't always noise](#static-aint-always-noise)
    - [Tab, Tab, Attack](#tab-tab-attack)
    - [Magikarp Ground Mission](#magikarp-ground-mission)
  - [Cryptography](#cryptography)
    - [Mod 26](#mod-26)
    - [Mind your Ps and Qs](#mind-your-ps-and-qs)
    - [Dachshund Attacks](#dachshund-attacks)
    - [Play Nice](#play-nice)
    - [Pixelated](#pixelated)
  - [Forensics](#forensics)
    - [information](#information)
    - [Weird File](#weird-file)
    - [Matryoshka doll](#matryoshka-doll)
    - [Milkslap](#milkslap)
    - [tunn3l v1s10n](#tunn3l-v1s10n)
    - [Wireshark doo dooo do doo](#wireshark-doo-dooo-do-doo)
    - [Wireshark twoo twooo two twoo](#wireshark-twoo-twooo-two-twoo)
    - [Surfing the Waves](#surfing-the-waves)
    - [MacroHard WeakEdge](#macrohard-weakedge)
    - [Trivial Flag Transfer Protocol](#trivial-flag-transfer-protocol)
    - [Disk, disk, sleuth](#disk-disk-sleuth)
    - [Disk, disk, sleuth! II](#disk-disk-sleuth-ii)
  - [Web Exploitation](#web-exploitation)
    - [GET aHEAD](#get-ahead)
    - [Cookies](#cookies)
    - [Scavenger Hunt](#scavenger-hunt)
    - [Some Assembly Required 1](#some-assembly-required-1)
  - [Reverse Engineering](#reverse-engineering)
    - [Transformation](#transformation)
    - [keygenme-py](#keygenme-py)
    - [crackme-py](#crackme-py)
    - [ARMssembly 0](#armssembly-0)
    - [speeds and feeds](#speeds-and-feeds)
    - [Shop](#shop)
  - [Binary Exploitation](#binary-exploitation)
    - [What's your input?](#whats-your-input)

# PicoCTF 2021 Writeups

## General SKills

### Obedient Cat

`This file has a flag in plain sight (aka "in-the-clear").`

The description isn't kidding.. You just have to: `cat flag` and the flag is produced

Flag: `picoCTF{s4n1ty_v3r1f13d_28e8376d}`

### Python Wrangling

`Python scripts are invoked kind of like programs in the Terminal... Can you run this Python script using this password to get the flag?`

First I had to download the python script `ende.py`, the flag file `flag.txt.en`, and the password file `pw.txt`.

Running the file: `python3 ende.py -d flag.txt.en` and inputting the password: `dbd1bea4dbd1bea4dbd1bea4dbd1bea4` produces the flag.

Flag: `picoCTF{4p0110_1n_7h3_h0us3_dbd1bea4}`

### Wave a flag

`Can you invoke help flags for a tool or binary? This program has extraordinarily helpful information...`

First you have to download the program `warm`. Using `file` you find the program is a ELF 64-bit.

You have to make the program executable by using: `chmod +x warm`. Running the program it tells you to pass the `-h` flag to learn what it can do. Using `./warm -h` produces the flag in the output.

Flag: `picoCTF{b1scu1ts_4nd_gr4vy_18788aaa}`

### Nice netcat

`There is a nice program that you can talk to by using this command in a shell: $ nc mercury.picoctf.net 22902, but it doesn't speak English...`

When you connect to the port a list of numbers are outputted. It looks like they may be decimal ASCII representations.

Using the `From Decimal` recipie in CyberChef I was able to convert the numbers to the flag.

Flag: `picoCTF{g00d_k1tty!_n1c3_k1tty!_d3dfd6df}`

### Static ain't always noise

`Can you look at the data in this binary: static? This BASH script might help!`

First you have to download the two files, one is `static` and the other is `ltdis.sh`. Running `file` on `stiatic` you find that it's a ELF 64-bit. Make the program executable by using: `chmod +x static`, the same can be done for the Bash script.

Running `./ltdis.sh static` tells us in the output that: `Any strings found in static have been written to static.ltdis.strings.txt with file offset`.

Using `cat static.ltdis.strings.txt` shows us the flag in the output.

Flag: `picoCTF{d15a5m_t34s3r_ccb2b43e}`

### Tab, Tab, Attack

`Using tabcomplete in the Terminal will add years to your life, esp. when dealing with long rambling directory structures and filenames: Addadshashanammu.zip`

First you have to download the file and then `unzip Addadshashanammu.zip`. This produces multiple directories within other directories.

Using `ls -R` to recursively list all directories and files shows the end of the line stops at: `./Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku:fang-of-haynekhtnamet`

Once that directory is reached using `file fang-of-haynekhtnamet` shows that we're dealing with a ELF 64-bit. It appears that the permissions are already set so we can execute the program. Running `./fang-of-haynekhtnamet` produces the flag.

Flag: `picoCTF{l3v3l_up!_t4k3_4_r35t!_d32e018c}`

### Magikarp Ground Mission

`Do you know how to move between directories and read files in the shell? Start the container, ssh to it, and then ls once connected to begin. Login via ssh as ctf-player with the password, abcba9f7`

First you must launch the instance then to connect, use: `ssh ctf-player@venus.picoctf.net -p 50952`. Then enter the password that is given. Using `ls` we find that there's two files, `1of3.flag.txt` contains a portion of the flag and instructions to find the second portion are in: `instructions-to-2of3.txt`.

First portion of the flag: `picoCTF{xxsh_`. The instructions tells us to: `Next, go to the root of all things, more succinctly /`. We can do this by using `cd /`. Using `ls` we find the second portion of the flag along with instructions to find the last portion.

Second portion of the flag: `0ut_0f_\/\/4t3r_`. The instructions tells us to: `Lastly, ctf-player, go home... more succinctly ~`. We do this by using `cd ~` where we find the last portion of the flag.

Full Flag: `picoCTF{xxsh_0ut_0f_\/\/4t3r_21cac893}`

## Cryptography

### Mod 26

`Cryptography can be easy, do you know what ROT13 is?`
`cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_GYpXOHqX}`

Using the `ROT13` recipie in CyberChef we can produce the flag from the ciphertext.

Flag: `picoCTF{next_time_I'll_try_2_rounds_of_rot13_TLcKBUdK}`

### Mind your Ps and Qs

`In RSA, a small e value can be problematic, but what about N? Can you decrypt this? values`

First we must download the file `values` which contain the RSA values.

`c: 240986837130071017759137533082982207147971245672412893755780400885108149004760496`
`n: 831416828080417866340504968188990032810316193533653516022175784399720141076262857`
`e: 65537`

I first needed to find the p and q values. So I used the website: `factordb.com`. I inputted the n value and I got p = `1593021310640923782355996681284584012117` and q = `521911930824021492581321351826927897005221`.

I then used this site to decode the ciphertext: `https://www.dcode.fr/rsa-cipher`. Inputting the values I obtained I was able to retrieve the flag.

Flag: `picoCTF{sma11_N_n0_g0od_23540368}`

### Dachshund Attacks

`What if d is too small? Connect with nc mercury.picoctf.net 31133.`

Since this is an RSA problem, there's a great tool that I wanted to download first from: `https://github.com/Ganapati/RsaCtfTool`. After doing this I then connected to the service using: `nc mercury.picoctf.net 31133` and grabbed the RSA values.

Since there's an RSA attack method called weiner and a Dachshund is also called a weiner dog, I decided to run this attack using the tool above:
`./RsaCtfTool.py -n 89764762883114346163956180244339542588191131391910618597956236396846752553814093471554943032971015025016923330048463223452666667805739349477602577938734275683955744555685324405243118072515003938079825436554508061283202689345845691237232568153552197835431186640420589706996702940618733028308892094204239229553 -e 62961465046479567010491515522747176001288557716800650650398380009006092824231868771536585238280362882112993783973182822304259322135996987975677864581938567766786965672217761921081072481276891885207449470984798287557518035251766265522182545299755692400598689983545298710634103399386403754776996717141119104343 --uncipher 7483419321458169732846992838016542987104571415892347935438973224027238024670159881081773011841319824605896817099707490577529571904588913829604151011683806540087288389854385988622129339752141736104702805767415515245425529075007714638669198316554183744223433956063572692932983173327823714933534074985376786642 --attack wiener`

This gave me the output for the unciphered text as: `HEX : 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007069636f4354467b70726f76696e675f7769656e65725f313134363038347d`.

I then through this value, minus the leading zeros, into CyberChef and used the `From Hex` recipie to retrieve the flag.

Flag: `picoCTF{proving_wiener_1146084}`

### Play Nice

`Not all ancient ciphers were so bad... The flag is not in standard format. nc mercury.picoctf.net 6057 playfair.py`

First I downloaded the Python file `playfair.py`. Looking at the source code it seems that we're working with the alphabet `meiktp6yh4wxruavj9no13fb8d027c5glzsq`. Since it seems we're working with a PlayFair cipher I used the tool found at: `https://www.dcode.fr/playfair-cipher`.

I expanded the square size to 6X6 as this was indicated what we should use in the Python file by: `SQUARE_SIZE = 6`. I then wrote in the alphabet into the matrix.

Next, I connected to the service and it stated that the encrypted message was: `y7bcvefqecwfste224508y1ufb21ld`. So I inputted that value into the tool and the result was the string `WD9BUKBSPDTJ7SKD3KL8D6OA3F03G0`. Since the other strings were all lowercase I converted the string to lowercase as well using Python.

![play](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/vmware_5IgqXwXSsj.png)

```python
s = "WD9BUKBSPDTJ7SKD3KL8D6OA3F03G0"
print(s.lower())
```

The service asked me to enter the plaintext message, which I did, and the flag was returned.

Flag: `2e71b99fd3d07af3808f8dff2652ae0e`

### Pixelated

`I have these 2 images, can you make a flag out of them? scrambled1.png scrambled2.png`

First I downloaded the two `.png` files. When looking at the images they both just appear as noise. Since this is a crypto challenge, I figured to solve it I may need to XOR the two files together.

I used the following command to XOR the `.png` files together and output the result to a separate `.png`.
`gmic scrambled1.png scrambled2.png -blend xor -o output.png`

I was able to see that there was some kind of message in the output file but it was really hard to read anything.

![pixe1](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/vmware_H4GCS5N3EJ.png)

So I ended up opening the file in GIMP. I ended up messing with color levels until I found settings that worked. I brought the brightness levels all the way down and the contrast levels all the way up. This made the flag very easy to read.

![pixe2](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/gimp-2.10_gKdpOj9WQ2.png)

Flag: `picoCTF{0542dc1d}`

## Forensics

### information

`Files can always be changed in a secret way. Can you find the flag?`

First you have to download the file `cat.jpg`.

Next use: `exiftool cat.jpg` to produce the metadata of the file. Looking through the info it seems that there may be a base64 string within the License field, `cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9`.

I placed this into the `Magic` recipie within CyberChef and it produced the flag.

Flag: `picoCTF{the_m3tadata_1s_modified}`

### Weird File

`What could go wrong if we let Word documents run programs? (aka "in-the-clear"). Download file.`

First you must download the file which is `weird.docm`.

I then opened this file within Word. I got a security warning about Macros. So I then went to `View > Macros > View Macros`. This showed that there was a Macro name called `runpython`.

I clicked on this particular Macro and pressed `Edit` which opened up the python script. The script is supposed to print out what looks like a base64 string.

![weird1](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/WINWORD_HqyghgSrFS.png)

I took this string and ran it through the `Magic` recipie in CyberChef and was able to obtain the flag.

Flag: `picoCTF{m4cr0s_r_d4ng3r0us}`

### Matryoshka doll

`Matryoshka dolls are a set of wooden dolls of decreasing size placed one inside another. What's the final one? Image: this`

First you have to download the file which is `dolls.jpg`.

By the name of the file I thought that there may be many picture files embedded within other image files. So I looked at the `binwalk` help page and I saw that there was actually a 'matryoshka' flag which can be used with the `-M` flag.

I used `binwalk -e -M dolls.jpg` and then used the file explorer window to navigate down the tree until I got to the file `flag.txt` which contained the flag.

Flag: `picoCTF{336cf6d51c9d9774fd37196c1d7320ff}`

### Milkslap

`🥛`

There's a link: `http://mercury.picoctf.net:16940/`, which brings us to a web page. It interestingly shows a guy getting a cup of milk thrown at his face. When you move your mouse from right to left the video proceeds forward, and when you move the opposite way the video goes in reverse.

So what I did was right click on a frame and chose `View Background Image`. This showed a single file named `concat_v.png`, which was a concatenation of all the frames into one `.png`. I downloaded this to my desktop.

I then ran `zsteg -a concat_v.png` to extract any information from the file. The flag was shown in the output.

![milk](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/vmware_qd5GEaLkKM.png)

Flag: `picoCTF{imag3_m4n1pul4t10n_sl4p5}`

### tunn3l v1s10n

`We found this file. Recover the flag.`

First you must download the file which is `tunn3l_v1s10n`. Using `file` just reveals that it is data.

### Wireshark doo dooo do doo

`Can you find the flag? shark1.pcapng.`

First you must download the file which is: `shark1.pcapng`.

After looking through strings I couldn't find anything. So Then I went to: `File > Export Objects > HTTP`. Looking through this list I found a text/plain file. I downloaded this file and use `cat` to view the contents. It appears it's the flag but it must be decoded.
`Gur synt vf cvpbPGS{c33xno00_1_f33_h_qrnqorrs}`

Using the `ROT13` recipie in CyberChef I was able to retrieve the flag.

Flag: `picoCTF{p33kab00_1_s33_u_deadbeef}`

### Wireshark twoo twooo two twoo

`Can you find the flag? shark2.pcapng.`

First you must download the file which is: `shark2.pcapng`.

### Surfing the Waves

`While you're going through the FBI's servers, you stumble across their incredible taste in music. One main.wav you found is particularly interesting, see if you can find the flag!`

First you must download the file `main.wav`.

### MacroHard WeakEdge

`I've hidden a flag in this file. Can you find it? Forensics is fun.pptm`

First you must download the file `Forensics is fun.pptm`. I then renamed the file to `fun.pptm` to make it easier to work with in Linux.

I used `unzip fun.pptm` to break down the PowerPoint into its various different files that make it up. I ended up finding a file called `hidden` it was found in: `ppt > slideMasters`.

The content of the file appeared to be base64: `ZmxhZzogcGljb0NURntEMWRfdV9rbjB3X3BwdHNfcl96MXA1fQ`. So I threw this in the `Magic` recipie of CyberChef and I was able to retrieve the flag.

Flag: `picoCTF{D1d_u_kn0w_ppts_r_z1p5}`

### Trivial Flag Transfer Protocol

`Figure out how they moved the flag.`

First you must download the file `tftp.pcapng`. I then opened it with Wireshark.

I then went to: `File > Export Objects > TFTP`. There was a list of files which I then proceeded to download.

![tftp](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/vmware_5rQAjGOl75.png)

One of the files was called `program.deb` so I installed it using `sudo apt install ./program.deb`. Doing this revealed that the program was actually `steghide` which made sense because there were `.bmp` files.

There was a file called `instructions.txt` but when viewing it, it appeared to be ciphertext. So I took the ciphertext and used `https://www.quipqiup.com/` to decode it. It said: `t ftp doesnt encrypt our traffic so we must disguise our flag transfer figure out away to hide the flag and i will check back for the plan`. There was also a file called `plan` which had more ciphertext, so I did the same thing, it said: `i used the program and hid it with due diligence check out the photos`.

### Disk, disk, sleuth

`Use "srch_strings" from the sleuthkit and some terminal-fu to find a flag in this disk image: dds1-alpine.flag.img.gz`

First I downloaded the file and then I used `gunzip` to decompress the file. I then transferred the file to my Windows Desktop. I did this because I already had installed `Autopsy`, which is the GUI version of `Sleuthkit` and it has more features.

In `Autopsy` I let the program run for a while so it could analyze the image. I then ran a `Keyword Search` for "pico". One of the files that was shown to contain that string was `syslinux.cfg`. Looking at the contents of the file I was able to see the flag.

![disk](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/autopsy64_6YwS6HLCrs.png)

Flag: `picoCTF{f0r3ns1c4t0r_n30phyt3_a011c142}`

### Disk, disk, sleuth! II

`All we know is the file with the flag is named "down-at-the-bottom.txt"... Disk image: dds2-alpine.flag.img.gz`

First I downloaded the file and then I used `gunzip` to decompress the file. I then transferred the file to my Windows Desktop. I did this because I already had installed `Autopsy`, which is the GUI version of `Sleuthkit` and it has more features.

In `Autopsy` I let the program run for a while so it could analyze the image. I then navigated to: `Views > File Types > By Extension > Documents > Plain Text`. That is where I found the file `down-at-the-bottom.txt`. Within the file was some ASCII art of the flag.

![disk2](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/autopsy64_O3rvC6tcHg.png)

Flag: `picoCTF{f0r3ns1c4t0r_n0v1c3_0ba8d02d}`

## Web Exploitation

### GET aHEAD

`Find the flag being held on this server to get ahead of the competition http://mercury.picoctf.net:47967/`

I used the tool Burpsuite to find this flag. I used the FoxyProxy extentsion within FireFox to enable the proxy for Burpsuite. I found that when choosing Red on the page it resulted in `GET` requests but when choosing Blue it resulted in `POST` requests. So I sent one of the `POST` requests to repeater and I changed it to a `HEAD` request. In teh response I was able to find the flag.

![GET](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/vmware_uzCFS43ZEY.png)

Flag: `picoCTF{r3j3ct_th3_du4l1ty_cca66bd3}`

### Cookies

`Who doesn't love cookies? Try to figure out the best one. http://mercury.picoctf.net:27177/`

I used the tool Burpsuite to find this flag. I used the FoxyProxy extentsion within FireFox to enable the proxy for Burpsuite.

While viewing the cookies in Burpsuite I saw that I could increment the `name=` parameter by 1 and each time I did that the webpage would display a new message with a different cookie name.

I sent the request to `Repeater` within Burpsuite and I incremented the value until I got to `name=18` and that's when the flag was displayed.

![cookie](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/vmware_gqnV38IpXu.png)

Flag: `picoCTF{3v3ry1_l0v3s_c00k135_064663be}`

### Scavenger Hunt

`There is some interesting information hidden around this site http://mercury.picoctf.net:39491/. Can you find it?`

The first thing I did when I got to the website was look through the source code of the webpage. I was able to find the first porition of the flag within a HTML comment. `<!--Here's the first part of the flag: picoCTF{t -->`.

The second portion of the flag was looking at the CSS in `Style Editor`, it was found within `mycss.css` in a comment. `/* CSS makes the page look nice, and yes, it also has part of the flag. Here's part 2: h4ts_4_l0 */`.

When looking at the Javascript file `myjs.js`, there was a comment which said: `/* How can I keep Google from indexing my website? */`, this pointed to robots.txt. The contents of `http://mercury.picoctf.net:39491/robots.txt` was:

`User-agent: *`
`Disallow: /index.html`
`# Part 3: t_0f_pl4c`
`# I think this is an apache server... can you Access the next flag?`

A then found a word list of common apache directories here: `https://github.com/digination/dirbuster-ng/blob/master/wordlists/vulns/apache.txt`. I then took the list and used it within `dirbuster` to run against the website. `dirbuster` ended up finding the directory `/.htaccess/`. Going to: `http://mercury.picoctf.net:39491/.htaccess/` I was able to find fourth portion of the flag. `# Part 4: 3s_2_lO0k # I love making websites on my Mac, I can Store a lot of information there.`

!!!!! Still need the last part !!!!!

Flag: `picoCTF{th4ts_4_l0t_0f_pl4c3s_2_lO0k}`

### Some Assembly Required 1

`http://mercury.picoctf.net:26318/index.html`

Viewing the webpage there's a form that says `Enter flag`. Entering it a random string returns `Incorrect!`.

I then Looked at the `Network` tab in the Firefox webdeveloper tools. I saw that there was a `.js` file but also another file named `JIFxzHyW8W` which appeared to be a octet-stream. I was looking at the headers and I saw that it used a `GET` request for the filename `/JIFxzHyW8W`. So I went to the following link in the browser: `http://mercury.picoctf.net:26318/JIFxzHyW8W`.

Doing this brought up a dialog box to download the file, which I did. I then used `cat` to examine the contents of the file and at the very end was the flag. I then took this flag and entered it into the original form on the webpage and it returned `Correct!`.

Flag: `picoCTF{8857462f9e30faae4d037e5e25fee1ce}`

## Reverse Engineering

### Transformation

`I wonder what this really is...` `enc ''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])`

First you must download the file `enc`. Running `file` shows that it's a UTF-8 text. The code shown in the description looks like Python.

### keygenme-py

`keygenme-trial.py`

First I downloaded the file, then I used `cat` to examine the code.

It appears that the key to unlock the full version is actually the flag. Looking at the code most of the flag is hardcoded in, except 8 x's which are generated elsewhere.

```python
key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
key_part_dynamic1_trial = "xxxxxxxx"
key_part_static2_trial = "}"
key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial
```

There's a function called `check_key` which takes the flag and sees if it is the correct length and that each character is correct. There are 8 separate `hashlib` comparisons that are conducted, which must correspond to the 8 x's.

```python
if key[i] != hashlib.sha256(username_trial).hexdigest()[4]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[5]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[3]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[6]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[2]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[7]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[1]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[8]:
            return False
```

So I used a python3 interactive shell and ran each `hashlib` statement so I could see the output and thus find the missing part of the flag.

![key](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/vmware_fgOCu2LDzT.png)

The resulting values ended up being: `f911a486`.

Flag: `picoCTF{1n_7h3_|<3y_of_f911a486}`

### crackme-py

`crackme.py`

First I downloaded the file. Then I examined the code using `cat`. It appears that there may be an encoded flag:

```python
bezos_cc_secret = "A:4@r%uL`M-^M0c0AbcM-MFE0cdhb52g2N"
```

There's also a function `decode_secret(secret)` which is never called, and a dummy function called `choose_greatest()`. So I commented out the dummy function call and wrote a call to the decode function: `decode_secret(bezos_cc_secret)` at the end of the script. Doing this printed out the flag.

Flag: `picoCTF{1|\/|_4_p34|\|ut_4593da8a}`.

### ARMssembly 0

`What integer does this program print with arguments 182476535 and 3742084308? File: chall.S Flag format: picoCTF{XXXXXXXX} -> (hex, lowercase, no 0x, and 32 bits. ex. 5614267 would be picoCTF{0055aabb})`

I first downloaded the file which was `chall.S`. Using `file` I was able to determine it was assembler source. Looking into the code using `strings` I saw that the the type of assembly being used was `armv8-a`.

I then found this write up on Github showing how to compile and run ARMv8 in Linux commandline.
`https://github.com/joebobmiles/ARMv8ViaLinuxCommandline`. I followed the steps and compiled the assembly into an ELF file. I then ran it using: `./chall.elf 182476535 3742084308`. I was given the result of: `3742084308`.

I then took that value and used this converter: `https://cryptii.com/pipes/integer-encoder` to convert it to 32 bit hex format, then I submitted the flag!

Flag: `picoCTF{df0bacd4}`

### speeds and feeds

`There is something on my shop network running at mercury.picoctf.net:16524, but I can't tell what it is. Can you?`

Going to the website there's listed weird looking code where each line starts with a `G` and it looks like it's coordinates. Googlingn the first line of the file: `G17 G21 G40 G90 G64 P0.003 F50` makes references to "G Codes".

So I found an online G Code viewer at: `https://ncviewer.com/`. I took the code listed on the website and put it into a file called: `g_code.gcode`. I then uploaded that into this website and the flag was printed on the screen!

![speed](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/vmware_ncv5ndUnj3.png)

Flag: `picoCTF{num3r1cal_c0ntr0l_1395ffad}`

### Shop

`Best Stuff - Cheap Stuff, Buy Buy Buy... Store Instance: source. The shop is open for business at nc mercury.picoctf.net 42159.`

First I downloaded the source file called `source`. I ran `file` against it and found it was an ELF-32bit executable. I made the program executable using `chmod +x source`.

Running the program we're greated with the following menu:

```python
Welcome to the market!
=====================
You have 40 coins
        Item            Price   Count
(0) Quiet Quiches       10      12
(1) Average Apple       15      8
(2) Fruitful Flag       100     1
(3) Sell an Item
(4) Exit
Choose an option: 
```

Choosing `2` we're asked how many to buy. Inputting `1` we are returned the message `Not enough money`.

So I tried doing the same thing except this time I put an `a`. The program then continued to ask me `How many do you want to buy?`. So I wanted to see what else I could input and get away with. I put that I wanted to buy `-1000`. This ended up making my balance 10,040 coins instead of just 40.

I then went back to option: `(2) Fruitful Flag` and requested to buy 1 flag and I got an error stating there was no `flag.txt` which makes sense. Now I have to connect via `nc` and try the same methodology on the online version.

The same method ended up working and I was shown an encoded flag which seemed to be in decimal.

![shop](https://github.com/Steven-Howe/picoCTF2021/blob/main/picoCTF_screenshots/vmware_JKGBJW9dNR.png)

Decoding the flag in CyberChef using the recipie `From Decimal` I was able to retrieve the plaintext flag.

Flag: `picoCTF{b4d_brogrammer_797b292c}`

## Binary Exploitation

### What's your input?

`We'd like to get your input on a couple things. Think you can answer my questions correctly? in.py nc mercury.picoctf.net 39137.`

First I downloaded the sample file which was `in.py`. The program first asks `what's your favorite number?` which really isn't of any consequence. The second question asks `What's the best city to visit?`. The variable `res` must equal `city` in order to get the flag.

I then used: `nc mercury.picoctf.net 39137` to connect to the serivce. I answered the first question with `2018`. I then answered the second question by entering `city`. This led to the flag being printed out.

Flag: `picoCTF{v4lua4bl3_1npu7_8433797}`
