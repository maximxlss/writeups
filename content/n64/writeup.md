---
title: Mips (Akasec CTF 2024; rev)
date: 2024-06-07
---
> Author: miyako
> check out my 16 star pb (note: you need ares to run the rom properly)

### N64 chall??
We are given a file called [`chall.z64`](./chall.z64). With a quick google search, you can find out that this is the file extension for Nintendo 64 ROMs, and that Ares, mentioned in the chall's description, is an emulator for N64. The console is based on MIPS architecture, whose name is present in the chall's title. Next step is to [download Ares](https://ares-emu.net/download) and set up the keymap (Settings > Input).

Let's run[^1] the ROM:
![[Pasted image 20240607234838.png]]
Not too confusing, the objective is clear. You can experiment and see that the key is 30 inputs long and consists of keys `["L", "U", "R", "D", "CL", "CU", "CR", "CD", "B", "A", "LR", "RR", "Z"]`. The natural next step is to dissect the binary. Let's try Ghidra.
### There is a Ghidra plugin for everything
Obviously there is a [plugin](https://github.com/zeroKilo/N64LoaderWV) for Ghidra. Download it from [here](https://github.com/zeroKilo/N64LoaderWV/files/14229054/N64LoaderWV.zip) and install `dist/ghidra_11.0.1_PUBLIC_20240210_N64LoaderWV.zip` (File > Install Extensions > Plus icon).
The decomplication is horrific, but the trick is to skip straight to the important stuff by finding the place where the string "wrong" is used (which we see when we input a wrong password). Go to the Defined Strings view, find "wrong" and open the function that refers to it:
![[Pasted image 20240608000404.png]]
Here is obviously the point it decides if your key is wrong or not. If you look into `FUN_80010ed8`, it seems similar to `strcmp`, even. So let's look at what it compares. Seemingly, it's the data at addresses `0xFFFFFFFF800280b0` and `0xFFFFFFFF800270c8`. Those addresses look really weird for N64. The way you can get around that is trial and error, with the help from Ares' toolset.
### No debugger needed
The Ares emulator (like most old console emulators) supports viewing and modifying memory contents of the virtual console. To do that, go to Tools > Memory (see how the addresses are small?). There are multiple views, corresponding to ROM, RAM, etc. You can go to the Memory Map in Ghidra to see, that the adresses are, umm, aren't even in any segment??? What is going on?
Actually, I still have no idea, probably something weird about the plugin. But the thing is, Ghidra is confused. If you just try to infer what address you _actually_ need to check, you will end up with `0x280b0` and `0x270c8`, which is in multiple ways weird, but works.
It's not hard to see that `0x280b0` contains the input string (encoded) and `0x270c8` contains the expected string. You can input all the keys and see what bytes they are encoded into, after which you can decode the password:
```Python
values = bytes.fromhex("05020901140a190f07040b0c03") # copied from input memory
# after entering the corresponding buttons
buttons = ["L", "U", "R", "D", "CL", "CU", "CR", "CD", "B", "A", "LR", "RR", "Z"]

transl = {}
for i in range(len(values)):
    transl[values[i]] = buttons[i]

cipher = bytes.fromhex("030c0a0a0a0a1401010a04071909010a02050907020c09070a0c0a030903")
decoded = []
for i, c in enumerate(cipher):
    if c not in transl:
        print(i, c, "noo")
        continue
    decoded.append(transl[c])

print("".join(decoded))
```
Now go to the provided netcat endpoint to submit the password and get the flag.

[^1]:If you are on Windows and missing `ResampleDmo.dll`, run `DISM /Online /Add-Capability /CapabilityName:Media.MediaFeaturePack` in an elevated shell and reboot, [source](https://www.reddit.com/r/WindowsHelp/comments/qk4ot7/rtkngui64exe_system_error_resampledmodll_was_not/).