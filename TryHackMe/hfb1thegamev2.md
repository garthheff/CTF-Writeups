# The Game v2

Premium room

Practice your Game Hacking skills.

Room: https://tryhackme.com/room/hfb1thegamev2

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/hfb1thegamev2.md

-------------------

# TryHackMe - The Game v2

## Overview

The challenge provides a Windows game binary and a `.pck` file.  
The game is built with Godot, so the main goal is to recover the project files and inspect the assets/scripts.

## Files

```bash
file TetrixFinal.exe
file TetrixFinal.pck
````

The `.exe` is a Windows PE executable, and the `.pck` is the Godot pack file containing the project resources.

## Recovering the Godot Project

Download GDRETools:

```bash
curl -s https://api.github.com/repos/GDRETools/gdsdecomp/releases/latest | grep browser_download_url
wget https://github.com/GDRETools/gdsdecomp/releases/download/v2.5.0/GDRE_tools-v2.5.0-linux.zip
unzip GDRE_tools-v2.5.0-linux.zip
chmod +x gdre_tools.x86_64
```

Launch GDRETools:

```bash
./gdre_tools.x86_64 --main-pack gdre_tools.pck
```

In the GUI:

1. Go to `RE Tools`
2. Select `Recover Project`
3. Open `TetrixFinal.pck`
4. Choose an output folder
5. Select `Full Recovery`
6. Click `Extract`

## Reviewing the Recovered Project

After extraction:

```bash
cd ~/Desktop/Tetrix
find . -type f | sort
```

Recovered files included:

```text
Board.gd
GUI.gd
Utils.gd
sol.gd
sol.jpg
blocks/*.gd
```

At this point, the project has been successfully recovered and decompiled.

## Finding the Flag

Search through the recovered files:

```bash
grep -RniE "THM|flag|score|secret|win|points|sol" .
```

The file `sol.jpg` stood out as a likely solution image.

Opening `sol.jpg` revealed the flag visually inside the image.

## Flag

```text
THM{MEMORY_CAN_CHANGE_*****}
```

## Notes

A Windows machine is not required.
The challenge can be solved fully on Linux by recovering the Godot project and inspecting the recovered assets.


