# Loader 

The job of the loader is to be small but have a simpler input method than the exploit hackstring.

For more explanation about the different gadges see `gadgets.md`.

## Input Chars

To make it easier to load more advanced rops after the initial exploit we are going to need to be able to enter any byte we want without needing to use special characters, with hopefully using as less key presses as possible in the process.

To do so we are going to take the key map of the calculator (see `key_map.md`) and we are going to search for two things:
* keys that require one key-press for input
* keys whos key code have all of the hex chars (0-f)

that way we can get two keys, remove the top nibble, and append them to each other to create any byte that we want!

## Pseudo code

First of all the pseudo code of the loader itself

```
start:
    set lr 

    ; set the starting place
    ER12 = <program start address>
    EA = ER12, [EA+] = QR0, [EA+] = ER8

get_key_loop:

;
; we are going to repeat this twice so we enter two 
; bytes at a time instead of one byte at a time
;
.repeat 2
    ; get the key and get its lower 4 bits
    r0 = getkeycode()
    r0 &= 0xf
    r2 = r0

    ; get the second key and get its upper 
    ; 4 bits
    r0 = getkeycode()
    
    ; we only care about the r0, and we trash r1
    r1 &= 0xF; r0 <<= 4, r1 |= r0, [0x8100] = r1

    ; combine these using the power of addition
    er0 += er2

    ; do the store
    r2 = r0
    [EA+] = R2
.end

    goto get_key_loop
```

## Explanation 

First of all we are going to setup the link register so we can use gadgets that have `RT` at their end.

```
set lr
```

Next we are going to set the EA register, that will save us from needing to keep track of another variable and thus will save space (the only other gadget for storing is `ST R2, [ER0]` and since we use `ER0` extensively we can't use that one efficiently).

```
ER12 = RAM_START
EA = ER12, [EA+] = QR0, [EA+] = ER8
```

next we are starting the `getkeycode_loop`, in short it is going to take two chars at a time and will turn them into a single byte. See `Input Chars` for more info about this.

First get the first key and take the lower part of its value, this is going to serve as the lower nibble for the final byte, save it in r2 for later use
```
r0 = getkeycode()
r0 &= 0xf
r2 = r0
```

Then get the next nibble, we are going to already set it up for being the upper nibble, we use that weird gadget because the better gadgets can't be entered from the exploit
```
r0 = getkeycode()
r1 &= 0xF; r0 <<= 4, r1 |= r0, [0x8100] = r1
```

Next we are going to add these toghether, we work on `ER0` and `ER2` but that is fine because we still get the important result. This can work instead of `OR` because we make sure no bits will overlap, making the `ADD` essentially an `OR` (we don't have an `OR R0, R2` or `OR R2, R0`).
```
er0 += er2
```

Then we are going to do the store, we do it before the comparison because it is easier and doesn't really hurt us in any way.
```
r2 = r0
[EA+] = R2
```

And we do all of the above things twice, the reason is because in order to actually exit from the loader we are going to actually **override** the loader itself with a small copy that has a single difference, instead of having a `goto get_key_loop`, it is going to have a `goto new_program`. To do so we need to override the `goto` before it arrives again, and for that we are going to do two bytes, and then loop around, so the last two bytes loaded by the loader are going to be the actual position the new program is going to be loaded at.
