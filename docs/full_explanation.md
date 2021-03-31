# FX991ES Vulnerability Full Explanation

## Explanation

Before understanding the vuln and how we use it, we need to understand a bit about the calculator.

The basic memory map that we need to know is as followed:
* `8000h` - start of ram
* `8154h` - input buffer (100 bytes)
* `81b8h` - backlog buffer (100 bytes)
* `821ch` - random seed (8 bytes)
* `821ch` - counter (2 bytes)
* `8E00h` - end of ram

The expression you input in the calculator is first saved in the input buffer, once you either press calculate or AC or 
alike the expression is copied from the input buffer, into the backlog buffer as follows:

```c
strcpy(0x81b8, 0x8154)
```

Normally this is not a problem because the calculator ensures that the input buffer is always null terminated, so it will 
not overflow, but our vulnerability allows us to overwrite that NULL terminator of the input buffer.

If we overwrite the null terminator (and assume that there are no NULL terminators in the input buffer) we are going to 
essentially repeat the 100 bytes of memory until the end of ram:

1. the copy starts at the input buffer copying it to the backlog buffer
2. after the 100 bytes we continue into the backlog buffer (because it is directly after the input buffer) because there 
   is no null terminator, it will continue copying forward
3. this is continued until the end of ram because we don't give it any null terminators, fortunately for us the end of 
   ram has 0s, so we will stop copying there

If we only override the input buffer with our overflow it gives us 91 controllable bytes, and the first bytes have to be 
something special so we will trigger the overflow, to get around this we can use the backlog logic to get 100 bytes in
the input buffer.

1. first fill the input buffer, that means entering 91 more bytes in addition to the basic overflow string
2. now that we are in the backlog buffer, we can fill it up with 100 bytes
3. once we are done we will press AC, that will clear the input buffer
4. now we can press `◄` in order to copy the backlog buffer into the input buffer*
5. now we can press `=`, that will copy the input buffer (which is filled with 100 bytes with no null terminator)  and 
   cause the overflow that we talked about before

* This also uses strcpy, so you may ask, why does this not copy everything to the end? the reason is actually simple, 
  the seed has NULL at its highest byte (we are little endian). To make sure that it actually does have NULL byte we do
  a full reset, which clears the memory of the calculator.

So now we have a primitive to overwrite all of the ram from the input buffer with a specific pattern of 100 bytes.

If we look at the initial stack pointer (offset 0 of the rom) we can see that it starts at the end of ram, this means 
that we can override the stack with our data, which means ROP!

But wait, if we can override he return address, why not jump to the stack? The reason is actually quite simple, if you 
read about the architecture of the calculator you will see that the first segment of memory is different for code and 
data, because the RAM is mapped at the first segment we can't actually jump to it, because there is just more code where
the RAM is. And even tho the second segment and forward is shared between code and data, it is not actually useful because 
there is nothing that is writable at these positions, it is just more ROM.

## Basic overflow

So now that you understand how we are going to use the overflow, how do we actually get to it?

TODO: Figure exactly why this happens

1. Start by entering LineIO mode - `[SHIFT] [MODE/SETUP] 2`
    * this allows to enter directly the values we want without needing to worry about order in the MthIO mode
2. Enter the following formula `X = [SHIFT] [logab] X , 1 , x10^ 9`
3. Start the calculation by entering `[CALC] =` and stop it with `[AC]`
4. Now replace the last parameter with 2 (`[DEL] [DEL] [DEL] 2`)
5. Start calculation with `[CALC] =`, you should get and error
6. now when you will press `[LEFT]` your cursor should be at the start of the expression, if you press anything you 
   will see that nothing changes, that is because you are on the null terminator :) 

See [Input Format](input_format.md) if you don't understand what to press

## Full flow

So once you know the background this is the full flow:

1. Cause the cursor to be on the null terminator (with the basic overflow)
2. Enter 91 chars (easiest is to press `1234567890` 9 times and then another char one time)
    * you know you got to the last char when you see on your right the first char of the overflow (should be `X`)
3. Now enter 100 bytes of the rop hack string
    * Should be 
