# Gadgets 

When creating hack strings there are two main types of gadgets you will be looking for:
* gadgets that can be entered using the key map of the calculator 
* gadgets that can do advanced things (but will be loaded by the loader)

Before reading this page you should have some kind of understanding on how rops work and their general idea.

Note, this won't go over the simplest of gadgets (setting registers via `POP`, simple `ST`/`L` gadgets and so on), but it will go over the more advanced gadgets or the gadgets that require some extra understanding and are worth explaning in here

## Gadgets for exploits 

Note that these gadgets can of course be used from any context, but we note them here because they can specifically be used from the exploit without a problem.

### Setting the link register (LR)

In order to use any gadgets that end with `RT` and not with `POP PC` we need to somehow have the `LR`/`LCSR` register point to an address that will do a `POP PC` right after it (so we can continue execution). Luckily for us there is such a place:

```
11D90                 BL      ER12
11D92                 POP     PC
```

This just requires us to set ER12 (which we can with a `POP ER12` gadget).

Of course we need to set ER12 to some value, for simplicity we can just set it to some address of a `POP PC`, and that would work, but we could save some space and instead have `ER12` be the next gadget, but that requires that the next gadget be in the same `CSR` as this gadget (aka segment 1).

Once we have setup the `LR` register we can use alot more gadgets.

### Setting EA register

One of the things this arch has is the `EA` register, which has a nice addressing mode which increments `EA` automatically, thing is that for that we need to load EA to something using the `LEA` instruction, bad news is that there 
are almost no gadgets that actually do that directly... 

instead we found the following gadget:
```
16058                 LEA [ER12]
1605a                 ST QR0, [EA+]
1605c                 ST ER8, [EA+]
1605e                 RT 
```

this gadget essentially `ER12` to the `EA` register, and then stores 10 bytes from the given registers, so what we need to do is load to `ER12` the address we want `- 10`, of course that would not work for any case so if we can loading the first values into QR0 and ER8 would be better (of course we don't have space for that from the exploit).

### Unconditional jumps

Unconditional jump is an important gadget for the loader (as you can read in the `loader.md`), to do one we simply need to set the `SP` to point back to the top of the stack.

For that we can use the following primitive:

```
2c70                 MOV SP, ER14
2c72                 POP ER14
2c74                 POP PC
```

Of course that requires us to set `ER14` to a valid value but aas you can see we have such a gadget in the same gadget.

This does require having some extra dummy data for the `POP ER14` but not alot we can do about that...

## Gadgets for loaded programs

These are general helpful gadgets to do some of the more advanced stuff, these might require inputting bytes which are impossible to input using the exploit itself.

The most important primitives in here are the ones that will allow us to gain conditional jumps, once we have that we can do basically anything :)

### Value as boolean

The first gadget we need for doing conditional jumps is a way to truncate a value to either 0 or 1, to do so we have the following gadget:
```
8ac4                 CMP R1, R0
8ac6                 SUBC R0, R0
8ac8                 NEG R0
8aca                 RT 
```

This will take a value in `R0`, and given that `R1` is zero (we can set it to zero), it will return 0 if `R0` had a zero value, and 1 if `R0` had any value (value returned in `ER0`/`R0`).

You will see why that is important later on.

### Indirect jump

For doing an indirect jump we need to somehow override the SP value with a non-constant, the problem is that there is no gadget to more another register into `ER14` easily, and the only moves to `SP` are made by `ER14`, instead we are going to develop another primitive with a few gadgets to override a value on the stack at runtime:

First of all we need to get the value of the stack pointer into a good register, the following gadget will do:
```
4588                 MOV ER0, SP
458a                 RT 
```

Next we need to add an offset to ER0, we can use the following gadgets:

TODO: fix this to use ER4/ER0

Then once we added the values we have the position on the stack where the variable should be, so just write it:
```
132f2                 ST ER2, [ER0]
132f4                 RT 
```

And since `ER2` is a good register that we can manipulate and read from memory it allows us to do very strong indirect jumps.

Once we can manipulate the stack it is just a matter of using again the jump primitives just that this time we can override the `POP ER14` value at runtime

### Loading from a table of words

Next in the list of ingridients we need for conditional jump, we are going to need to load from a table (you will see why soon).

We actually have a perfect gadget for that:
```
134b4                 ADD ER0, ER0
134b6                 ADD ER2, ER0
134b8                 L ER0, [ER2]
134ba                 MOV R2, #9
134bc                 RT 
```

This will simply multiply the index by itself (aka by 2, making it an index into a list of words). Then it is going to add some base to it (from `ER2`), and then it will load it 

There is another version of this that loads a value to `ER8` instead but it does not override the `R2` register:
```
13480                 ADD ER0, ER0
13482                 ADD ER0, ER2
13484                 L ER8, [ER0]
13486                 RT 
```

And since you can move `ER8` to `ER0` it can give the same result in two gadgets instead of one.

### Conditional jump (if not zero)

So now we have everything we need! The way we are going to do a conditional jump is with a table!

1. First we are going to call the first gadget to take `R0` and turn it into either 0 or 1
2. We are going to use that value as an index to a jump table, 0 will be jumped to if the value was 0, 1 otherwise.
3. then we can use our indirect jump to take the loaded value from table and will jump to it!

And that is it, with a bit of gadgets we can do indirect jumps in our code, which unlock a bunch of new possibilities :)
