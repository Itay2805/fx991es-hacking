# Memory Map

## Code space

This is the mapping as seen when the cpu fetches code 

### Segment 0

This is fully mapped to the first 64k of the ROM

### Segment 1

This is mapped to the last 

## Data space

This is the mapping as seen when accessing memory using the L/ST instructions

### Segment 0

* `0000h` - `7FFFh`: Rom window (1:1)
* `8000h` - `8DFFh`: RAM (3584 bytes)
* `8E00h` - `EFFFh`: Unused, read as zero
* `F000h` - `FFFFh`: SFR (Special Function Register)

### Segment 1

The same as the segment 1 of code

### Segment 8

The same as the segment 0 of code, this is so the firmware can still access
the whole ROM without the ROM window

## SFR Mapping

As said these are in segment 0 and start at `0F000h`.

The following are the known ones:

* TODO: this 