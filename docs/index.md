

# Building a class-dump in <del>2019</del> 2020

## This is being actively worked on, this message will disappear when I am happy with the writeup

Building out a "class-dump"-like introspection tool for Apple platforms has changed considerably since the original [class-dump](http://stevenygard.com/projects/class-dump/) came out. Learning these new (and old) technologies can be quite intimidating due to the steep learning curve and somewhat hard to find documentation.

This article *attempts* to explain the complete process of programmatically inspecting a [Mach-O](https://en.wikipedia.org/wiki/Mach-O) (Apple) binary to display the compiled Swift types and Objective-C classes by discussing the following:

* [I. Mach-O File Format](#apples_mach-o_file_format)
    * [1.1 The Mach-O Header](#mach_o_header)
    * [1.2 Mach-O Load Commands](#load_commands)
    * [1.3 File Offsets => Virtual Addresses and back](#file_offsets_to_virtual_addresses)
    * [1.4 Virtual Addresses at Runtime](#virtual_address_at_runtime)
    * [1.5 PIE](#pie)
* [II. The Symbol Table](#the_symbol_table)
    * [2.1 Symbol Table Overview](#nm_sym)    
    * [2.2 Symbol Table Implementation](#symbol_table_implementation)    
    * [2.3 nlist_64 Overview](#nlist_64_overview)
    * [2.4 Symbol Table Stripping](#symbol_table_stripping)
* [III. Objective-C](#objective_c)
    * [3.1 Objective-C Class List](#objc_class_list)
    * [3.2 Objc4](#objc4)
    * [3.3 How to Disappoint Swift Developers](#how_to_disappoint_swift_developers)
    * [3.4 The bits value revisited (class_ro_t vs class_rw_t)](#how_to_disappoint_swift_developers)
    * [3.5 The class_ro_t struct](#the_class_ro_t_struct)
* [IV. DYLD Opcodes and Binding](#dyld_opcodes_and_binding)
* [V. Swift](#swift)
    * Swift Types Layout
    * [5.2 Swift Types Layout]()
* [VI. ARM64e](#arm64e)


This writeup takes its sweet time explaining things, but there's a lot of concepts to go through. If you're brand new to this stuff, I'd recommend going through the sections *in chunks over several days* and **do the experiments**. This is a loooooooong writeup, but if you can get through this whole thing, you'll have a very good understanding of how a lot of internals work. Yay...

If you know most of this stuff, I'd recommend just jumping to the appropriate section that you need to learn.

All you script/plugin writers for Ghidra, Frida, Hopper, IDA, jtool, & friends should *carefully* read the Swift parts because I have recommendations for y'all to take your tools to the next level when resymbolicating stripped Swift symbols. 

<p align="center">
<img src="https://media.giphy.com/media/8YmZ14DOpivXMuckSI/giphy.gif" alt="And here we go">
</p>

---
<a name="apples_mach-o_file_format"></a>
## I. Mach-O File Format
---

The Mach-O file format is the "table of contents" and layout found right at the beginning of every Mach-O (read Apple) **image**. An image is any compiled, executable code including (but not limited to) executables, frameworks, dylibs, etc. Understanding the Mach-O format is great if you want to know where stuff is located on disk and where it will be when loaded into memory.

There are many great sources out there that already cover this topic well. 

* <a href="https://lowlevelbits.org/parsing-mach-o-files/" target="_blank">PARSING MACH-O FILES</a>
* <a href="https://github.com/aidansteele/osx-abi-macho-file-format-reference">Mirror of OS X ABI Mach-O File Format Reference</a>
* <a href="https://adrummond.net/posts/macho" target="_blank">Inside a Hello World executable on OS X</a>

And if you want to pay money for some Mach-O tutorials...

* <a href="https://store.raywenderlich.com/products/advanced-apple-debugging-and-reverse-engineering" target="_blank">Advanced Apple Debugging and Reverse Engineering, Chp 18, 19</a> (written by yours truly)
* <a href="http://www.newosxbook.com/index.php" target="_blank">MacOS and iOS Internals, Volume I: User Mode, Chp 5</a>


But this stuff won't stick unless you play around with it and do the experiments. Time to get your hands dirty.

---
<a name="mach_o_header"></a>
## 1.1 The Mach-O Header
---

In the file `<mach-o/loader.h>`, there exists a C struct called **`mach_header_64`** that is the beginning to all 64-bit compiled Apple images (well, sorta, it actually depends on some things like FAT files, 32-bit architecture, but don't think about that now). 

> **Note:** When referring to C System headers on your OS X machine, you can usually resolve the header location to the following Terminal command: `echo $(xcrun --show-sdk-path)/usr/include`. This resolves to the base directory search path for C system headers. The resolved filepath of loader.h can be viewed via: `cat $(xcrun --show-sdk-path)/usr/include/mach-o/loader.h | less -R`

Looking at the `mach_header_64` struct, it contains the following:

```c
struct mach_header_64 {
        uint32_t        magic;          /* mach magic number identifier */
        cpu_type_t      cputype;        /* cpu specifier */
        cpu_subtype_t   cpusubtype;     /* machine specifier */
        uint32_t        filetype;       /* type of file */
        uint32_t        ncmds;          /* number of load commands */
        uint32_t        sizeofcmds;     /* the size of all the load commands */
        uint32_t        flags;          /* flags */
        uint32_t        reserved;       /* reserved */
};
```

Cross reference this with any *compiled* executable. I'll pick **grep**, feel free to pick anything else:

```bash
lolgrep:~$ xxd -g 4 -e $(which grep) | head -2
```

The `xxd` command will dump the raw data of an executable to `stdout`. The `-g 4` says to group all the values into 4 bytes, which is perfect since each member in the `mach_header_64` struct is a 4 byte value. The `-e` option says to format the output in little-endian byte order (i.e. anything after a mac PowerPC).

>**Note:** Now's as good as time as any to mention type sizes in a programming language. An `int` in C on a 64 bit system will (*typically*) take up 32 bits or 4 bytes of storage. An `Int` in Swift will take up 64 bits or 8 bytes of storage. A pointer *to any type of a value* will take up the full 64 bits in size in both languages. In `Swift`, you can use the `MemoryLayout` type to verify size. In the C language family, use the `sizeof` function to determine the size of a type. Check out [this Swift link](https://swiftunboxed.com/internals/size-stride-alignment/) or [this generic languages link](https://gankra.github.io/blah/rust-layouts-and-abis/#alignment) for a good writeup that dives further in to this.

After executing the above Terminal command, this produces the following output on my machine:

```none
00000000: feedfacf 01000007 80000003 00000002  ................
00000010: 00000014 00000798 00200085 00000000  .......... .....
```

Going through the `mach_header_64` struct members:

* Cross referencing the `xxd` output with the `mach_header_64` found in `<mach-o/loader.h>`, the `0xfeedfacf` means it's a 64-bit compiled image (`MH_MAGIC_64`).
* The `0x01000007` can be resolved via `<mach/machine.h>` to realize it's compiled for a `CPU_TYPE_X86_64` type of machine.
* The `0x80000003` can be resolved via the same `<mach/machine.h>` header by OR'ing `CPU_SUBTYPE_X86_ALL|CPU_SUBTYPE_LIB64`.
* The `0x00000002` value is given by the `MH_EXECUTE`, meaning it's an executable (and not a library or something else).
* Following the `filetype` in the struct is the `ncmds`, with 20 **load commands** (0x00000014 == 20)

If you're new to this stuff, check out the `<mach/machine.h>` header to make sure I'm telling the truth. I'll let you figure the remaining struct members out yourself 👍

You can view the `mach_header_64` in an alternative way by running `otool -h` to view the Mach-O header:

```bash
lolgrep:~$ otool -h $(which grep)
```

This produces the following on my machine:

```none
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
 0xfeedfacf 16777223          3  0x80           2    20       1944 0x00200085
```

Keep an eye on that `ncmds` with the value 20; this is what's going to be discussed next.

---
<a name="load_commands"></a>
## 1.2 Mach-O Load Commands
--- 

It's these load commands (whose count is given by the `ncmds` from the `mach_header_64`) that can be interesting when exploring a compiled executable.

Each load command begins with a **`LC_`** and whose description/usage is given in `<mach-o/loader.h>`

Use `otool`'s `-l` option with `grep` to display all the load commands in `grep`:


```bash
lolgrep:~$ otool -l $(which grep) | grep LC_ 
      cmd LC_SEGMENT_64
      cmd LC_SEGMENT_64
      cmd LC_SEGMENT_64
      cmd LC_SEGMENT_64
      cmd LC_SEGMENT_64
            cmd LC_DYLD_INFO_ONLY
     cmd LC_SYMTAB
            cmd LC_DYSYMTAB
          cmd LC_LOAD_DYLINKER
     cmd LC_UUID
       cmd LC_BUILD_VERSION
      cmd LC_SOURCE_VERSION
       cmd LC_MAIN
          cmd LC_LOAD_DYLIB
          cmd LC_LOAD_DYLIB
          cmd LC_LOAD_DYLIB
          cmd LC_LOAD_DYLIB
      cmd LC_FUNCTION_STARTS
      cmd LC_DATA_IN_CODE
      cmd LC_CODE_SIGNATURE
```

Make sure the `ncmds` count (20 for my version of `grep`) from the `mach_header_64` matches the load command count... 

```bash
lolgrep:~$ otool -l $(which grep) | grep LC_ | wc -l
20
```

Each of these commands does something specific. For example `LC_LOAD_DYLIB` is an instruction to load a framework (like `Cocoa`, or `UIKit` into the process's address space). The `LC_MAIN` specifies the address to start the `main` function to the program. Exhaustively describing all the load commands could be a bit boring to most, so check out the `<mach-o/loader.h>` or other writeups if you're interested in learning more about load commands.

Now that you have a overview of the load commands, remove the `grep` filtering and display the full output of `otool -l`:

```bash
lolgrep:~$ otool -l $(which grep)
```

`otool -l` produces *a lot* of output, but focus on the initial `LC_SEGMENT_64` load commands closer to the beginning...

When exploring memory and the load commands, different areas of memory are grouped together. These Mach-O groupings are called **segments**. Segments will have different memory permissions. 

Execute the following for your Terminal command:


```bash 
lolgrep:~$ otool -l $(which grep) | grep LC_SEGMENT -A10
```

The output will display the Mach-O segments contained in `grep`. This will look something like this...

```none
      cmd LC_SEGMENT_64
  cmdsize 72
  segname __PAGEZERO
   vmaddr 0x0000000000000000
   vmsize 0x0000000100000000
  fileoff 0
 filesize 0
  maxprot 0x00000000
 initprot 0x00000000
   nsects 0
    flags 0x0
--
      cmd LC_SEGMENT_64
  cmdsize 632
  segname __TEXT
   vmaddr 0x0000000100000000
   vmsize 0x0000000000004000
  fileoff 0
 filesize 16384
  maxprot 0x00000005
 initprot 0x00000005
   nsects 7
    flags 0x0
--
...
```

There's a Mach-O segment called **`__PAGEZERO`** (given by the **`segname`** member), which when loaded into memory, has no memory permissions (see `maxprot`, and `initprot`). That means you can't read, write, nor execute anything that resides in this memory segment.  Hitting this memory is what happens when you fack up a pointer in C or dereference an implicitly unwrapped optional in Swift... *it's a dead zone in memory that's designed to catch implicitly unwrapped (`!`)/`nil`/`NULL`/`nullptr` dereference bugs in your code by killing the process*.

Below the `__PAGEZERO` segment, there's the `__TEXT` segment. This segment has readable and executable permissions determined from the **`initprot`** value of **0x00000005**. How can one translate the value 5 to mean readable and writable? 

Think of this 5 value in bits...

```none
exeuctable writeable readable
1          0         1
```

The value 5 is `0b101` in binary, meaning everything except writable.

The next interesting part is the `nsects` value immediately below the `initprot` field. Inside a Mach-O Segment, there can be 0 or more "subcomponents" called **sections**. These sections group certain parts of functionality in an executable. In the above example, inside the `__TEXT` segment, there are 7 sections for `grep`.

Use `grep` to only show the Mach-O sections in `grep`...

```bash
lolgrep:~$ otool -l $(which grep) | grep __TEXT -B2 -A9
      cmd LC_SEGMENT_64
  cmdsize 632
  segname __TEXT
   vmaddr 0x0000000100000000
   vmsize 0x0000000000004000
  fileoff 0
 filesize 16384
  maxprot 0x00000005
 initprot 0x00000005
   nsects 7
    flags 0x0
Section
--
--
Section
  sectname __text
   segname __TEXT
      addr 0x0000000100000c50
      size 0x00000000000028fc
    offset 3152
     align 2^4 (16)
    reloff 0
    nreloc 0
     flags 0x80000400
 reserved1 0
 reserved2 0
--
--
Section
  sectname __stubs
   segname __TEXT
      addr 0x000000010000354c
      size 0x0000000000000192
    offset 13644
     align 2^1 (2)
    reloff 0
    nreloc 0
...
```

From the above output, the first section inside the `__TEXT` segment is a section (confusingly) called `__text`. It's this section where compiled code resides (unless someone is doing something sneaky).

>**Note:** You'll often see both the segment and section grouped together via a period to specify the exact Mach-O location. For example, using the above paragraph, I could also say all compiled code resides in the `__TEXT.__text` section. Most tools out there use this methodology.

There are many, many interesting Mach-O sections. One could write a novel on just this topic. Again, check out the Mach-O links above to learn more about the different types of Mach-O sections. 

---
<a name="file_offsets_to_virtual_addresses"></a>
## 1.3 File Offsets => Virtual Addresses (and back)
---

The Mach-O segment/section load command info provide a translation into the virtual address of stuff loaded into memory and to the file offsets on disk for an image.

Consider the following C code (if you're new to this stuff, *code this out with me*):

Navigate to your `/tmp` directory:

```bash
lolgrep:~$ cd /tmp
lolgrep:/tmp$
```

Create **ex.c** with the following code:

```c
int SomeGlobalInt = 8;
int SecondGlobalInt = 7;
int main() {
  return 0;
}
```

Compile ex.c: 

```bash
lolgrep:/tmp$ clang ex.c -o ex
```

...then query the `*GlobalInt` integer symbols using the `nm` tool (which displays symbol table information, more on that later)

```bash
lolgrep:/tmp$ nm -m ex | grep GlobalInt
0000000100001004 (__DATA,__data) external _SecondGlobalInt
0000000100001000 (__DATA,__data) external _SomeGlobalInt
```

You'll (hopefully) see the global integer symbols in the output.

The `-m` option of the `nm` command displays the Mach-O section when printing *locally* implemented symbols in the symbol table. For *external* symbols, the `-m` option will display the library the symbol is located from. This will be discussed in much more detail below.

From the output, these global integers are located in the Mach-O `__DATA` segment inside the `__data` section, starting at virtual address `0x000000100001000` (`_SomeGlobalInt`) and `0x00000100001004` (`_SecondGlobalInt`).

One can translate these virtual addresses to the image file offset by consulting the Mach-O section load commands and hunting for the `__DATA.__data` Mach-O section.

```bash
lolgrep:/tmp$ otool -l ex | grep __data -A10
  sectname __data
   segname __DATA
      addr 0x0000000100001000
      size 0x0000000000000008
    offset 4096
     align 2^2 (4)
    reloff 0
    nreloc 0
     flags 0x00000000
 reserved1 0
 reserved2 0
 ```

The `size` member indicates the size of the `__DATA.__data` section (which is 8 bytes due to the 2 4 byte C `int`s). The virtual address of the `__DATA.__data` section is at `0x0000000100001000`. The offset on disk in the executable to the `__DATA.__data` section is at `4096`. 

Verify this with `xxd` again by dumping the raw bytes at offset **4096** (or equivalent for your compilation):

```bash
lolgrep:/tmp$ xxd -g 4 -e -s 4096 -c 8 ex
00001000: 00000008 00000007                    ........
```

Breaking the options down:
* `-g 4`   : group into 4 bytes
* `-e`     : little endian mode
* `-s 4096`: Start at offset 4096, given by the `offset` member
* `-c 8`   : Stop after displaying 8 bytes (each int was 4 bytes)

At offset 4096 (or 0x1000 in hex) the value of 8 followed by the value of 7, matches the assigned values for `SomeGlobalInt` and `SecondGlobalInt` in the source code.

This means one can translate virtual load addresses to file offsets (and back) with the following formula: 

```c
symbol_offset_address = (virtual_symbol_address - containing_macho_section_virtual_address) + contain_macho_section_file_offset
```

This trick is used extensively in [dsdump](https://github.com/DerekSelander/dsdump) to find information in a file. For example, a pointer will reference another area in memory through a virtual address. Using the above method, if you know the virtual address, you can obtain the file offset of what the pointer is pointing to on disk.

*All compiled code pointers will reference virtual addresses, not file offsets on disk.*

---
<a name="virtual_address_at_runtime"></a>
## 1.4 Virtual Addresses at Runtime
---

You saw the file offsets on disk, you'll now check out the virtual addresses of the C `int`s when they're loaded into memory. Use Apple's debugger, **LLDB**, to inspect the addresses in the **ex** program you compiled earlier. 

Execute the following:

```bash
lolgrep:/tmp$  lldb ex -s <(echo -e "b main\n run\n x/2wx 0x00000100001000")
```

There's a lot going on in this command. You're using LLDB to debug the **ex** executable. The `-s` option says to perform the following actions from a script. The `<()` command is a trick called [process substitution](http://tldp.org/LDP/abs/html/process-sub.html) to make the output of a proces be treated as a file. This would be the same thing as making a file with the following contents:

```bash
b main
run
x/2wx 0x00000100001000
```

The above script will set a breakpoint on the `main` function, then start up the ex program (via `run`). Program execution will then stop on the `main` function and will dump out the contents at the address `0x00000100001000` via the **x** (e*x*amine) command. 

The `x` command is an LLDB command whose syntax was cherry picked over from [GDB](https://en.wikipedia.org/wiki/GNU_Debugger). The `x` command will examine memory at the provided address.  The `wx` says to format the dereferenced memory in "word" size (4 bytes) and format the dereferenced output in hexadecimal. The 2 says to do it twice, once at address `0x0000000100001000` and once at address `0x0000000100001004`

The output should not be suprising:

```bash
(lldb)  x/2wx 0x00000100001000
0x100001000: 0x00000008 0x00000007
```

This is the runtime values of `SomeGlobalInt` and `SecondGlobalInt`

And what's the runtime address of these values? 

```bash
(lldb) p/x &SomeGlobalInt
(void **) $1 = 0x0000000100001000
(lldb) p/x &SecondGlobalInt
(void **) $2 = 0x0000000100001004
```

These are the virtual addresses that match the virtual addresses given by the `nm` command.

---
<a name="pie"></a>
## 1.5 PIE
---

Ohhhh but it gets a bit more confusing than that. In addition to the virtual load address, the OS can shift a loaded image's virtual addresses at runtime to a different starting base address to help mitigate attacks. This is called **Address Space Layout Randomization** or simply **ASLR**.  

Since an image can have a different address everytime it loads, this means that referencing virtual addresses needs to be able to reference addresses not based on an absolute virtual address value, but via a relative load address from the current memory address. This is known as a Position Indenpendent Executable or **PIE**.  

By default, every `MH_EXECUTE` you compile is position independent. You can confirm this with the following experiment:

Create the following C file, **ex2.c**:

```c
#include <stdio.h>
int main() {
  printf("main is at: %p\n", main);
  return 0;
}
```

Compile it...

```bash
lolgrep:/tmp$ clang ex2.c -o ex2
```

Give it a couple of runs...

```bash
lolgrep:/tmp$ ex2
main is at: 0x1025c9f50
lolgrep:/tmp$ ex2
main is at: 0x101eeef50
lolgrep:/tmp$ ex2
main is at: 0x109fcaf50
```

Notice how the address of `main` changes from load to load. This is because the executables starting base address is changing for each run via ASLR.

>**Note:** Some observant readers might have wondered why the virtual address didn't change with LLDB in the previous experiment. By default, LLDB will remove ASLR when a program is being debugged. If the **ex** program where to run without LLDB, the address would have changed around from invocation to invocation. 

Observe the virtual address of the `main` function in the compiled **ex2** image through the `nm` command:

```bash
lolgrep:/tmp$ nm ex2 | grep main
0000000100000f50 T _main
```

On my compilation, `main` is at `0x00000100000f50`. This means that the virtual address `0x00000100000f50` is being shifted every time the program is run. You can remove this automatic feature in `clang` easily enough via the **`-fno-pie`** option:

```bash
lolgrep:/tmp$ clang ex2.c -fno-pie -o ex2_nopie
```

Now give it a couple runs:

```bash
lolgrep:/tmp$ ex2_nopie
main is at: 0x100000f50
lolgrep:/tmp$ ex2_nopie
main is at: 0x100000f50
lolgrep:/tmp$ ex2_nopie
main is at: 0x100000f50
```

You can even observe the PIE bit in the Mach-O header. Compare the `ex2` and `ex2_nopie` executables together:

```bash
lolgrep:/tmp$ diff -y <(xxd -g 4 -e ex2 | head -2)  <(xxd -g 4 -e ex2_nopie | head -2)
00000000: feedfacf 01000007 80000003 00000002  ..............   00000000: feedfacf 01000007 80000003 00000002  ..............
00000010: 00000010 00000558 00200085 00000000  ....X..... ... | 00000010: 0000000f 00000510 00000085 00000000  ..............
```

Compare the values in the second to last row in the lower right. You'll see a `00200085` vs a `00000085`. Consult the `<mach-o/loader.h>` header for the phrase **PIE**:

```bash
lolgrep:/tmp$ cat $(xcrun --show-sdk-path)/usr/include/mach-o/loader.h | grep PIE -A3
#define MH_PIE 0x200000     /* When this bit is set, the OS will
             load the main executable at a
             random address.  Only used in
             MH_EXECUTE filetypes.
```

You'll see a `#define  MH_PIE 0x200000`, which tells the loading framework (**dyld**) that it is capable to slide this program's base address around to a different value.

*Even though a program's base address might change around when it's loaded into memory, the virtual addresses that are referenced on disk will never change*.

---
<a name="the_symbol_table"></a>
## II. Symbol Table
---

The symbol table plays an immensily important role of declaring what symbols it implements as well as what symbols it relies upon for that image to correctly function. All code/variables that survive out of the scope of code are candidates to be put into the symbol table for an image. 

For example (no need to code this particular example out):

```c
int someGlobalNumber = 5;
int foo(void) {
  int someNumber = 4;
  static someStaticNumber = 7;
  return someNumber + someStaticNumber + someGlobalNumber; 
}
```

In the above example, the `foo` function along with `someStaticNumber` and `someGlobalNumber` *could* end up in the symbol table, but the `someNumber` variable inside the function would not (typically) show up in the symbol table. Notice how `someStaticNumber` and `someGlobalNumber` survive outside the scope of the `foo` function, so *could* end up in the symbol table. Now, I said "*could*" because it's quite possible to hide symbols that are private and shouldn't be exposed to other modules (via symbol table `strip`'ing or [function attributes](https://clang.llvm.org/docs/AttributeReference.html)), but more on that later.  

---
<a name="nm_sym"></a>
## 2.1 Symbol Table Overview
---

As mentioned, the symbol table references internally implemented and *externally referenced* symbols.

Write out the following **ex3.m** Objective-C file to your `/tmp/` directory:

```objc
@import Foundation;

char *someData = "hello";
void someFunction() {}

int main() {
  printf("some val\n");
  NSLog(@"some different value");
}
```

Compile ex3.m

```bash
lolgrep:/tmp$ clang -fmodules ex3.m -o ex3
```

Then give it a run... 

```bash
lolgrep:/tmp$ ex3
some val
2019-10-25 17:27:34.956 ex3[19476:2277376] some different value
```

You didn't implement the code for `printf` nor `NSLog`. Use `nm` to look at how that's being referenced in the symbol table:

```bash
lolgrep:/tmp$ nm ex3
                 U _NSLog
                 U ___CFConstantStringClassReference
0000000100002010 d __dyld_private
0000000100000000 T __mh_execute_header
0000000100000f30 T _main
                 U _printf
0000000100002018 D _someData
0000000100000f20 T _someFunction
                 U dyld_stub_binder
```

You'll see undefined external symbols preceeded by a uppercase 'U'. It's `dyld`'s job to find the corresponding symbol in the appropriate library based upon the symbol table information. For the local symbols, you'll see a 'T' for (`__TEXT`) for `someFunction` and `main` and `D` (`__DATA`) for `someData`. We'll talk more about this a couple paragraphs down...

---
<a name="symbol_table_implementation"></a>
## 2.2 Symbol Table Implementation
---

You got the high up, now it's jump into the weeds to see the symbol table data structures in action. 

The location of the symbol table is given by the **`LC_SYMTAB`** Mach-O load command. The symbol table is merely just an array of a C struct called **`nlist_64`** (we're discussing 64-bit executables only here). This struct can be found in `<mach-o/nlist.h>` and has the following format:

```c
struct nlist_64 {
    union {
        uint32_t  n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;        /* type flag, see below */
    uint8_t n_sect;        /* section number or NO_SECT */
    uint16_t n_desc;       /* see <mach-o/stab.h> */
    uint64_t n_value;      /* value of this symbol (or stab offset) */
};
```
The individual fields will be discussed in detail below. 

Find the symbol table offset in the compiled **ex3** image:

<a name="lc_symtab"></a>
```bash
lolgrep:/tmp$ otool -l ex3 | grep LC_SYMTAB -A5
     cmd LC_SYMTAB
 cmdsize 24
  symoff 12488
   nsyms 9
  stroff 12652
 strsize 136
```

In this example, the symbol table starts at offset **12488** into the ex3 image.

Dump the raw bytes at the `symoff` value and do it for `nsyms` lines:

```bash
lolgrep:/tmp$ hexdump -s 12488 -e '1/4 "%08x " 1/1 "%02x " 1/1 "%02x " 1/2 "%04x " 1/8 "%010x" "\n"' ex3 | head -9
00000076 0e 0a 0000 0100002010
00000002 0f 01 0010 0100000000
00000016 0f 01 0000 0100000f30
0000001c 0f 0a 0000 0100002018
00000026 0f 01 0000 0100000f20
00000034 01 00 0300 0000000000
0000003b 01 00 0200 0000000000
0000005d 01 00 0100 0000000000
00000065 01 00 0100 0000000000
```
You gotta ❤️ the ugly formatting of the `hexdump` command...

Start at offset 12488 (or your equivalent on your compilation) with the `-s` option. After that, there's the huge formatted output string declared by the `-e` option. Breaking it down:
* The `1/4 "%08x "` part will output the first 4 byte column that references the `n_un` union (containing the 4 byte `n_strx` value in the `nlist_64` struct). The 1 in the 1/4 says to do it one time for a size of 4 bytes. The `"%08x "` says to display this 4 byte value in hex and make sure to pad it with up to 8 zeros if needed. A single byte (eight 1's or 0's, AKA bits) can occupy 2 digits in hex, so an easy rule is to multiply the size of your data by 2 when printing it in hex. To hammer this concept home, the decimal value 255 (aka 2^8) will have the hex value 0xFF. 
* The process repeats again. The ` 1/1 "%02x "` value says to print one byte only once (for the `n_type` value in the `nlist_64` struct) and format the output to have 2 bytes in hex.
* The same process is repeated for the `n_sect` value which is also a type of `uint8_t`.
* The 2 byte `uint16_t` value for `n_desc` is then printed
* Finally, the 8 byte `uint64_t` value for `n_value` is printed.

Cross reference the raw `nlist_64` data from `hexdump` to the much-easier-to-type format from `nm`:

```bash
lolgrep:/tmp$ nm -xp ex3
0000000100002010 0e 0a 0000 00000076 __dyld_private
0000000100000000 0f 01 0010 00000002 __mh_execute_header
0000000100000f30 0f 01 0000 00000016 _main
0000000100002018 0f 0a 0000 0000001c _someData
0000000100000f20 0f 01 0000 00000026 _someFunction
0000000000000000 01 00 0300 00000034 _NSLog
0000000000000000 01 00 0200 0000003b ___CFConstantStringClassReference
0000000000000000 01 00 0100 0000005d _printf
0000000000000000 01 00 0100 00000065 dyld_stub_binder
```

The `-x` will display the raw data of the `nlist_64` struct (be aware that the `-x` output flips the first `n_strx` and `n_value` around in output since the `n_value` is considered to be the most important). Next up, the `-p` option will display the symbols in numerical order (instead of symbol table name order). 

The `nm` command will also grab the name of the symbol which can be derived from the offset of the `n_strx` into the blob of characters given by the `stroff` in the Mach-O `LC_SYMTAB` [obtained earlier, which had the `stroff`  value **12652**](#lc_symtab) and whose size is given by the `strsize` value. 

Going after the first symbol, the **__dyld_private** symbol has a `n_strx` offset of **0x00000076** (noticed I added a 0x to the beginning of the value to ensure it's interpreted as hex) into the blob of characters pointed at by the `stroff` value. Use `xxd` to verify this:

```bash
lolgrep:/tmp$ xxd -s $(( 0x00000076 + 12652 )) ex3 | head -1
000031e2: 5f5f 6479 6c64 5f70 7269 7661 7465 0000  __dyld_private..
```

The bash **`$(( expr ))`** command will perform arithmetic on your behalf, adding 0x00000076 to 12652.

And that's how the `nm` command can programmatically find the names for these symbols!

---
<a name="nlist_64_overview"></a>
## 2.3 nlist_64 Overview
---

The symbol table's `nlist_64` array really can give off an impressive amount of information about an image. There's a lot of info in `<mach-o/nlist.h>`, but some highlights will be reviewed below. 

Looking at the `nlist_64` value for the `someData` and `someFunction` symbols given by `nm` above on ex3...

<pre>
nlist_64 fields: n_value          n_type n_sect  n_desc n_strx   
raw data:        0000000100002018 0f     0a      0000   0000001c _someData
                 0000000100000f20 0f     01      0000   00000026 _someFunctin
</pre>

* The `n_value` will give the virtual address *if the symbol is implemented locally*.
* The `n_type` contains a whole bunch of information packed into 8 bits. For this particular case, the value 0x0f can be seen as a bit mask for `N_EXT` (0x01) and `N_SECT` (0x0e) (see header). The `N_EXT` says it's a "public" symbol (so you can [`dlopen`](http://man7.org/linux/man-pages/man3/dlopen.3.html)/[`dlsym`](http://man7.org/linux/man-pages/man3/dlsym.3.html) it), the `N_SECT` tells us that the symbol's Mach-O section is described in the `nlist_64`'s `n_sect` field. 
* As seen earlier, the `n_strx` (last hex column) will provde an index into the array of characters for the symbol's name. 
* The `n_sect` will indicate where the symbol is located in the Mach-O sections which starts at index 1 (not 0 like most arrays). Confirm this is true with the following experiment:

```bash 
lolgrep:/tmp$ otool -l ex3 | grep sectname
  sectname __text
  sectname __stubs
  sectname __stub_helper
  sectname __cstring
  sectname __unwind_info
  sectname __got
  sectname __cfstring
  sectname __objc_imageinfo
  sectname __la_symbol_ptr
  sectname __data
```

  Note how the `someFunction` symbol is at the `__text` Mach-O section (index 1 in `n_sect`), the `someData` is at `__data` section due to the 0x0a (AKA 10).

  Cross reference the data gathered from manually parsing `n_sect` with the output of `nm`'s `-m` option:

```bash
lolgrep:/tmp$ nm -m ex3 | grep some
0000000100002018 (__DATA,__data) external _someData
0000000100000f20 (__TEXT,__text) external _someFunction
```

* Continuing with `nlist_64`'s attributes, the `n_desc` value isn't of too much use for local symbols, so let's look at the `nlist_64` values whose symbols are defined outside of ex3:

<pre>
nlist_64 fields: n_value          n_type n_sect  n_desc n_strx   
raw data:        0000000000000000 01     00      0300   00000034 _NSLog
                 0000000000000000 01     00      0200   0000003b ___CFConstantStringClassReference
                 0000000000000000 01     00      0100   0000005d _printf
</pre>

  Notice how the `n_value` (first column) is set to 0 for undefined symbols; they're not implemented locally, so they shouldn't have a local virtual address. The `N_EXT` bit is set (0x01) for the `n_type`, meaning the symbol is a public symbol. For the `n_sect` value (3rd column), these are all set to 0x00 or `NO_SECT`, meaning the Mach-O section is undefined (makes sense, they're external symbols). Now let's pick up on the remaining `nlist_64` members.

* The `n_desc` can do a number of things, but for this case, it is telling us which library the symbol can be found in (provided the symbol has two-level namespacing, Google that on your own time). These values in `n_desc` provide an index into the Mach-O load commands for external libraries.

```bash
lolgrep:/tmp$ otool -L ex3 | awk '{print $1}'
ex3:
/usr/lib/libSystem.B.dylib
/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation
```  

From the above, `NSLog` is expected to be found in Foundation (0x0300), `__CFConstantStringClassReference` is from CoreFoundation (0x0200), `printf` is from libSystem.B.dylib (0x0100)

Again, confirm this is true with `nm`:

```bash
lolgrep:/tmp$ nm -m ex3  | grep undefined
                 (undefined) external _NSLog (from Foundation)
                 (undefined) external ___CFConstantStringClassReference (from CoreFoundation)
                 (undefined) external _printf (from libSystem)
                 (undefined) external dyld_stub_binder (from libSystem)
```

As homework, navigate to the location of the `Foundation` framework (given by the `otool -L ex3` command earlier) and confirm a symbol named `NSLog` exists there that is public for use.

---
<a name="symbol_table_stripping"></a>
## 2.4 Symbol Table Stripping
---

Create the **`ex4.c`** file with the following code:

```c
#include <stdio.h>

void someFunction() { printf("yay\n"); }
int main() {
  someFunction();
  return 0;
}
```

Compile the ex4.c file:

```bash
lolgrep:/tmp$ clang ex4.c -o ex4
```

Check out the symbols with `nm`

```bash
lolgrep:/tmp$ nm ex4
0000000100002008 d __dyld_private
0000000100000000 T __mh_execute_header
0000000100000f70 T _main
                 U _printf
0000000100000f50 T _someFunction
                 U dyld_stub_binder
```

Now, **`strip`** the ex4 image

```bash
lolgrep:/tmp$ strip ex4
```

Stripping the symbol table will remove uneeded symbols. Dump the symbol table:

```bash
lolgrep:/tmp$  nm ex4
0000000100000000 T __mh_execute_header
                 U _printf
                 U dyld_stub_binder
```

Weird, the symbols aren't there, but will it still run?

```bash
lolgrep:/tmp$ ex4
yay
```

In a `MH_EXECUTE` type image, any C/Objective-C/Swift function don't need to be externally available so that information can be removed from the symbol table. Why is that? A `MH_EXECUTE` type of file should be ran by itself, it shouldn't be loaded into another address space!

> **Note:** Just because there's no symbol in the symbol table for some code doesn't mean that you can't infer that a function is there. The **`LC_FUNCTION_STARTS`** load command will export a list of all the function/method locations (*only code, NOT data*) that are implemented by an image. This information is formatted in **[ULEB](https://en.wikipedia.org/wiki/ULEB)**. This is useful for debuggers and crash analytics.

What if the above code was compiled as a shared library? What would happen to the symbol table? Compile ex4.c, but now add the `-shared` option:

```bash
lolgrep:/tmp$ clang -shared ex4.c -o ex4.shared
```

Ensure the ex4.shared file is the correct `MH_DYLIB` `filetype` (from `mach_header_64`'s `filetype`, remember? 😛) after compiling:

```bash
lolgrep:/tmp$ file ex4.shared
ex4.shared: Mach-O 64-bit dynamically linked shared library x86_64
```

Check out the symbols via `nm`... 

```bash
lolgrep:/tmp$ nm ex4.shared
0000000000002008 d __dyld_private
0000000000000f70 T _main
                 U _printf
0000000000000f50 T _someFunction
                 U dyld_stub_binder
```

Then run the `strip` command and check out the differences. What is the difference compared to the `MH_EXECUTE` image and why do you think that is? 

Public symbols in shared libraries won't be stripped out because there could be consumers in other images that rely on those symbols, so they need to keep their names intact.

---
## III. Objective-C
---

Objective-C still plays quite a relevant role—even in Swift. A pure Swift class (i.e. `class ASwiftClass {}`) will inherit from an Objective-C class called **SwiftClass** on all Apple platforms (you'll verify this in a second).

In addition, Swift methods *can* be stripped out of the symbol table, but Objective-C methods can still be resolved via other ways (as you'll see shortly). If a Swift class overrides an Objective-C method (i.e. `viewDidLoad`), there'll be a compiler generated Objective-C bridging method (called a [thunk](https://en.wikipedia.org/wiki/Thunk)) which retains and rearranges assembly registers to the Swift calling convention. The thunk method is visible on the Objective-C side, while the actual Swift method can be stripped out. You'll see at the end of this writeup that you can infer the stripped Swift method by using this Objective-C class knowledge and the Swift reflection type knowledge introduced later.

---
## 3.1 Objective-C Class List
---

Using the Mach-O knowledge you've built up earlier, it's quite easy to hunt for Objective-C classes that are built into an image. All you have to do is look for the **`__DATA_CONST.__objc_classlist`** (or `__DATA.__objc_classlist` if pre iOS-13) Mach-O section in an image.

Build up an executable with Objective-C code and name it **ex5.m**:

```objc
@import Foundation;

@interface AClass : NSObject
@end

@interface AnotherClass : AClass
@end

int main() { return 0; }
```

Compile ex5.m with the debugging information flag (`-g`):

```bash
lolgrep:/tmp$ clang ex5.m -fmodules -o ex5 -g
```

Debug the program with **lldb**,  set a breakpoint on the `main` function, then run the program:

```bash
lolgrep:/tmp$ lldb -s <(echo -e "b main\nrun") ex5
```

> **Note:** By default, LLDB disables PIE when executing programs. That means virtual addresses referenced in Mach-O load commands for an `MH_EXECUTE` image will likely be the same realized virtual memory address at runtime (provided you didn't override LLDB's settings). 

With PIE disabled via LLDB, use this knowledge to run `otool` inside of the LLDB program to query the runtime location of the `__objc_classlist` Mach-O section:

```bash
(lldb) platform shell otool -l ex5 | grep classlist -A3
  sectname __objc_classlist
   segname __DATA_CONST
      addr 0x0000000100001000
      size 0x0000000000000010
```

> **Note:** It's worth noting that LLDB does have the functionality to dump Mach-O sectrions (via **(lldb) image dump section [ImageName]**), although I am not very happy with the output of that command.

For my instance, the `__objc_classlist` starts at `0x0000000100001000` which has a size of 0x10 bytes (the size of 2 pointers). Confirm that this address (`0x0000000100001000`) is the `__DATA_CONST.__objc_classlist` Mach-O section loaded at runtime:

```bash
(lldb) image lookup -va 0x0000000100001000
      Address: ex5[0x0000000100001000] (ex5.__DATA_CONST.__objc_classlist + 0)
      Summary: (void *)0x0000000100002148: AClass
       Module: file = "/tmp/ex5", arch = "x86_64"
```

This `__DATA_CONST.__objc_classlist` section is an array of pointers to Objective-C classes implemented by that image! Confirm this by dereferencing the address at `0x0000000100001000` and `0x0000000100001008`:

```bash
(lldb) x/2gx 0x0000000100001000
0x100001000: 0x0000000100002148 0x0000000100002198
```

You should be already familiar with the `x` LLDB command from earlier. The `gx` in this command says to format the dereferenced memory in giant words (8 bytes) and format the dereferenced output in hexadecimal. The 2 says to do it twice, once at address `0x0000000100001000` and once at address `0x0000000100001008`

It's the dereferenced values, `0x0000000100002148` and the `0x0000000100002198` that represents Objective-C classes. Print both of these classes out:

```bash
(lldb) exp -l objc -- (Class)0x0000000100002148
(Class) $2 = AClass
(lldb) exp -l objc -- (Class)0x0000000100002198
(Class) $3 = AnotherClass
```

> **Note:** As of around clang version `clang-1100.0.33.8` (in Xcode 11), the default configuration for compiling the Objective-C `__objc_class_list` Mach-O section was moved from the `__DATA` Mach-O segment to the `__DATA_CONST` Mach-O segment. This change is discussed in the DYLD opcodes part of the writeup, but just be aware that if you have an older version of clang, you'll see `__objc_class_list` in the `__DATA` Mach-O segment.

---
## 3.2 Objc4
---

It's quite insightful to look at the source code to build Objective-C.

The most recent opensource Objective-C class layout (at the time of writing this) can be found in a header named **[objc4/objc4-756.2/objc-runtime.new.h](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html)**

> **Note:** You can determine the version of your Objective-C runtime via a `otool -l /usr/lib/libobjc.A.dylib | grep SOURCE -A2 | tail -1`. This value will (hopefully) have a corresponding source code version on Apple's [https://opensource.apple.com/source/objc4/](https://opensource.apple.com/source/objc4/). Sometimes your version will be ahead of Apple's opensource listings since they take their sweet time publishing it. For this writeup, my Objective-C runtime version (779.1) is ahead of Apple's opensource listing (756.2)

In this header file, there is a C struct is called **`objc_class`**. All instances of an Objective-C class will have a pointer to this `objc_class` struct at offset 0. Below is a *simplified* layout of the `objc_class` struct.


```objc
struct objc_class {
    struct objc_class* isa;        // size 8 bytes, offset +0x0
    struct objc_class* superclass; // size 8 bytes, offset +0x8
    struct bucket_t *_buckets;     // size 8 bytes, offset +0x10
    mask_t _mask;                  // size 4 bytes, offset +0x14
    mask_t _occupied;              // size 4 bytes, offset +0x18
    uintptr_t bits;                // size 8 bytes, offset +0x20
``` 

* The `isa` references the `objc_class` data. This is a clever layout because not only do heap allocated instances have the `isa` at offset 0, but so do all `objc_class`'s have an `isa` at offset 0. This is subtle, but important so this is going into emphasized text: 

    > *A heap allocated object's `isa` will be an `objc_class` that contains all the **instance** methods (i.e. `-[NSFileManager fileExistsAtPath:isDirectory:]`). The heap allocated object's `isa`'s `isa` is called a **Meta Class** which contains all of the **class** methods (i.e. `+[NSFileManager defaultManager]`). a meta class has no isa (it's set to `NULL`)*. 

    This means, that if you were to build an Objective-C introspection tool, you'd need to go after the Objective-C class (given by the `__objc_classlist` Mach-O section) and the meta class (given by the `isa` from the list of classes in the `__objc_classlist` Mach-O section) to find all class/instance methods implemented in that image (don't even think about Objective-C categories yet, we'll build up to that).*

* The `superclass` is the same idea, except it's just a reference to the "parent `isa`".

... Skipping `_buckets`, `_mask`, and `_occupied` because they're not applicable to this writeup...

* The `bits` value is the "guts" to the Objective-C class and is a wee bit complicated in design. The `bits` value contains a pointer to a struct of type **class_ro_t** (discussed below). However, once the Objective-C class is "initialized" and loaded into memory through first invocation, this `bits` value will change to point to a struct of type **`class_rw_t`** (not discussed below, Google on your own time). To make it even more WTF, this `bits` pointer will pack additional bits in non-pointer aligned values. That is, on 64-bit systems, a pointer will always reside on an address ending with either a 0x0 or a 0x8. That means the first 3 bits can be used to store miscellaneous information (like if an Objective-C class is written in Swift!) 

If you want to resolve the pointer from the `bits` value, you'd have to bitwise AND it with **0x00007ffffffffff8UL**. This is defined as the **`FAST_DATA_MASK`** in the objc-runtime-new.h header.

---
## 3.3 How to Disappoint Swift Developers
---

Earlier, I said all pure Swift classes on Apple platforms are really just Objective-C classes underneath, so let's prove that.

Create the following Swift file, **ex6.swift**:

```swift
class APureSwiftClass {}

let a = APureSwiftClass()
print("\(a)")
```

Compile with debugging info:

```bash
lolgrep:/tmp$ swiftc ex6.swift -o ex6 -g
```

Run with LLDB via a breakpoint on `main` (yes, Swift still has a `main`, they just hide it from you)

```bash
lolgrep:/tmp$ lldb ex6 -s <(echo -e "br set -n main -s ex6\nrun")
```

And then hunt for the `__objc_classlist` Mach-O section:

```bash
(lldb) platform shell otool -l ex6 | grep classlist -A3
  sectname __objc_classlist
   segname __DATA_CONST
      addr 0x0000000100001018
      size 0x0000000000000008
```

On this compilation, the class list starts at virtual address `0x0000000100001018` and the size is 8 bytes (due to only one Objective-C class).

Dereference this single value array to get the raw Objective-C data for the `APureSwiftClass`:

```bash
(lldb) x/gx 0x0000000100001018
0x100001018: 0x0000000100002138
```

Confirm this address contains the class of interest:

```bash
(lldb) exp -l objc -- (Class)0x0000000100002138
(Class) $2 = ex6.APureSwiftClass
```

> **Note:** By executing the above LLDB command, you are **initializing** the class for runtime. This will essentially change the `objc_class`'s `bits` from a `class_ro_t` to the `class_rw_t`. But for this particular example, it doesn't matter, since you're going after the non-pointer aligned bits. 

On my machine, the pointer for `APureSwiftClass` (AKA a `objc_class*`, AKA a `Class`) starts at **0x0000000100002138**. Dereference this value 5 times to display the raw `objc_class` data:

```bash
(lldb) x/5gx 0x0000000100002138
0x100002138: 0x0000000100002100 (isa)    0x00007fff91b6d478 (superclass)
0x100002148: 0x00007fff63aa1400 (boring) 0x0000000000000000 (boring)
0x100002158: 0x00000001000020b2 (bits!)
```

I've annotated the above output. Looking at the `bits` of the `objc_class` do you see how there is a 2 in the least significant hexadecimal value? 

If you were to consult the [objc-runtime-new.h file](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html), you'll see **`FAST_IS_SWIFT_STABLE`** has the following declaration:

```c
#define FAST_IS_SWIFT_STABLE    (1UL<<1)
```

This is the bit that says if a class is Objective-C or Swift.

Now do the same thing for the `superclass` whose address you obtained in the previous LLDB command. First figure out what it's called:

```bash
(lldb) exp -l objc -- (Class)0x00007fff91b6d478
(Class) $4 = Swift._SwiftObject
```

This class is called **`_SwiftObject`**. And what is it? 

```bash
(lldb) x/5gx 0x00007fff91b6d478
0x7fff91b6d478: 0x00007fff91b6d4a0 0x0000000000000000
0x7fff91b6d488: 0x00007fff63aa1400 0x0000000000000000
0x7fff91b6d498: 0x00007fff811c6c50
```

Oh no! There's no 2 in that `0x00007fff811c6c50` value! All your Swift classes on Apple platforms really just inherit from an Objective-C class underneath. Womp womp.

I anticipate this will change in a couple years, but for now, it's always fun to bring Swift developers down to my level 😈

---
## 3.4 The bits value revisited (class_ro_t vs class_rw_t)


While LLDB is still paused (if not run it again and break on `main`), in the `main` function of ex6, execute the following Swift code:

```bash
(lldb) e import Foundation  # Needed to reference the NSClassFromString API in Swift
(lldb) p/x NSClassFromString("ex6.APureSwiftClass") # print the result in hexadecimal
(AnyClass?) $R18 = 0x0000000100002138 ex6.APureSwiftClass
```

Note how that `0x0000000100002138` (or equivalent on your computer) address matches with the dereferenced value obtained from `__objc_classlist` Mach-O section you found earlier.


> **Note:** remember, whenever you reference a class, you're initializing it, and changing the `bits` value from a `class_ro_t*` to a `class_rw_t*`. Executing the `NSClassFromString`, `po`'ing a class in LLDB, or executing a `e APureSwiftClass.self` in Swift via LDLB will initialize the class. As of right noww, the `APureSwiftClass` should be initialized, meaning the `class_rw_t*` value will reside in the `bits` field. The `class_ro_t*` will point to memory contained in a Mach-O section, the `class_rw_t*` will point to a heap allocated reference due to the runtime not knowing how many methods there are in the ObjC class (ObjC categories, associated objects, other runtime fun, etc.) until the class is loaded.

Rerun the program with the `run` command.

```bash
(lldb) run
```

The program should have reset itself to the start of the `main` function. Since ASLR is disabled, the virtual addresses will remain unchanged from run to run. Dump the address for the `APureSwiftClass` (mine was 0x0000000100002138) **without** initializing the class (i.e. no `po`'ing).


```bash
(lldb) x/5gx 0x0000000100002138
0x100002138: 0x0000000100002100 0x00007fff91b6d478
0x100002148: 0x00007fff63aa1400 0x0000000000000000
0x100002158: 0x00000001000020b2 <- bits, AKA (class_ro_t* | FAST_IS_SWIFT_STABLE)
```

Keep a record of the `bits` value as it will change in a second. My value is **`0x00000001000020b2`**

Initialize the `APureSwiftClass` via Swift:

```bash
(lldb) e APureSwiftClass.self
(ex6.APureSwiftClass.Type) $R16 = ex6.APureSwiftClass
```

Rerun the earlier command and inspect the `objc_class` struct's `bits` value:

```bash
(lldb) x/5gx 0x0000000100002138
0x100002138: 0x0000000100002100 0x00007fff91b6d478
0x100002148: 0x00007fff63aa1400 0x0000001800000000
0x100002158: 0x0000000100501682 <- bits, AKA (class_rw_t* | FAST_IS_SWIFT_STABLE)
```

The `bits` param has now changed to the `class_rw_t* | FAST_IS_SWIFT_STABLE`

> *If you're a building out an Objective-C runtime introspection tool, and you're testing the tool on itself, make sure you know the correct struct that resides in the `bits` value*. I burned *a lot* of hours working with the wrong struct by accidentially initializing Objective-C classes by `po`'ing them in LLDB 🤦‍♂️

Fortunately, the `class_ro_t` and the `class_rw_t` struct both have `int32_t flags` value right at the beginning. The `flags` member can tell you if the class is initialized via the value is (1 << 31, AKA 0x80000000).

In the above example, if I didn't know if a class was initialized at runtime, I'd start with the `bits` value (`0x0000000100501682`). I'd remove the Swift bit packed flags, turning the value into **`0x0000000100501680`**. Then, I'd dereference this value with a size of 32 bits in LLDB

```bash
(lldb) x/wx 0x0000000100501680
0x100501680: 0x80080000
```

The 0x8 in the most significant bit means the class has already been initialized, meaning the `bits` value is a `class_rw_t*`.

---
## 3.5 The class_ro_t struct
---

The `class_ro_t` struct is the "key" value to exploring an Objective-C class. It's the gateway to the class's name, it's methods, it's properties, it's instance variables, etc. And *unlike* the `class_rw_t` struct, this value is located in the `__DATA.__objc_const` Mach-O section, meaning one can query this information programatically on disk.  

Here's a *simplified* `class_ro_t` layout:

```c
struct class_ro_t {
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
    uint32_t reserved;

    const uint8_t * ivarLayout;
    const char * name;
    method_list_t * baseMethodList;  // An array for method_t
    protocol_list_t * baseProtocols; // An array for protocol_t
    const ivar_list_t * ivars;       // An array for ivar_t
    const uint8_t * weakIvarLayout;
    property_list_t *baseProperties; // An array for property_t
}
```

Using this knowledge, find the `const char* name` of this Swift class. While still in LLDB, start a fresh run of the program

```bash
(lldb) run
There is a running process, kill it and restart?: [Y/n] Y
```

Execution should stop at the `main` breakpoint you made earlier. This time, query the (same) address you obtained through Mach-O/NSClassFromString, but this time use LLDB's symbol lookup functionality:

```bash
(lldb) image lookup -s "type metadata for ex6.APureSwiftClass"
1 symbols match 'type metadata for ex6.APureSwiftClass' in /tmp/ex6:
        Address: ex6[0x0000000100002138] (ex6.__DATA.__data + 64)
        Summary: type metadata for ex6.APureSwiftClass
```
The **type metadata** is Swift's naming convention for an Objective-C class. More on that later. 

You'll see the familiar `0x0000000100002138` starting address for the Objective-C class called `APureSwiftClass`. Grab the `bits`:

```bash
(lldb) x/5gx 0x0000000100002138
0x100002138: 0x0000000100002100 0x00007fff91b6d478
0x100002148: 0x00007fff63aa1400 0x0000000000000000
0x100002158: 0x00000001000020b2
```

Remove the Swift class mask to turn the `bits` value into the `class_ro_t` pointer and dereference it 4 times:

```bash
(lldb) x/4gx 0x00000001000020b0
0x1000020b0: 0x0000001000000080 0x0000000000000010
0x1000020c0: 0x0000000000000000 0x0000000100000f00 
```

Cross referencing the `class_ro_t` struct with the dumped memory:

```c
struct class_ro_t {
    uint32_t flags; // 0x00000080
    uint32_t instanceStart; // 0x00000010
    uint32_t instanceSize; // 0x00000010
    uint32_t reserved; // 0x00000000
    const uint8_t * ivarLayout; // 0x0000000000000000
    const char * name; // 0x0000000100000f00
...
```

The above output has the fields included to make the raw data easier to read.

In my program's memory, the name of this class is found at address **`0x0000000100000f00`**. Dereference the address using `x`'s string format.

```bash
(lldb) x/s 0x0000000100000f00
0x100000f00: "_TtC3ex615APureSwiftClass"
```

That's how one can programmatically traverse every Objective-C class in an image and find it's name!

There's many more components to reading the `class_ro_t` struct, but that can be reviewed on your own time.

---
## 3.6 Other Mach-O ObjC Sections
---



<a name="dyld_opcodes_and_binding"></a>
## IV. DYLD Opcodes and Binding

Although this concept might be dry to many, it's essential knowledge for understanding how Swift types and Objective-C classes interact with each other with different images. How can a class's superclass be referenced in a different image? 

This is the job for **dyld opcodes**. In the Mach-O **LC_DYLD_INFO_ONLY** load command, there exists a series of opcodes that tell dyld what symbols and where to bind them. This happens as soon as an image is loaded into memory. 


---
## 4.1 Finding Opcodes 
---

Build out the following Objective-C file called **ex7.m**:

```objc
@import Foundation;

@interface SubArray : NSArray
@end
@implementation SubArray
@end

int main () { return 0; }
```

Compile ex7.m, make sure to include the `-fno-pie` option: 

```bash
lolgrep:/tmp$ clang -fmodules ex7.m  -o ex7 -fno-pie
```

Query the virtual address location of the `SubArray` Objective-C class:

```bash
lolgrep:/tmp$ nm ex7 | grep SubArray
00000001000010c8 S _OBJC_CLASS_$_SubArray
00000001000010a0 S _OBJC_METACLASS_$_SubArray
```

The `SubArray` class starts at `0x000001000010c8` (for me), whose `isa` will contain the value `0x000001000010a0` (the meta class). But what about it's superclass? The address at `0x000001000010d0` (`SubArray`'s start address + the size of a pointer) needs to be bound to the `NSArray` class; *this is where the opcodes come in*.

>**Note:** Frankly speaking, Apple's `dyldinfo`'s `-opcodes` option is a bit disappointing for this information because it only displays the opcodes it interprets; it doesn't display the realized virtual addresses that it will bind symbols to. That's why [dsdump](https://github.com/DerekSelander/dsdump)'s `-O` option is better suited to showcase this:

Use `dsdump`'s `-O` option to display the opcodes:

```bash
lolgrep:/tmp$ dsdump -O ex7 | head -5
0x0000 BIND_OPCODE_SET_DYLIB_ORDINAL_IMM (2)
0x0001 BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM (0x00, _OBJC_CLASS_$_NSArray)
0x0018 BIND_OPCODE_SET_TYPE_IMM (1)
0x0019 BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB (2, 0x000000D0) (0x1000010D0)
0x001C BIND_OPCODE_DO_BIND (0x1000010D0, _OBJC_CLASS_$_NSArray)
```

Here you can see the resolved `0x1000010D0` address be bound to by the `NSArray` class.

>**Note:** [Jonathan Levin](https://twitter.com/Morpheus______) has a [great writeup](http://www.newosxbook.com/articles/DYLD.html) of what each of these opcodes do.

Verify at runtime the `0x1000010D0` (or equivalent) address is being bound via `dyld`'s debugging environment variables (see `man dyld`).

Add the **`DYLD_PRINT_BINDINGS=1`** env var to the ex7 executable and observe the output.

```bash
lolgrep:/tmp$ DYLD_PRINT_BINDINGS=1 ex7
```

This produced the following on my machine:

```bash
dyld: bind: ex7:0x1000010D0 = CoreFoundation:_OBJC_CLASS_$_NSArray, *0x1000010D0 = 0x7FFF895E11C0
dyld: bind: ex7:0x1000010A8 = CoreFoundation:_OBJC_METACLASS_$_NSArray, *0x1000010A8 = 0x7FFF895E1E40
dyld: bind: ex7:0x1000010A0 = libobjc.A.dylib:_OBJC_METACLASS_$_NSObject, *0x1000010A0 = 0x7FFF91AC90F0
dyld: bind: ex7:0x1000010B0 = libobjc.A.dylib:__objc_empty_cache, *0x1000010B0 = 0x7FFF63AA1400
dyld: bind: ex7:0x1000010D8 = libobjc.A.dylib:__objc_empty_cache, *0x1000010D8 = 0x7FFF63AA1400
```

Again, observe the `NSArray` class being bound to address `0x1000010D0` (or equivalent) at runtime.

*Understanding the binding opcodes is incredibly important to infer what symbol is being used from another image since these addresses are `nil`'d out while on disk. It's only at load time will these addresses get bound to an actual address so dyld opcode knowledge is a must for building a class-dump tool.*  


<a name="swift"></a>
## Swift

Finally! You got to Swift! Unlike all the previous concepts, exploring Swift types is evolving at a rapid pace. So much so that I must say that this information will likely get stale in less than a year. 

**This information only pertains to Swift 5.x**

## 5.1 Swift Types

Unlike Objective-C where classes are only fair game, Swift can introspect any type--an enum, struct, class, protocol, etc!

To do this, several different Mach-O sections are utilized. By far the most important one is the **`__TEXT.__swift5_types`**. The `__swift5_types` contains an array of "**relative pointers**" to all the Swift types found in the image. Think of it sort of like the `__DATA__CONST.__objc_classlist` section where it's an array of pointers to Objective-C classes. The difference is that this section stores all Swift *types* and it only uses 4 bytes (by default, instead of 8 bytes via a pointer).

Relative pointers are a 4 byte signed integer that takes it's value and adds it to the address.

In pseudo-c-ish-code...

```c
#include <mach-o/getsect.h>

unsigned long sz = 0;
int32_t *data = getsectdata("__TEXT", "__swift5_types", &sz);
for (int i = 0; i < (sz / sizeof(int32_t)); i++) {
  uintptr_t nominalTypeDesc = (uintptr_t)data[i] + (uintptr_t)&data[i];
}
```

The relative pointers idea is a really nifty trick by the Swift developers. Not only does each relative pointer only use half the amount of bytes, but dyld doesn't need to rebase any of the pointers when loaded into memory since it will always be a hardcoded offset to whatever address the image is loaded in. 


These relative pointers will point to something called a **nominal type descriptor**, which is just a fancy way of saying the layout of a type (similar to the `objc_class` struct you saw earlier). These type descriptors come in varying sizes based upon the type they represent. For example, here's the structural layout for a [nominal type descriptor for a Swift class](https://github.com/apple/swift/blob/67ff818215841c52ab5c65c3066a36a711427bed/include/swift/ABI/Metadata.h#L3784-L4088). A nominal type descriptor for, say, a Swift enum will have a different layout.

If you clicked on the above link, that's a little hard on the eyes, right? Figuring out the offsets for C++ classes can be a pain the ass due to inheritance. Fortunately, [Scott Knight](https://twitter.com/sdotknight) provides an *excellent* [article](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html) with simplified C struct offsets. If you're interested in the Swift layouts, I'd strongly suggest you read Scott's work, since Scott does a much better job explaining all the Swift struct layouts. So instead of focusing on all the different structs like Scott, I'll do a deep dive into one struct layout: the layout for Swift classes.

Copying and pasting directly from Scott's work, here's a simplified nominal type descriptor for a Swift class:

```c
struct NominalClassDescriptor {
    uint32_t Flags // All nominal type descriptors begin with Flags, used to determine nominal type descriptor
    int32_t  Parent // The reference to the parent type descriptor 
    int32_t  Name // The name of the type descriptor
    int32_t  AccessFunction // 
    int32_t  FieldDescriptor            
    int32_t  SuperclassType // Superclass type            
    uint32_t MetadataNegativeSizeInWords 
    uint32_t MetadataPositiveSizeInWords 
    uint32_t NumImmediateMembers // Number of additional members stored after this class (aka NumImmediateMembers * sizeof(void*) payload)        
    uint32_t NumFields // Number of properties stored in this class                  
}
```

You will explore this `NominalClassDescriptor` struct in a Swift program. Create **ex8.swift** with the following code:

```swift
class SomeClass {
  func doStuff() { }
}
let a = SomeClass()
print("\(a)")
```

Compile with debugging info:

```bash
lolgrep:/tmp$ swiftc -g ex8.swift
```

Debug the ex8 executable by setting a breakpoint on **`main`**

```bash
lldb ex8 -s <(echo -e "br set -n main -s ex8\nrun")
```

While paused in `main`, query for the `__swift5_types` Mach-O section:


```bash
(lldb) platform shell otool -l ex8 | grep types -A3
  sectname __swift5_types
   segname __TEXT
      addr 0x0000000100000f90
      size 0x0000000000000004
```

From the output, the address of interest is found at **`0x0000000100000f90`** (on my machine), whose size is only 4 bytes (AKA there's only one Swift type). Dereference this address to a 32 bit signed integer.

```bash
(lldb) x/wd 0x0000000100000f90
0x100000f90: -92
```

The address `0x100000f90` has the value `-92`. Add these two values together to get the nominal type descriptor address for the `SomeClass` type:

```bash
(lldb) image lookup -a `0x0000000100000f90 + -92`
      Address: ex8[0x0000000100000f34] (ex8.__TEXT.__const + 28)
      Summary: ex8`nominal type descriptor for ex8.SomeClass
```

The backticks is an LLDB trick to evaluate an expression before being parsed to the surrounding command. The resolved address is **0x0000000100000f34** (for me).

Cross referencing the`NominalClassDescriptor` layout from above, dereference 3 relative pointers to get the `Name` field.

```bash
(lldb) x/3wd 0x0000000100000f34
0x100000f34: -2147483568
0x100000f38: -28
0x100000f3c: -20
```

The `Name` string is at offset -20 from address 0x100000f3c. Use LLDB to evaluate this address: 

```bash
(lldb) x/s `0x100000f3c + -20`
0x100000f28: "SomeClass"
```

BOOM! And that's Swift reflection in a nutshell!

## Swift Methods in a Class

Immediately following the `NominalClassDescriptor`, there exists a varying amount of data (given by the `NumFields` field). This is a list of methods available to the Swift class.


 
There's many, many more components to this, such as being able to programmatically find methods, but I'll leave that to interested reader to explore on their own time (or you can just look at [dsdump's source](https://github.com/DerekSelander/dsdump). 

## Swift Calling Convention

Swift's calling convention differs a bit from other languages on Apple platforms. 

[Mike Ash](https://twitter.com/mikeash?lang=en)'s [writeup](https://www.mikeash.com/pyblog/objc_msgsends-new-prototype.html)

## strip'ing Swift Methods?

Even though `strip`'ing methods in Objective-C removed the symbol table information, Objective-C's methods, properties, ivars all could still be obtained by looking in other Mach-O sections. So does the same thing apply to Swift types? 

Well... sorta...





<a name="arm64e"></a>
## ARM64e Disk Pointers

TODO, I am burnt out writing and I am sure you are from reading, I'll get to this eventually :] 

## EL FIN

WOW! You read to here!? Here's a 30 minute [video](https://www.youtube.com/watch?v=KCxXPhu3S7o) of me explaining the above concepts.
