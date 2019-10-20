## Building a class-dump in 2019

## This is being actively worked on, this message will disappear when I am happy with the writeup

Building out a "class-dump"-like introspection tool for Apple platforms has changed considerably since the original [class-dump](http://stevenygard.com/projects/class-dump/) came out. Learning these new (and old) technologies can be quite intimidating due to the steep learning curve.

This article attempts to explain the complete process of programmatically inspecting a [Mach-O](https://en.wikipedia.org/wiki/Mach-O) (Apple) binary by discussing the following:

* [Mach-O File Format](#apples_mach-o_file_format)
* [The Symbol Table](#the_symbol_table)
* [DYLD Opcodes and Binding](#dyld_opcodes_and_binding)
* Objective-C Class Layout
* Swift Types Layout
* ARM64e disk pointers

---
**Note:** You *should* be comfortable with C before reading this article. If you can understand this, then you're good to go
```c
int32_t* a = NULL;
int64_t* b = NULL;
if (++a != ++b) {
	// you understand pointer arithmetic
} else {
	// google "pointer arithmetic"
}
```

---

<a name="apples_mach-o_file_format"></a>
### Apple's Mach-O File Format

The Mach-O file format is the "table of contents" and layout of every Mach-O (read Apple) **image**. An image can be a number of different compiled, executable code including (but not limited to) executables, frameworks, dylibs, etc

There are many great sources out there that already cover the topic well. 

* [PARSING MACH-O FILES](https://lowlevelbits.org/parsing-mach-o-files/)
* [Mirror of OS X ABI Mach-O File Format Reference](https://github.com/aidansteele/osx-abi-macho-file-format-reference)
* [Inside a Hello World executable on OS X](https://adrummond.net/posts/macho)

And if you want to pay money for some Mach-O tutorials...

* [Advanced Apple Debugging and Reverse Engineering, Chp 18, 19](https://store.raywenderlich.com/products/advanced-apple-debugging-and-reverse-engineering) (fair warning, that link benefits me)
* [MacOS and iOS Internals, Volume I: User Mode, Chp 5](http://www.newosxbook.com/index.php)


Although, there's many references out there, this stuff will not stick unless you play with it yourself so...

In the file `<mach-o/loader.h>`, there exists a struct called **`mach_header_64`** that is the beginning to all 64-bit Apple executables (well, sorta, it actually depends on some things like FAT files, but don't think about that now). This will very likely apply to you, unless you are running an "ancient" version of OS X with ancient hardware

---
**Note**

When referring to C System headers on your OS X machine, you can usually resolve the header location to the following Terminal command:


```bash
echo $(xcrun --show-sdk-path)/usr/include
```

This resolve to the base directory, so the resolved filepath can be viewed via:

```bash
cat $(xcrun --show-sdk-path)/usr/include/mach-o/loader.h | less -R
```

---

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

Cross reference this with any compiled executable. I'll pick **grep**, feel free to pick anything else:

```bash
xxd -g 4 -e $(which grep) | head -2
```
The `xxd` command will dump the raw data of an executable to `stdout`. The `-g 4` says to group all the values into 4 bytes, which is perfect since each member in the mach_header_64 struct is a 4 byte value. The `-e` option says to format the output in little-endian byte order. If any of this is confusing, The Advanced Apple Deubgging book goes into much more detail about this. 

This produces something similar to:

```none
00000000: feedfacf 01000007 80000003 00000002  ................
00000010: 00000013 00000750 00200085 00000000  ....P..... .....
```
Going through the `mach_header_64` struct members:

* Cross referencing the output with the `<mach-o/loader.h>`, we can see that the `0xfeedfacf` means it's a 64-bit compiled image (`MH_MAGIC_64`).
* The `0x01000007` can be resolved via `<mach/machine.h>` to realize it's compiled for a `CPU_TYPE_X86_64` type of machine.
* The `0x80000003` can be resolved via the same `<mach/machine.h>`header to realize it's the or'ing of `CPU_SUBTYPE_X86_ALL|CPU_SUBTYPE_LIB64`
* The `0x00000002` value is given by the `MH_EXECUTE`, meaning it's an executable (and not a library or something else)
* Following the `filetype` in the struct is the `ncmds`, with 19 **load commands** (`0x00000013` == 19)

I'll let you figure the remaining struct members out yourself.

You can view this in an alternative way by running `otool -h` to view the Mach-O header.

```bash
otool -h $(which grep)
```

This produces the following on my machine:

```none
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
 0xfeedfacf 16777223          3  0x80           2    19       1872 0x00200085
 ```

### Load Commands

It's these load commands (given by the `ncmds` from the `mach_header_64`) that can be interesting when exploring a compiled executable.

Use `otool`'s `-l` option to display an image's load commands:

```bash
otool -l $(which grep)
```

When exploring memory and the load commands, different areas of memory are grouped together. These Mach-O groupings are called **Segments**. Segments will have different memory permissions. For example in `grep`:

```bash 
lolgrep:~$ otool -l $(which grep) | grep LC_SEGMENT -A10
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

There's a Mach-O segment called **__PAGEZERO** which when loaded into memory, has no memory permissions (see `maxprot`, and `initprot`). That means you can read, write, nor execute anything that resides in this memory.  

Below the `__PAGEZERO` segment, there's the `__TEXT` segment. This segment has readable and executable permissions due to the `initprot` value. How did I translate the value 5 to readable and writable? 

Think of this in bits

```
exeuctable writeable readable
1          1         1
```

The value 5 is 0b101 in binary, meaning everything except writable.

The next interesting part is the `nsects` value immediately below the `initprot` field. Inside a Mach-O Segment, there can be 0 or more "subcomponents" called **sections**.

These sections group certain parts of functionality in an executable. Inside the `__TEXT` segment, there are 7 sections for `grep`

Using `grep` to only show the Mach-O sections in `grep` 

```bash
otool -l $(which grep) | grep __TEXT -B2 -A9
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

From the above output, the first section inside the `__TEXT` segment is a section (confusingly) called `__text`. It's this section where compiled code (typically, unless someone is doing something sneaky) resides.

There are many, many interesting Mach-O sections. One could write a novel on just this topic. Again, check out the links above to learn more about the different types of sections. 

#### File Offsets => Virtual Addresses (and back)

The Mach-O sections provide a great insight into the virtual address as well as the file offset on disk.

Consider an extremely simple C file, **ex.c**:

```c
int SomeGlobalInt = 8;
int SecondGlobalInt = 7;
int main() {
  return 0;
}
```

Upon compiling and querying the Mach-O section locations for the global integers
```bash
clang ex.c -o ex
```

Using the `nm` tool (which displays symbol table information, more on that later...)

```bash
nm -m ex | grep GlobalInt
0000000100001004 (__DATA,__data) external _SecondGlobalInt
0000000100001000 (__DATA,__data) external _SomeGlobalInt
```

The `-m` option says to show the Mach-O section when displaying locally implemented symbols

The globals are located in the `__DATA` segment inside the `__data` section, at virtual address `0x000000100001000` and `0x00000100001004`

One can translate these virtual addresses to the file offset by consulting the Mach-O section load commands.

```bash
otool -l ex | grep __data -A10
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

The size of the `__data` section is 8 bytes (due to the 2 4 byte integers). The virtual address of the `__data` section is at `0x0000000100001000`. The offset on disk in the executable to the `__data` section is at `4096`. 

You can verify this with `xxd` again...

```bash
xxd -g 4 -e -s 4096 ex  | head -1
00001000: 00000008 00000007 00000000 00000000  ................
```

Breaking the options down:
* `-g 4`   : group into 4 bytes
* `-e`     : little endian mode
* `-s 4096`: Start at offset 4096

You can use the following format to translate virtual addresses to file offsets with the following formula: 

```c
resolved_file_offset = (virtual_symbol_address - containing_macho_section_virtual_address) + contain_macho_section_file_offset
```


#### NO pie disable pie 



### LC_SOURCE_VERSION

https://opensource.apple.com/tarballs/text_cmds/text_cmds-99.tar.gz

https://opensource.apple.com/source/text_cmds/text_cmds-99/grep/grep.c.auto.html


<a name="the_symbol_table"></a>
## Symbol Table

One of the load commands is called 

<a name="dyld_opcodes_and_binding"></a>
## DYLD Opcodes and Binding
<!-- 
You can use the [editor on GitHub](https://github.com/DerekSelander/dsdump/edit/master/docs/index.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Markdown

Markdown is a lightweight and easy-to-use syntax for styling your writing. It includes conventions for

```markdown
Syntax highlighted code block

# Header 1
## Header 2
### Header 3

- Bulleted
- List

1. Numbered
2. List

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/DerekSelander/dsdump/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
 -->


## ARM64e Disk Pointers
