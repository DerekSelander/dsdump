## Building a class-dump in 2019

Building out a "class-dump"-like introspection tool for Apple platforms has changed considerably since the original [class-dump](http://stevenygard.com/projects/class-dump/) came out. Learning these new (and old) technologies can be quite intimidating for the uninitiated. 

This article attempts to explain the complete process of programmatically inspecting a [Mach-O](https://en.wikipedia.org/wiki/Mach-O) (Apple) binary by discussing the following:

* [The Mach-O File Format](#the-mach-o-file-format)
* [The Symbol Table](#the-symbol-table)
* [DYLD Opcodes and Binding](#dyld-opcodes-and-binding)
* Objective-C Class Layout
* Swift Types Layout
* ARM64e disk pointers

---
**Note:** You should be (midly) comfortable with C before reading this article. If no, Google "c pointer arithmetic" and "c pointers" first 👍 

---

### The Mach-O File Format

The Mach-O file format is the "table of contents" and layout of every Mach-O (read Apple) image. This includes executables, frameworks, dylibs, anything that is a compiled executable.

There are many great sources out there that already cover topic well. 

* [PARSING MACH-O FILES](https://lowlevelbits.org/parsing-mach-o-files/)
* [Mirror of OS X ABI Mach-O File Format Reference](https://github.com/aidansteele/osx-abi-macho-file-format-reference)
* [Inside a Hello World executable on OS X](https://adrummond.net/posts/macho)
* [Let's Build a Mach-O Executable](https://www.mikeash.com/pyblog/friday-qa-2012-11-30-lets-build-a-mach-o-executable.html)

And if you want to pay money for a Mach-O tutorials...

* [Advanced Apple Debugging and Reverse Engineering, Chp 18, 19](https://store.raywenderlich.com/products/advanced-apple-debugging-and-reverse-engineering)
* [MacOS and iOS Internals, Volume I: User Mode, Chp 6](http://www.newosxbook.com/index.php)


Although, there's many references out there, this stuff will not stick unless you play with it yourself so if the Mach-O concept is new to you, please follow along in your `Terminal`.

In the file `<mach-o/loader.h>`, there exists a struct called **`mach_header_64`** that is the beginning to all 64-bit Apple executables (well, sorta, it actually depends on some things like FAT files, but don't think about that now). This will very likely apply to you, unless you are running an "ancient" 32-bit version of OS X with ancient hardware

---

**Note:** When referring to C headers on your OS X machine, you can usually resolve the header location to the following Terminal command:

```bash
echo $(xcrun --show-sdk-path)/usr/include
```

This resolve to the base directory, so the resolved `<mach-o/loader.h>` filepath can be viewed via:

```bash
cat $(xcrun --show-sdk-path)/usr/include/mach-o/loader.h | less -R
```

---

Looking at the `mach_header_64` struct, it has the following format:

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

Cross reference the `mach_header_64` with any compiled Terminal executable. I'll pick **`grep`**, you pick anything else:

```bash
xxd -g 4 -e $(which grep) | head -2
```
The `xxd` command will dump the raw data of an executable to `stdout`. The `-g 4` says to group all the values into 4 bytes, which is perfect since each member in the mach_header_64 struct is 4 bytes. The `-e` option says to format the output in little-endian byte order. If any of this is confusing, The Advanced Apple Deubgging book goes into much more detail about this. 

This produces something similar to:

```none
00000000: feedfacf 01000007 80000003 00000002  ................
00000010: 00000013 00000750 00200085 00000000  ....P..... .....
```
Cross referencing the `mach_header_64` header with the raw data, one can see the following:

* The `0xfeedfacf` means it's a 64-bit compiled image, determined by the `MH_MAGIC_64` value found in `<mach-o/loader.h>`.
* The `0x01000007` can be resolved via `<mach/machine.h>` to realize it's compiled for a `CPU_TYPE_X86_64` type of machine.
* The `0x80000003` can be resolved via the same `<mach/machine.h>`header to realize it's the or'ing of `CPU_SUBTYPE_X86_ALL|CPU_SUBTYPE_LIB64`
* The `0x00000002` value is given by the `MH_EXECUTE`, meaning it's an executable (it can run by itsef, AKA not a library).
* Following the `filetype` in the struct is the `ncmds`, which 0x13 (19 in decimal) commands.

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

It's these load commands (given by the `ncmds` from the `mach_header_64`) that can be interesting when exploring a compiled executable. The load commands tell where certain parts are located on disk (fileoffset) and where that code will be loaded into memory (virtual memory).

You can use `otool` to dump all the load commands. Picking on `grep` again...

```bash
otool -l $(which grep) 
```

The output is quite a bit. Take note of all the output that begins with **LC_**. That is the `ncmds` count that gave the 19 value earlier in the header. You can verify with the following:

```bash
otool -l $(which grep) | grep LC_ | wc -l
```

---

**Note:** You can use the **`otool`** command on your OS X machine to query the load commands in an executable. I'd also recommend checking out [jtool2](http://www.newosxbook.com/tools/jtool2.tgz)  

---

There are *many* important load commands, but we'll focus on one of the most important ones first: the `LC_SEGMENT_64` load command. This load command chunks a "grouping" of memory together when loaded into a process. 

For example, there's usually a **`__TEXT`** segment that has readable and executable memory permissions, but are not writable. There's usually a **`__DATA`** segment that writeable and readable but not executable permissions when loaded into memory. 

Inside a segment command can include 0 or more **sections**. A Mach-O section has a specific intention/purpose inside of the executable. For example, all compiled executable code usually resides inside a **`__text`** section, which resides inside of the `__TEXT` segment. In addition, there's a section that stores hardcoded strings typically inside of the `__cstring` section, which is also placed inside the `__TEXT` segment.

*The breakdown of these sections and what they do can be a novel in themselves, I and others have already written about this, so check the above links if you want to know more*


### The `LC_SOURCE_VERSION` Load Command

Not totally relevant, but something that is useful if you are learning this stuff for the first time is the usefulness of **`LC_SOURCE_VERSION`**, especially when using it with [opensource.apple.com](https://opensource.apple.com)

If you wanted to find the source control to `grep` for your OS X machine, all you have to do is run the following:

```bash
otool -l $(which grep)  | grep LC_SOURCE_VERSION -A2
```

Which gives the following on my machine:

```none
      cmd LC_SOURCE_VERSION
  cmdsize 16
  version 99.0
```

This **99.0** version will match in the links that Apple posts to their opensource repos. For example, here's the exact source that was used to build `grep` for my machine:
[https://opensource.apple.com/source/text_cmds/text_cmds-99/grep/grep.c](https://opensource.apple.com/source/text_cmds/text_cmds-99/grep/grep.c)

And the tarball:
[https://opensource.apple.com/tarballs/text_cmds/text_cmds-99.tar.gz](https://opensource.apple.com/tarballs/text_cmds/text_cmds-99.tar.gz)



## The Symbol Table

There's also the **`LC_SYMTAB`** load command. This command will showcase the offset of where the symbol table is embedded inside the executable.

The symbol table is an array of `nlist_64` that indicate what the executable includes as symbols and what it exports for other consumers.

The `nlist_64` struct has the following format

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

Inspecting `grep`...

```bash
otool -l $(which grep) | grep LC_SYMTAB -A5
```

Produces the following on my machine:

```bash
     cmd LC_SYMTAB
 cmdsize 24
  symoff 21848
   nsyms 77
  stroff 23652
 strsize 816
```

For me, the symbol table is at offset **21848**.

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