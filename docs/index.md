## Building a class-dump in 2019

## This is being actively worked on, this message will disappear when I am happy with the writeup

Building out a "class-dump"-like introspection tool for Apple platforms has changed considerably since the original [class-dump](http://stevenygard.com/projects/class-dump/) came out. Learning these new (and old) technologies can be quite intimidating for the uninitiated. 

This article attempts to explain the complete process of programmatically inspecting a [Mach-O](https://en.wikipedia.org/wiki/Mach-O) (Apple) binary by discussing the following:

* [Mach-O File Format](#apples_mach-o_file_format)
* [The Symbol Table](#the_symbol_table)
* [DYLD Opcodes and Binding](#dyld_opcodes_and_binding)
* Objective-C Class Layout
* Swift Types Layout
* ARM64e disk pointers

---
**Note:** You should be comfortable with C before reading this article. If you can understand this, then you're good to go
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

There are many great sources out there that already cover topic well. 

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

Cross reference this with any compiled Terminal executable. I'll pick **grep**, feel free to pick anything else:

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


#### File Offsets => Virtual Addresses (and back)


### LC_SOURCE_VERSION

https://opensource.apple.com/tarballs/text_cmds/text_cmds-99.tar.gz

https://opensource.apple.com/source/text_cmds/text_cmds-99/grep/grep.c.auto.html


## Symbol Table

One of the load commands is called 

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
