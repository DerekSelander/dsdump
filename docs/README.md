# clsdmp

**clsdmp** is an up to date implementation of `nm` and `class-dump` for MachO (Apple) binaries. It lists symbols and Objective-C/Swift classes

## Installing 

Upon building the repo, xref will install itself in `/usr/local/bin`. Make sure you have write access to that directory and it's already created else the Xcode project will fail to build. 

## Usage
```
 Usage: xref <options> macho_file
 A cross between nm and vmmap for finding references to symbols (C, ObjC, Swift), both statically and in programs in memory
  --objc      Dumps Objective-C classes

  --swift     Dumps Swift classes

  --all       Search in all functions, even ones that are stripped out

  --arch      (-A) <arch> Display info for specified arch (defaults to your CPU)

  --verbose   (-v) <level>  verbose modes, there are 4 levels

  --symbol    (-s) <symbol> Find references to a symbol, use --objc for non-C

  --undefined (-u) Dump only undefined (externally referenced) symbols

  --defined   (-U) Dump only defined (internally implemented) symbols

  --library   (-l) Dump only defined (internally implemented) symbols

  --color     (-c) Everything is so much better in cOLoR!

 Examples
    # dump all Objective-C classes (implemented/referenced) by launchd with color, display super class
    xref --objc /sbin/launchd -vc

    # dump implemented Objective-C classes and methods
    xref --objc /sbin/launchd -vvvcU

    # dump externally referenced symbols
    xref /sbin/launchd -vcu

    # dump programs that link to MobileDevice in their process address space
    sudo xref -l /System/Library/PrivateFrameworks/MobileDevice.framework/MobileDevice

Environment variables
    DSCOLOR	Same as -c

    DEBUG	Used for testing... those damn dyld opcodes

    ARCH	Same as -A to specify the architecture
 ```

[![img](media/vmmap.png)](https://store.raywenderlich.com/products/advanced-apple-debugging-and-reverse-engineering)
