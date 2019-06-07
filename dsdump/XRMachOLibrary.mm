//
//  XRMachOLibrary.m
//  xref
//
//  Created by Derek Selander on 3/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary.h"
#import "miscellaneous.h"
#import "XRMachOLibrary.h"
#import "XRMachOLibrary+SymbolDumper.h"
#import "XRMachOLibrary+Opcode.h"
#import "XRMachOLibrary+FAT.h"
#import "XRSymbolEntry.h"
#include <unordered_map>

using namespace std;
@interface XRMachOLibrary ()

@property (nonatomic, readonly) NSString *realizedPath;
@property (nonatomic, assign) int maxlibNameLength;
@property (nonatomic, assign) std::unordered_map<uint64_t, XRSymbolEntry*> exports;
@end

@implementation XRMachOLibrary

- (instancetype)initWithPath:(NSString*)path {
    if (self = [super init]) {
        self.path = path;
        self.depdencies = [NSMutableArray array];
        [self.depdencies addObject:(NSString *)[NSNull null]];
        
        self.sectionCommandsArray = [NSMutableArray array];
        [self.sectionCommandsArray addObject:(NSNumber*)[NSNull null]];
        
        self.segmentCommandsArray = [NSMutableArray array];
        self.sectionCommandsDictionary = [NSMutableDictionary dictionary];
        self.segmentCommandsDictionary = [NSMutableDictionary dictionary];
        
        self.file_offset = 0;
        

        self.addressSymbolDictionary = [NSMutableDictionary dictionaryWithCapacity:800];
        self.externalObjectiveClassesDict = [NSMutableDictionary dictionaryWithCapacity:100];
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:self.resolvedPath]) {
            printf("No file at \"%s\"\n", [self.resolvedPath UTF8String]);
            return nil;
        }
        
        self.fd = open([self.resolvedPath UTF8String], O_RDONLY);
        if (_fd == -1) { perror("Couldn't open file"); return nil; }
        
        FILE* f = fdopen(self.fd, "r");
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);  /* same as rewind(f); */
        self.data = (uint8_t *)malloc(fsize + 1);
        fread(self.data, 1, fsize, f);
        fclose(f);
        if (fsize < 4) {
            perror("File too small"); return nil;
        }
        
        if (xref_options.arch) {
            intptr_t offset = [self offsetForArchitecture:[NSString stringWithUTF8String:xref_options.arch]];
            if (offset == FAT_OFFSET_BAD_NAME) {
                dprintf(STDERR_FILENO, "%sunknown architecture: \"%s\", available: %s, exiting...%s\n", dcolor(DSCOLOR_RED),xref_options.arch, [self printAllArchitectures].UTF8String, color_end());
                exit(1);
            }
            _file_offset += offset;
        }
        uint32 magic = *(uint32_t *)&_data[_file_offset];
        
        
    // If this is a fat executable, it'll go back here and try again
    LOL:
        
        if (magic == MH_MAGIC || magic == MH_MAGIC) {
            dprintf(STDERR_FILENO, "%sxref doesn't support 32 bit architectures :[%s\n", dcolor(DSCOLOR_RED), color_end());
            exit(1);
        } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {

            _header = *(struct mach_header_64 *)&_data[_file_offset];
            _load_cmd_buffer = DATABUF(sizeof(struct mach_header_64) + _file_offset);
            uintptr_t cur = (uintptr_t)_load_cmd_buffer;
            
            for (int i = 0; i < _header.ncmds; i++) {
                struct load_command *load_cmd = (struct load_command *)cur;
                
                if (load_cmd->cmd == LC_LOAD_DYLIB || load_cmd->cmd == LC_LOAD_WEAK_DYLIB || load_cmd->cmd == LC_REEXPORT_DYLIB || load_cmd->cmd == LC_LOAD_UPWARD_DYLIB) {
                    
                    struct dylib_command *dylib_cmd = (struct dylib_command *)cur;
                    NSString * libPath = [NSString stringWithUTF8String:(char *)(cur + dylib_cmd->dylib.name.offset)];
                    [pathsSet addObject:libPath];
                    [self.depdencies addObject:libPath];
                    
                } else if (load_cmd->cmd == LC_BUILD_VERSION) {
                    
                    struct build_version_command *build_version = (struct build_version_command *)cur;
                    self.build_cmd = build_version;
                    
                }  else if (load_cmd->cmd == LC_VERSION_MIN_IPHONEOS) {
                    
                    self.version_cmd = (struct version_min_command *)cur;
                    
                }  else if (load_cmd->cmd == LC_RPATH) {
                    
                    struct rpath_command *r_cmd = (struct rpath_command*)cur;
                    NSMutableString* rpathString = [NSMutableString stringWithUTF8String:(char *)(cur + r_cmd->path.offset)];
                    [rpathSet addObject:rpathString];
                    
                } else if (load_cmd->cmd == LC_FUNCTION_STARTS) {
                    
                    self.function_starts_cmd = (struct linkedit_data_command *)cur;
                    void * functions = &_data[_file_offset + self.function_starts_cmd->dataoff];
                    
                    const uint8_t* infoStart = (uint8_t*)functions;
                    const uint8_t* infoEnd = ((const uint8_t* )functions) + self.function_starts_cmd->dataoff;
                    struct segment_command_64* code_segment = (struct segment_command_64*)[self.segmentCommandsDictionary[@"__TEXT"] pointerValue];
                    assert(code_segment);
                    
                    uint64_t address = code_segment->vmaddr;
                    for(const uint8_t* p = infoStart; (*p != 0) && (p < infoEnd); ) {
                        uint64_t delta = 0;
                        uint32_t shift = 0;
                        bool more = true;
                        do {
                            uint8_t byte = *p++;
                            delta |= ((byte & 0x7F) << shift);
                            shift += 7;
                            if ( byte < 0x80 ) {
                                address += delta;
                                if (!self.symbolEntry[@(address)]) {
                                    XRSymbolEntry *entry = [XRSymbolEntry new];
                                    entry.address = address;
                                    _symbolEntry[@(address)] = entry;
                                }

                         
                                more = false;
                            }
                        } while (more);
                    }
                    
                } else if (load_cmd->cmd == LC_SYMTAB) {
                    
                    self.symtab = (struct symtab_command *)load_cmd;
                    
                    self.symbols = static_cast<struct nlist_64 *>(DATABUF(_file_offset + self.symtab->symoff)); //(struct nlist_64 *)&_data[_file_offset + self.symtab->symoff];
                    self.str_symbols = static_cast<char *>(DATABUF(_file_offset + self.symtab->stroff)); // (char *)&_data[_file_offset + self.symtab->stroff];
     

                } else if (load_cmd->cmd == LC_DYLD_INFO || load_cmd->cmd == LC_DYLD_INFO_ONLY) {
                    
                    self.dyldInfo = (struct dyld_info_command *)load_cmd;
//#warning fix this
                    
                    self.exports.reserve(self.dyldInfo->export_size);
                    if (xref_options.objectiveC_mode) {
                        [self parseDYLDOpcodes];
                        
                    }
                    
                } else if (load_cmd->cmd == LC_DYSYMTAB) {
                    
                    self.dysymtab = (struct dysymtab_command *)load_cmd;
                    
                } else if (load_cmd->cmd == LC_SEGMENT_64) {
             
                    [self.segmentCommandsArray addObject:@(cur)];
                    struct segment_command_64 * cmd = (struct segment_command_64 *)load_cmd;
                    struct section_64 *sections = (struct section_64 *)(cur + sizeof(struct segment_command_64));
                    
                    char seg_name[17] = {};
                    memcpy(seg_name, cmd->segname, 16);
                    NSString *segmentKey = [NSString stringWithUTF8String:seg_name];
                    self.segmentCommandsDictionary[segmentKey] = @((uintptr_t)cmd);
                    
                    for (int j = 0; j < cmd->nsects; j++) {
                        struct section_64 section = sections[j];
                        char sect_name[17] = {};
                        memcpy(seg_name, &section.segname, 16);
                        memcpy(sect_name, &section.sectname, 16);
                        NSString *sectionKey = [NSString stringWithFormat:@"%s.%s", seg_name, sect_name];
                        
                        uintptr_t sec_ptr = (uintptr_t)&sections[j];
                        self.sectionCommandsDictionary[sectionKey] = @(sec_ptr);
                        [self.sectionCommandsArray addObject:@(sec_ptr)];
                        
                        if (strcmp(section.segname, "__DATA") == 0 && strcmp(section.sectname, "__la_symbol_ptr") == 0) {
                            self.lazy_ptr_section = &sections[j]; //calloc(1, sizeof(struct section_64));
                        }
                    }
                    
                } else if (load_cmd->cmd == LC_UUID) {
                    
                    self.uuid_cmd = (struct uuid_command *)calloc(1, sizeof(struct uuid_command));
                    memcpy(self->_uuid_cmd, load_cmd, sizeof(struct uuid_command));
                    
                }
                cur += load_cmd->cmdsize;
            }
            
        } else if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
            // Could only have gotten here if --arch is not specified
            dprintf(STDERR_FILENO, "%sMultiple arches found: %s%s\n", dcolor(DSCOLOR_RED), [self printAllArchitectures].UTF8String, color_end());
            dprintf(STDERR_FILENO, "%sUse --arches (-A) (or ARCH env var) to specify arch, defaulting to: %s%s\n",  dcolor(DSCOLOR_RED), [self defaultArchitectureName].UTF8String, color_end());
            
            intptr_t off = [self offsetForDefaultArchitecture];
            assert(off >= 0);
            _file_offset += off;
            magic = *(uint32_t *)&_data[_file_offset];
            goto LOL;
            assert(0);
            
        } else if (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
            struct fat_arch_64 fatHeader;
            fatHeader = *(struct fat_arch_64 *)_data;
            printf("FAT MAGIC 64 headers not implemented... tell Derek what module is using this\n");
            assert(0);
        }
        
        if (self.lazy_ptr_section && self.dysymtab) {
            uintptr_t syms = (_file_offset + self.dysymtab->indirectsymoff);
            _indirect_symbols.count = self.dysymtab->nindirectsyms;
            _indirect_symbols.indirect_sym = (uint32_t *)calloc(self.indirect_symbols.count, sizeof(uint32_t));
             pread(_fd, _indirect_symbols.indirect_sym, _indirect_symbols.count * sizeof(uint32_t), syms);
        }
    }
    
    [exploredSet addObject:path];
    

    if (!self.symtab) {
        perror("Warning: no symbol table\n");
        return nil;
    }
    
    self.symbolEntry = [NSMutableDictionary dictionaryWithCapacity:self.dysymtab->nlocalsym + self.dysymtab->nextdefsym];
    
    // DYLD opcodes contain information about ObjC classes, used for classdump
    if (xref_options.objectiveC_mode) {
        [self preparseUndefinedObjectiveCSymbols];
        [self parseDYLDExports];
    }
    
    // Swift can contains methods stripped out, that are given by exported info
    if (xref_options.objectiveC_mode) {
        [self parseLocalSymbolsInSymbolTable];
    }
    
    return self;
}

/********************************************************************************
 // Symbol parsing
 ********************************************************************************/

/// Grab externally referenced ObjectiveC Swift classes, which are located in externals in symbol table
- (void)preparseUndefinedObjectiveCSymbols {
    for (int i = self.dysymtab->iundefsym; i < self.dysymtab->nundefsym + self.dysymtab->iundefsym; i++) {
        struct nlist_64 symbol = self.symbols[i];
        char * chr = &self.str_symbols[symbol.n_un.n_strx];
        if (!strnstr(chr, "_OBJC_CLASS_$_", OBJC_CLASS_LENGTH)) { continue; }
        NSString *str = [NSString stringWithUTF8String:chr];
        self.externalObjectiveClassesDict[str] = @(i);
    }
}

- (void)parseLocalSymbolsInSymbolTable {
    // Only goes after local and external symbols
    for (int i = self.dysymtab->ilocalsym; i < self.dysymtab->ilocalsym + self.dysymtab->nlocalsym; i++) {
        struct nlist_64 *symbol = &self.symbols[i];
        XRSymbolEntry *cur = self.symbolEntry[@(symbol->n_value)];
        if (symbol->n_value && !cur.name) {
            XRSymbolEntry *entry = [[XRSymbolEntry alloc] initWithSymbol:symbol machoLibrary:self];
            self.symbolEntry[@(symbol->n_value)] = entry;
        }
    }
    
    for (int i = self.dysymtab->iextdefsym; i < self.dysymtab->iextdefsym + self.dysymtab->nextdefsym; i++) {
        struct nlist_64 *symbol = &self.symbols[i];
        XRSymbolEntry *cur = self.symbolEntry[@(symbol->n_value)];
        if (symbol->n_value && !cur.name) {
            XRSymbolEntry *entry = [[XRSymbolEntry alloc] initWithSymbol:symbol machoLibrary:self];
            self.symbolEntry[@(symbol->n_value)] = entry;
        }
    }
}

/********************************************************************************
//  Find internal methods
********************************************************************************/

- (uintptr_t)externalSymbolStubAddress:(NSString *)symbol {
    
    const char *searched_symbol = [symbol UTF8String];

    size_t count  = (self.lazy_ptr_section->size / (1 << self.lazy_ptr_section->align));
    
    int start = self.lazy_ptr_section->reserved1;
    for (int i = 0; i < count; i++) {
        int offset = self.indirect_symbols.indirect_sym[i + start];
        
        // If stripped' local symbol, you're not gonna find it by name
        if (INDIRECT_SYMBOL_LOCAL & offset) { continue; }
        
        struct nlist_64 sym = self.symbols[offset];
        char * chr = &self.str_symbols[sym.n_un.n_strx];

        if (strcmp(chr, searched_symbol) == 0 || strcmp(&chr[1], searched_symbol) == 0 ) {
            uintptr_t buf_stub_helper;

            pread(self.fd, &buf_stub_helper, sizeof(uintptr_t), self.file_offset + self.lazy_ptr_section->offset + (PTR_SIZE * i));
            
    
            return self.lazy_ptr_section->addr + (PTR_SIZE * i);
        }
    }
    
    return 0;
}

/********************************************************************************
// Helper debugging methods 
********************************************************************************/

- (NSString *)description {
    return [NSString stringWithFormat:@"(%p) %@", self, self.realizedPath];
}

- (NSUInteger)hash {
    return [self.path hash];
}

/********************************************************************************
 // Translate load/file addresses
 ********************************************************************************/

- (uintptr_t)translateLoadAddressToFileOffset:(uintptr_t)loadAddress useFatOffset:(BOOL)useFatOffset {
   __unused  uintptr_t f = useFatOffset ? self.file_offset : 0;
    for (int i = 1; i < self.sectionCommandsArray.count; i++) {
        NSNumber *sectionNumber = self.sectionCommandsArray[i];
        struct section_64 *sec = reinterpret_cast<struct section_64 *>(sectionNumber.pointerValue);
        if (sec->addr <= loadAddress && loadAddress < sec->addr + sec->size) {
            return loadAddress - sec->addr  + sec->offset + f;
        }
    }
    dprintf(STDERR_FILENO, "WARNING: couldn't find address 0x%lx in binary!\n", loadAddress);

    return 0;
}

- (uintptr_t)translateOffsetToLoadAddress:(uintptr_t)offset {
    uintptr_t f = -self.file_offset;
    for (int i = 1; i < self.sectionCommandsArray.count; i++) {
        NSNumber *sectionNumber = self.sectionCommandsArray[i];
        struct section_64 *sec = (struct section_64 *)sectionNumber.pointerValue;
        
        if (sec->offset <= (offset + f) && (offset + f) < sec->offset + sec->size) {
            return offset - sec->offset + sec->addr + f;
        }
    }
    dprintf(STDERR_FILENO, "WARNING: couldn't find offset 0x%lx in binary!\n", offset);
    return 0;
}

/********************************************************************************
 // PAC crap
 ********************************************************************************/

- (BOOL)isARM64e {
    static dispatch_once_t onceToken;
    static BOOL isARM64e = NO;
    __weak XRMachOLibrary * wself = self;
    dispatch_once(&onceToken, ^{
        XRMachOLibrary *sself = wself;
        cpu_type_t type = *(cpu_type_t *)&sself->_data[sself->_file_offset + 4];
        cpu_subtype_t subtype = *(cpu_subtype_t *)&sself->_data[sself->_file_offset + 8];
        
        isARM64e = ((CPU_ARCH_ABI64|CPU_TYPE_ARM) == type && CPU_SUBTYPE_ARM64E == subtype) ? YES : NO;
    });
    return isARM64e;
}

/********************************************************************************
 // misc methods
 ********************************************************************************/

- (NSString *)resolvedPath {
    if (_realizedPath) {
        return _realizedPath;
    }
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:self.path]) {
        _realizedPath = self.path;
        return _realizedPath;
    }
    
    if ([self.path hasPrefix:@"@rpath"]) {
        
        static dispatch_once_t once;
        static NSString *executablePath = nil;
        dispatch_once(&once, ^{
            executablePath = [self.path stringByDeletingLastPathComponent];
        });
        
        NSString *rpathReplacement = nil;
        for (NSString *potentialPath in rpathSet) {
            if ([potentialPath hasPrefix:@"@loader_path"]) {
                rpathReplacement = [potentialPath stringByReplacingOccurrencesOfString:@"@loader_path" withString:executablePath];
            } else if ([potentialPath hasPrefix:@"@executable_path"]) {
                rpathReplacement = [potentialPath stringByReplacingOccurrencesOfString:@"@executable_path" withString:executablePath];
            }
            
            NSString *realizedPath = [self.path stringByReplacingOccurrencesOfString:@"@rpath" withString:rpathReplacement];
            
            if ([[NSFileManager defaultManager] fileExistsAtPath:realizedPath]) {
                _realizedPath = realizedPath;
                return realizedPath;
            }
        }
        
        return [self.path stringByReplacingOccurrencesOfString:@"@rpath" withString:[self.path stringByDeletingLastPathComponent]];
    }
    return self.path;
}

@end