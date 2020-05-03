//
//  XRMachOLibrary.m
//  xref
//
//  Created by Derek Selander on 3/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//


/////////////////////////////////////////////////////////
// muwahahahahahaha going to hell for this...
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"

#import "swift/Demangling/Demangler.h"

#pragma clang diagnostic pop
// </muwahahahahahaha going to hell for this...>
/////////////////////////////////////////////////////////

#import "XRMachOLibrary.h"
#import "miscellaneous.h"
#import "XRMachOLibrary.h"
#import "XRMachOLibrary+SymbolDumper.h"
#import "XRMachOLibrary+Opcode.h"
#import "XRMachOLibrary+FAT.h"
#import "XRSymbolEntry.h"
#import "XRMachOLibraryCplusHelpers.h"
#import "payload.hpp"

#import <sys/mman.h>
#import <mach/mach.h>
#import <unordered_map>

#define SOME_DEFAULT_VALUE_FOR_DICT_COUNT 10000
using namespace std;
@interface XRMachOLibrary ()

@property (nonatomic, readonly) NSString *realizedPath;
@property (nonatomic, assign) int maxlibNameLength;
@property (nonatomic, assign) std::unordered_map<uint64_t, XRSymbolEntry*> exports;
@end

namespace llvm {
    int EnableABIBreakingChecks = 0;
}

using namespace payload;

/// Used for an oddball address that no process virtual memory should usually grab
#define MMAP_POTENTIAL_START 0x0000000400000000UL

namespace dshelpers {
    swift::Demangle::DemangleOptions simplifiedOptions = swift::Demangle::DemangleOptions::SimplifiedUIDemangleOptions();
    Context context = Context();
    
    const char *simple_demangle(char *mangled, std::string &strout_ref, swift::Demangle::DemangleOptions options) {
        if (!mangled) { return nullptr; }
        auto str = StringRef(mangled);
        strout_ref = context.demangleSymbolAsString(str, options);
        return strout_ref.c_str();
    }
    
    const char* simple_demangle(const char *mangled, std::string &strout_ref, swift::Demangle::DemangleOptions options) {
        if (!mangled) { return nullptr; }
        auto str = StringRef(mangled);
        strout_ref = context.demangleSymbolAsString(str, options);
        return strout_ref.c_str();
    }
    
    const char *simple_demangle(StringRef mangled, std::string &strout_ref, swift::Demangle::DemangleOptions options) {
        strout_ref = context.demangleSymbolAsString(mangled, options);
        return strout_ref.c_str();
    }
    
    const char *simple_type(StringRef type, std::string &strout_ref ) {
        strout_ref = context.demangleTypeAsString(type, simplifiedOptions);
        return strout_ref.c_str();
    }
    
    const char *simple_type(StringRef type) {
        std::string strout_ref = context.demangleTypeAsString(type, simplifiedOptions);
        return strout_ref.c_str();
    }
    
    bool canDemangle(StringRef mangled) {
        return context.hasSwiftCallingConvention(mangled);
    }
    
    const char *simple_type(char* type, std::string &strout_ref) {
        if (!type)  { return nullptr; }
        auto str = StringRef(type);
        strout_ref = context.demangleTypeAsString(str, simplifiedOptions);
        return strout_ref.c_str();
    }
    const char *simple_type(const char* type, std::string &strout_ref) {
        if (!type)  { return nullptr; }
        auto str = StringRef(type);
        strout_ref = context.demangleTypeAsString(str, simplifiedOptions);
        return strout_ref.c_str();
    }
}

/// Using mmap to specify an address that's not in dsdump's virtual memory and also not in inspected exectuables virtual memory
static void ensureSafeAddressForMMap(size_t memory_size) {
    vm_address_t address = MMAP_POTENTIAL_START;
    vm_size_t vmsize = 0;
    vm_region_basic_info_64 info = {};
    mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object = {};
    kern_return_t status = vm_region_64(mach_task_self(), &address, &vmsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &infoCount, &object);
    
    if (status) {
        printf("Couldn't read own address space, exiting\n");
        exit(1);
    }
    
    if (info.protection != VM_PROT_NONE) {
        printf("%p is mapped to existing memory, exiting\n", (void*)MMAP_POTENTIAL_START);
        exit(1);
    }

    if (address - MMAP_POTENTIAL_START < memory_size) {
        printf("%p region is not large enough, exiting\n", (void*)MMAP_POTENTIAL_START);
        exit(1);
    }
}

////////////////////////////////////////////////////////////////////////////////



@implementation XRMachOLibrary

- (instancetype)initWithPath:(NSString*)path {
    if (self = [super init]) {
        self.path = path;
        
        __unused uintptr_t fatOffset = 0, fatSize = 0;
        self.depdencies = [NSMutableArray array];
        [self.depdencies addObject:(NSString *)[NSNull null]];
        
        self.sectionCommandsArray = [NSMutableArray array];
        [self.sectionCommandsArray addObject:(NSNumber*)[NSNull null]];
        
        self.segmentCommandsArray = [NSMutableArray array];
        self.segmentCommandsDictionary = [NSMutableDictionary dictionary];

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
        
        ensureSafeAddressForMMap(fsize);
        void* buff = ::mmap((void*)MMAP_POTENTIAL_START, fsize, PROT_READ, MAP_PRIVATE, self.fd, 0);

        payload::data = (uint8_t *)buff; // self.data;
        payload::size = fsize;
        
        if (fsize < 4) {
            perror("File too small"); return nil;
        }
        
        if (xref_options.arch) {
            size_t sz = 0;
            payload::offset = [self offsetForArchitecture:[NSString stringWithUTF8String:xref_options.arch] size:&sz];
            if (payload::offset == FAT_OFFSET_BAD_NAME) {
                dprintf(STDERR_FILENO, "%sunknown architecture: \"%s\", available: %s, exiting...%s\n", dcolor(DSCOLOR_RED),xref_options.arch, [self printAllArchitectures].UTF8String, color_end());
                exit(1);
            }
            ::munmap(buff, fsize);
            payload::data = (uint8_t*)::mmap((void*)MMAP_POTENTIAL_START, sz, PROT_READ, MAP_PRIVATE, self.fd, payload::offset);

            payload::offset = 0;
            payload::size = sz;
            
        }
        
   
        auto magic = *payload::GetData<uint32_t>(0); //*(uint32_t *)&_data[_file_offset];
        
        
    // If this is a fat executable, update start, go back here and try again
    LOL:
        
        if (magic == MH_MAGIC || magic == MH_MAGIC) {
            dprintf(STDERR_FILENO, "%sdsdump doesn't support 32 bit architectures :[%s\n", dcolor(DSCOLOR_RED), color_end());
            exit(1);
        } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {

            _header = payload::GetData<struct mach_header_64>(0);
            uintptr_t cur = (uintptr_t)DATABUF(sizeof(struct mach_header_64));
            
            for (int i = 0; i < _header->ncmds; i++) {
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
                    auto functions = payload::GetData<uint8_t>(self.function_starts_cmd->dataoff);
                    
                    const uint8_t* infoStart = (uint8_t*)functions;
                    const uint8_t* infoEnd = ((const uint8_t* )functions) + self.function_starts_cmd->dataoff;
                    struct segment_command_64* code_segment = (struct segment_command_64*)[self.segmentCommandsDictionary[@"__TEXT"] pointerValue];
                    assert(code_segment);
                    
                    uint64_t address = code_segment->vmaddr;
                    if (!self.symbolEntry) {
                        self.symbolEntry = [NSMutableDictionary dictionaryWithCapacity:SOME_DEFAULT_VALUE_FOR_DICT_COUNT];
                    }
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
                    self.symbols = GetData<struct nlist_64>(self.symtab->symoff);
                    self.str_symbols = payload::GetData<char>(self.symtab->stroff);
                    
                } else if (load_cmd->cmd == LC_DYLD_INFO || load_cmd->cmd == LC_DYLD_INFO_ONLY) {
                    self.dyldInfo = (struct dyld_info_command *)load_cmd;
//#warning fix this
                    
                    self.exports.reserve(self.dyldInfo->export_size);
                    // Swift implies Objc so parse 'em even if only Swift
                    if (xref_options.objectiveC_mode || xref_options.swift_mode || xref_options.opcodes) {
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
                    if (cmd->flags & SG_PROTECTED_VERSION_1 && !xref_options.symbol_mode) {
                        // FIXME, implement protected executables
                        // https://github.com/DerekSelander/dsdump/issues/6
                        printf("%s is protected, come again at a later beta\n", cmd->segname);
                        exit(1);
                    }
                    self.segmentCommandsDictionary[segmentKey] = @((uintptr_t)cmd);
                    
                    for (int j = 0; j < cmd->nsects; j++) {
                        struct section_64 section = sections[j];
                        char sect_name[17] = {};
                        memcpy(seg_name, &section.segname, 16);
                        memcpy(sect_name, &section.sectname, 16);
                        NSString *sectionKey = [NSString stringWithFormat:@"%s.%s", seg_name, sect_name];
                        
                        uintptr_t sec_ptr = (uintptr_t)&sections[j];
                        payload::sectionsDict.emplace(std::string(sectionKey.UTF8String), &sections[j]);
                      
                        [self.sectionCommandsArray addObject:@(sec_ptr)];
                        payload::sections.push_back(&sections[j]);
                        
                        if (strcmp(section.segname, SEG_DATA) == 0 && strcmp(section.sectname, "__la_symbol_ptr") == 0) {
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
            exit(1);
            
//            payload::offset = [self offsetForDefaultArchitecture];
//            payload::data = &payload::data[payload::offset];
//            magic = *payload::GetData<uint32_t>(0);
//            goto LOL;
//            assert(0);
            
        } else if (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
            printf("FAT MAGIC 64 headers not implemented... tell Derek what module is using this\n");
            assert(0);
        }
        
        if (self.lazy_ptr_section && self.dysymtab) {
            uintptr_t syms = self.dysymtab->indirectsymoff;
            _indirect_symbols.count = self.dysymtab->nindirectsyms;
            _indirect_symbols.indirect_sym = (uint32_t *)calloc(self.indirect_symbols.count, sizeof(uint32_t));
             pread(_fd, _indirect_symbols.indirect_sym + payload::offset, _indirect_symbols.count * sizeof(uint32_t), syms);
        }
    }
    
    [exploredSet addObject:path];

    if (!self.symbolEntry) {
        self.symbolEntry = [NSMutableDictionary dictionaryWithCapacity:self.dysymtab->nlocalsym + self.dysymtab->nextdefsym];
    }
    
    // DYLD opcodes contain information about ObjC classes, used for classdump
    if (xref_options.objectiveC_mode || xref_options.swift_mode || xref_options.opcodes) {
        [self preparseUndefinedObjectiveCSymbols];
        [self parseDYLDExports];
        
        // Swift can contains methods stripped out, that are given by exported info
        [self parseLocalSymbolsInSymbolTable];
    }
    
    
    if (xref_options.virtual_address) {
        [self handleVirtualAddress];
        exit(0);
    }
    
    if (xref_options.file_offset) {
        [self handleFileOffset];
        exit(0);
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
        
        // Don't need debugging symbols...
        if (symbol->n_type & N_STAB) {
            continue;
        }
        
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

            pread(self.fd, &buf_stub_helper, sizeof(uintptr_t), payload::offset + self.lazy_ptr_section->offset + (PTR_SIZE * i));
            
    
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
//   __unused  uintptr_t f = useFatOffset ? self.file_offset : 0;
    for (int i = 1; i < self.sectionCommandsArray.count; i++) {
        NSNumber *sectionNumber = self.sectionCommandsArray[i];
        struct section_64 *sec = reinterpret_cast<struct section_64 *>(sectionNumber.pointerValue);
        if (sec->addr <= loadAddress && loadAddress < sec->addr + sec->size) {
            return loadAddress - sec->addr  + sec->offset;
        }
    }
    dprintf(STDERR_FILENO, "WARNING: couldn't find address 0x%lx in binary!\n", loadAddress);

    return 0;
}

- (uintptr_t)translateOffsetToLoadAddress:(uintptr_t)offset {
//    assert(0);
    uintptr_t f = 0;
    for (int i = 1; i < self.sectionCommandsArray.count; i++) {
        NSNumber *sectionNumber = self.sectionCommandsArray[i];
        struct section_64 *sec = (struct section_64 *)sectionNumber.pointerValue;

        if (sec->offset <= (offset + f) && (offset + f) < (sec->offset + sec->size)) {
            return offset - sec->offset + sec->addr + f;
        }
    }
    dprintf(STDERR_FILENO, "WARNING: couldn't find offset 0x%lx in binary!\n", offset);
    return 0;
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

/// Display virtual addresses if specified in options
- (void)handleVirtualAddress {
    auto addrs = payload::CastToDisk<uintptr_t>(xref_options.virtual_address);
    auto diskAddr = addrs->disk();
    auto loadAddr = reinterpret_cast<uintptr_t>(addrs->load());
    if (!addrs->validAddress()) {
        printf("Couldn't find virtual address %p\n", addrs);
        exit(1);
    }
    
    section_64 *foundSect = nullptr;
    for (auto &sect : payload::sections) {
        if (sect->addr <= loadAddr && loadAddr <= sect->addr + sect->size) {
            foundSect = sect;
        }
    }
    printf("Virtual 0x%014lx -> Offset 0x%014lx, %s.%s [%p - %p]\n", xref_options.virtual_address, (uintptr_t)diskAddr - (uintptr_t)payload::data, foundSect->segname, foundSect->sectname, (void*)foundSect->addr, (void*)(foundSect->addr + foundSect->size));
    for (int i = 0; i < xref_options.virtual_address_count; i++) {
        auto addr = &diskAddr[i];
        printf("  %s0x%016lx%s:   %s0x%016lx%s %s0x%016lx%s\n", dcolor(DSCOLOR_CYAN), xref_options.virtual_address + (i * PTR_SIZE), color_end(), dcolor(DSCOLOR_YELLOW), *addr, color_end(), dcolor(DSCOLOR_RED), ARM64E_POINTER(*reinterpret_cast<uintptr_t*>(addr)), color_end());
    }
}

/// Display file offset
- (void)handleFileOffset {

    auto addrs = payload::LoadToDiskTranslator<uintptr_t>::Cast(&payload::data[xref_options.file_offset])->loadAddress();
    bool success = false;
    for (NSNumber *sectionAddress in self.sectionCommandsArray) {
        if ([sectionAddress isEqualTo:[NSNull null]]) {
            continue;
        }
        struct section_64 *sect = (struct section_64*)sectionAddress.pointerValue;
        if (sect->addr <= addrs && addrs < (sect->addr + sect->size)) {
            printf("Offset: %s0x%lx (%lu)%s => %s%p%s, found in %s%p - %p%s, %s%s.%s%s\n", dcolor(DSCOLOR_CYAN), xref_options.file_offset, xref_options.file_offset, color_end(), dcolor(DSCOLOR_GREEN), (void*)addrs, color_end(), dcolor(DSCOLOR_YELLOW), (void*)sect->addr, (void*)(sect->addr + sect->size), color_end(), dcolor(DSCOLOR_MAGENTA), sect->segname, sect->sectname, color_end());
            success = true;
            break;
        }
    }
    if (!success) {
        printf("Couldn't find address 0x%lx (%lu)!\n", xref_options.file_offset, xref_options.file_offset);
        exit(1);
    }
}

@end
