//
//  XRMachOLibrary.h
//  xref
//
//  Created by Derek Selander on 3/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//


#import "miscellaneous.h"
#import "XRMachOLibrary.h"
#import "XRBindSymbol.h"

#import <Foundation/Foundation.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/fat.h>

#define DATABUF(offset) ((void*)&payload::data[(offset)])

///
#define ARM64e_PTRMASK(data)  (self.isARM64e ? ((data)&0x000007FFFFFFFFFFUL) : (data))

NS_ASSUME_NONNULL_BEGIN

extern NSMutableSet <NSString*> *pathsSet;
extern NSMutableSet <NSString*> *exploredSet;
extern NSMutableSet <NSString*> *rpathSet;

@class XRSymbolEntry;

/// Deal with 32/64 in one value
typedef union {
    struct mach_header_64 h64;
    struct mach_header h;
} macho_generic_header;


typedef struct {
    long count;
    uint32_t *indirect_sym;
} indirect_symbols_t;

// An authenticated pointer is:
typedef struct {
    // {
    int32_t addend;
    uint16_t diversityData;
    uint16_t hasAddressDiversity : 1;
    uint16_t key : 2;
    uint16_t zeroes : 11;
    uint16_t zero : 1;
    uint16_t authenticated : 1;
} PACPointer;

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif
    

@interface XRMachOLibrary : NSObject {
    size_t _instructions_count;
}


/// Library dependencies
@property (nonatomic, strong) NSMutableArray <NSString *>*depdencies;
@property (nonatomic, copy) NSString *path;
@property NSString *testFUCK;


//#define ARM64e_PTRMASK(data)  (data)
@property (nonatomic, readonly) BOOL isARM64e;

/// File descriptor
@property (nonatomic, assign) int fd;


@property (nonatomic, assign) struct mach_header_64 header;

@property (nonatomic, strong) NSMutableDictionary <NSString*, XRBindSymbol*> *stringObjCDictionary;
@property (nonatomic, strong) NSMutableDictionary <NSNumber*, XRBindSymbol*> *addressObjCDictionary;
@property (nonatomic, strong) NSMutableArray <XRBindSymbol *>* threadedHolder;

@property (nonatomic, strong) NSMutableDictionary <NSNumber*, NSNumber*> *addressSymbolDictionary;
@property (nonatomic, strong) NSMutableDictionary <NSString*, NSNumber*> *externalObjectiveClassesDict;

/// The initial MachO command to dictate the file, other ivars will reference offsets of this
@property (nonatomic, assign) void *load_cmd_buffer;


/// Offsets into each load command struct section
@property (nonatomic, strong) NSMutableArray <NSNumber *>* sectionCommandsArray;
@property (nonatomic, strong) NSMutableArray <NSNumber *>* segmentCommandsArray;
@property (nonatomic, strong) NSMutableDictionary <NSString *, NSNumber *>* sectionCommandsDictionary;
@property (nonatomic, strong) NSMutableDictionary <NSString *, NSNumber *>* segmentCommandsDictionary;


@property (nonatomic, assign) struct build_version_command *build_cmd;
@property (nonatomic, assign) struct version_min_command *version_cmd;
@property (nonatomic, assign) struct uuid_command *uuid_cmd; 

@property (nonatomic, assign) struct symtab_command *symtab;
@property (nonatomic, assign) struct dysymtab_command *dysymtab;
@property (nonatomic, assign) struct nlist_64 *symbols;
@property (nonatomic, assign) char *str_symbols;

@property (nonatomic, assign) uint8_t *data;
@property (nonatomic, strong) NSMutableDictionary<NSNumber *, XRSymbolEntry *>*symbolEntry;




@property (nonatomic, assign) struct linkedit_data_command *function_starts_cmd;
@property (nonatomic, assign) struct section_64 *lazy_ptr_section;
@property (nonatomic, assign) struct dyld_info_command *dyldInfo;

/// The indirect symbol table *int that points to actual symbols
@property (nonatomic, assign) indirect_symbols_t indirect_symbols;
@property (nonatomic, assign) uintptr_t file_offset;

- (instancetype)initWithPath:(NSString*)path;
- (NSString *)realizedPath;


- (uintptr_t)translateLoadAddressToFileOffset:(uintptr_t)loadAddress useFatOffset:(BOOL)useFatOffset;
- (uintptr_t)translateOffsetToLoadAddress:(uintptr_t)offset;


@end


/// File handling logic
@interface XRMachOLibrary (FileManagement)


@end

NS_ASSUME_NONNULL_END
