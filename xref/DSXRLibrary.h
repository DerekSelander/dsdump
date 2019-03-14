//
//  DSXRLibrary.h
//  xref
//
//  Created by Derek Selander on 3/7/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import <Foundation/Foundation.h>
@import MachO;

NS_ASSUME_NONNULL_BEGIN

/// Deal with 32/64 in one value
typedef union {
    struct mach_header_64 h64;
    struct mach_header h;
} macho_generic_header;


typedef struct {
    long count;
    uint32_t *indirect_sym;
} indirect_symbols_t;

@interface DSXRLibrary : NSObject {

}

/// Library dependencies
@property (nonatomic, strong) NSMutableArray <NSString *>*depdencies;
@property (nonatomic, copy) NSString *path;

@property (nonatomic, assign) macho_generic_header header;

/// The initial MachO command to dictate the file, other ivars will reference offsets of this
@property (nonatomic, assign) void *load_cmd_buffer;


/// Offsets into each load command struct section
@property (nonatomic, strong) NSMutableArray <NSNumber *>* section_cmds;
@property (nonatomic, strong) NSMutableArray <NSNumber *>* segment_cmds;

@property (nonatomic, strong) NSMutableArray <NSNumber *>* function_starts;
@property (nonatomic, assign) struct build_version_command *build_cmd;
@property (nonatomic, assign) struct version_min_command *version_cmd;
@property (nonatomic, assign) struct uuid_command *uuid_cmd; 

@property (nonatomic, assign) struct symtab_command *symtab;
@property (nonatomic, assign) struct dysymtab_command *dysymtab;
@property (nonatomic, assign) struct nlist_64 *symbols;
@property (nonatomic, assign) char *str_symbols;

@property (nonatomic, assign) struct linkedit_data_command *function_starts_cmd;

/// __DATA.__la_symbol_ptr
@property (nonatomic, assign) struct section_64 *lazy_ptr_section;

/// __TEXT.__stubs
@property (nonatomic, assign) struct section_64 *stubs_section;

/// __TEXT.__text
@property (nonatomic, assign) struct section_64 *code_section;
@property (nonatomic, assign) struct segment_command_64 *code_segment;
@property (nonatomic, assign) struct section_64 *sections;

/// The indirect symbol table *int that points to actual symbols
@property (nonatomic, assign) indirect_symbols_t indirect_symbols;
@property (nonatomic, assign) uintptr_t file_offset;
- (instancetype)initWithPath:(NSString*)path;
- (void)dumpSymbols;
- (void)dumpExternalSymbols;
- (void)findAddressInCode_x86:(uintptr_t)address;
- (void)findAddressesForSymbolInCode:(NSString *)symbol;
- (void)findOffsetsInCode:(uintptr_t)file_offset;
@end

NS_ASSUME_NONNULL_END
