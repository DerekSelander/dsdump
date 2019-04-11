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

@property (nonatomic, assign) uintptr_t *cfstring_buffer; 
@property (nonatomic, assign) struct symtab_command *symtab;
@property (nonatomic, assign) struct dysymtab_command *dysymtab;
@property (nonatomic, assign) struct nlist_64 *symbols;
@property (nonatomic, assign) char *str_symbols;



@property (nonatomic, assign) struct linkedit_data_command *function_starts_cmd;

/// __DATA.__la_symbol_ptr
@property (nonatomic, assign) struct section_64 *lazy_ptr_section;

@property (nonatomic, assign) struct dyld_info_command *dyldinfo;

/// __TEXT.__stubs
@property (nonatomic, assign) struct section_64 *stubs_section;

/// __TEXT.__stub_helper
@property (nonatomic, assign) struct section_64 *stub_helper_section;

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

- (void)findAddressInCode:(uintptr_t)address;
- (void)findAddressesForSymbolInCode:(NSString *)symbol;
- (void)findOffsetsInCode:(uintptr_t)file_offset;
@end

NS_ASSUME_NONNULL_END


/*
 * The following are used to encode binding information
 */
#define BIND_TYPE_POINTER                    1
#define BIND_TYPE_TEXT_ABSOLUTE32                2
#define BIND_TYPE_TEXT_PCREL32                    3

#define BIND_SPECIAL_DYLIB_SELF                     0
#define BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE            -1
#define BIND_SPECIAL_DYLIB_FLAT_LOOKUP                -2

#define BIND_SYMBOL_FLAGS_WEAK_IMPORT                0x1
#define BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION            0x8

#define BIND_OPCODE_MASK                    0xF0
#define BIND_IMMEDIATE_MASK                    0x0F
#define BIND_OPCODE_DONE                    0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB            0x20
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM        0x40
#define BIND_OPCODE_SET_TYPE_IMM                0x50
#define BIND_OPCODE_SET_ADDEND_SLEB                0x60
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB            0x70
#define BIND_OPCODE_ADD_ADDR_ULEB                0x80
#define BIND_OPCODE_DO_BIND                    0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            0xA0
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED            0xB0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB        0xC0


/*
 * The following are used on the flags byte of a terminal node
 * in the export information.
 */
#define EXPORT_SYMBOL_FLAGS_KIND_MASK                0x03
#define EXPORT_SYMBOL_FLAGS_KIND_REGULAR            0x00
#define EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL            0x01
#define EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION            0x04
#define EXPORT_SYMBOL_FLAGS_REEXPORT                0x08
#define EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER            0x10
