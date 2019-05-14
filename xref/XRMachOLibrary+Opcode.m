//
//  XRMachOLibrary+Opcode.m
//  xref
//
//  Created by Derek Selander on 4/21/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary+Opcode.h"
#import "miscellaneous.h"
#import "XRBindSymbol.h"

@import MachO;

static NSMutableArray <XRBindSymbol *>* threadedHolder = nil;


#define BIND_THAT_BAD_BOY [self addToDictionaries:segStartAddr+segOffset symbol:symbolName libord:libraryOrdinal addend:addend]

static uint64_t read_uleb128(const uint8_t** p, const uint8_t* end)
{
    uint64_t result = 0;
    int         bit = 0;
    do {
        if (*p == end) {assert(0);}
        
        uint64_t slice = **p & 0x7f;
        
        if (bit >= 64 || slice << bit >> bit != slice) { assert(0); }
            
        else {
            result |= (slice << bit);
            bit += 7;
        }
    }
    while (*((*p)++) & 0x80);
    return result;
}

static int64_t read_sleb128(const uint8_t** p, const uint8_t* end)
{
    int64_t result = 0;
    int bit = 0;
    uint8_t byte;
    do {
        if (*p == end) { assert(0); }
        byte = *((*p)++);
        result |= ((byte & 0x7f) << bit);
        bit += 7;
    } while (byte & 0x80);
    // sign extend negative numbers
    if ( (byte & 0x40) != 0 )
        result |= (-1LL) << bit;
    return result;
}

@implementation XRMachOLibrary (Opcode)

- (void)parseOpcodes {
    assert(self.dyldInfo);
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        threadedHolder = [NSMutableArray arrayWithCapacity:100];
        self.addressObjCDictionary = [NSMutableDictionary dictionaryWithCapacity:100];
    });
    
//    uint8_t *bind_buffer = &self.data[self.dyldInfo->bind_off + self.file_offset];
    
//    int i = 0;
//    uint64_t bind_address = 0;
//    char *symbol = NULL;
//    char type = 0;
//    uint64_t segment = 0;
//    uint64_t seg_off = 0;
//    uint64_t addend = 0;
//    uint8_t dylib_ord = 0;
//    uint64_t threaded_count = 0;
//    uint8_t special = 0;
//    BOOL done = NO;
//    uint8_t opcode = BIND_OPCODE_MASK & bind_buffer[i];
//    uint8_t imm = BIND_IMMEDIATE_MASK & bind_buffer[i];
    
    // look bind info
    if ( self.dyldInfo ) {
        const uint8_t* p = (uint8_t *)&self.data[self.dyldInfo->bind_off + self.file_offset];
        const uint8_t* end = (uint8_t *)&p[self.dyldInfo->bind_size];
        
        uint8_t type = 0;
        uint64_t segOffset = 0;
        uint64_t count;
        uint64_t skip;
        const char* symbolName = NULL;
        uint64_t libraryOrdinal = 0;
        uint64_t segIndex;
        int64_t addend = 0;
        uintptr_t segStartAddr = 0;
        uint64_t ordinalTableSize = 0;
        uint64_t threaded_count = 0;
        bool useThreadedRebaseBind = false;
        bool done = false;
        const uint8_t *start_off  = p;
        while ( !done && (p < end) ) {
            uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
            uint8_t opcode = *p & BIND_OPCODE_MASK;
            DEBUG_PRINT("0x%04X ", (int)p - (int)start_off);
            ++p;
            switch (opcode) {
                case BIND_OPCODE_DONE:
                    done = true;
                    DEBUG_PRINT("BIND_OPCODE_DONE\n");
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                    libraryOrdinal = immediate;
                    DEBUG_PRINT("BIND_OPCODE_SET_DYLIB_ORDINAL_IMM (%d)\n", immediate);
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                    libraryOrdinal = read_uleb128(&p, end);
                    DEBUG_PRINT("BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB (0x%llX)\n", libraryOrdinal);
                    break;
                case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                    // the special ordinals are negative numbers
                    if ( immediate == 0 )
                        libraryOrdinal = 0;
                    else {
                        int8_t signExtended = BIND_OPCODE_MASK | immediate;
                        libraryOrdinal = signExtended;
                    }
                    DEBUG_PRINT("BIND_OPCODE_SET_DYLIB_SPECIAL_IMM (%d)\n", (int)libraryOrdinal);
                    break;
                case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                    symbolName = (char*)p;
                    while (*p != '\0') { ++p; }
                    ++p;
                    DEBUG_PRINT("BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM (0x%02x, %s)\n", immediate, symbolName);
                    break;
                case BIND_OPCODE_SET_TYPE_IMM:
                    type = immediate;
                    DEBUG_PRINT("BIND_OPCODE_SET_TYPE_IMM (%d)\n", type);
                    break;
                case BIND_OPCODE_SET_ADDEND_SLEB:
                    addend = read_sleb128(&p, end);
                    DEBUG_PRINT("BIND_OPCODE_SET_ADDEND_SLEB (0x%llX)\n", addend);
                    break;
                case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                    segIndex = immediate;
                    struct segment_command_64 *seg = (struct segment_command_64 *)self.segmentCommandsArray[immediate].longValue;
                    segStartAddr = seg->vmaddr; // segStartAddress(segIndex);
                    segOffset = read_uleb128(&p, end);
                    DEBUG_PRINT("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB (%d, 0x%08llX) (0x%08llX)\n", immediate, segOffset, (segOffset + segStartAddr));
                    break;
                case BIND_OPCODE_ADD_ADDR_ULEB: {
                    uint64_t off = read_uleb128(&p, end);
                    segOffset += off;
                    DEBUG_PRINT("BIND_OPCODE_ADD_ADDR_ULEB (0x%llX) (0x%08llX)\n", off, (segOffset + segStartAddr));
                    break;
                } case BIND_OPCODE_DO_BIND:
                    if (threaded_count > 0) {
                        threaded_count--;
                        [self addToThreaded:segOffset + segStartAddr symbol:symbolName libord:libraryOrdinal addend:addend];
                    } else {
                        DEBUG_PRINT("BIND_OPCODE_DO_BIND (0x%08llX, %s)\n", (segOffset + segStartAddr), symbolName);
                        BIND_THAT_BAD_BOY;
                    }
                    segOffset += sizeof(uintptr_t);
                    break;
                case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
                    uint64_t off = read_uleb128(&p, end) + sizeof(uintptr_t);
                    DEBUG_PRINT("BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB (%08llx) (0x%08llX, %s)\n", off, (segOffset + segStartAddr), symbolName);
                    BIND_THAT_BAD_BOY;
                    segOffset += off;
                    break;
                } case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
                    uint64_t off = immediate*sizeof(uintptr_t) + sizeof(uintptr_t);
                    DEBUG_PRINT("BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED (0x%llx) (0x%08llX)\n", off, (segOffset + segStartAddr));
                    BIND_THAT_BAD_BOY;
                    segOffset += off;
                    break;
                } case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                    count = read_uleb128(&p, end);
                    skip = read_uleb128(&p, end);
                    DEBUG_PRINT("BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB (%llu, 0x%08llX)\n", count, skip);
                    for (uint32_t i = 0; i < count; ++i) {
                        DEBUG_PRINT("\tDO_BIND (0x%08llX, %s)\n",(segStartAddr + segOffset), symbolName);
                        BIND_THAT_BAD_BOY;
                        segOffset += skip + sizeof(uintptr_t);
                    }
                    break;
                case BIND_OPCODE_THREADED:
                    // Note the immediate is a sub opcode
                    switch (immediate) {
                        case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
                            ordinalTableSize = read_uleb128(&p, end);
                            useThreadedRebaseBind = true;
                            threaded_count = ordinalTableSize;
                            DEBUG_PRINT("BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB (%llu)\n", ordinalTableSize);
                            break;
                        case BIND_SUBOPCODE_THREADED_APPLY: {
                            if ( !useThreadedRebaseBind ) { assert(0); }
                            DEBUG_PRINT("BIND_SUBOPCODE_THREADED_APPLY\n");
                            uint64_t delta = 0;
                            /*
                             do {
                             uintptr_t resolvedAddress = bind_address + seg_off;
                             uintptr_t offset = [self translateLoadAddressToFileOffset:resolvedAddress useFatOffset:NO] + self.file_offset;
                             
                             uint64_t value = *(uintptr_t *)((uintptr_t)DATABUF(offset));
                             
                             bool isRebase = (value & (1ULL << 62)) == 0;
                             if (isRebase) { do nothing}
                            else {
                                uint16_t ordinal = value & 0xFFFF;
                                XRBindSymbol *obj = threadedHolder[ordinal];
                                [self addToDictionaries:resolvedAddress  symbol:(char*)obj.name.UTF8String libord:obj.libOrdinal addend:obj.addend];
                                DEBUG_PRINT("\tTHREADED_APPLY (%p, %s)\n", (void*)resolvedAddress, obj.name.UTF8String);
                                
                            }
                            value &= ~(1ULL << 62);
                            delta = (value & 0x3FF8000000000000) >> 51;
                            seg_off += (delta * PTR_SIZE);
                            
                    } while (delta != 0);
                    
                             */
                            do {
                                uintptr_t resolvedAddress = segStartAddr + segOffset;
                                uintptr_t offset = [self translateLoadAddressToFileOffset:resolvedAddress useFatOffset:YES];
                                uint64_t value = *(uintptr_t *)((uintptr_t)DATABUF(offset));
//                                const uint8_t* pointerLocation = (uint8_t*)fHeader + fSegments[segIndex]->fileoff() + segOffset;
//                                uint64_t value = P::getP(*(uint64_t*)pointerLocation);
                                bool isRebase = (value & (1ULL << 62)) == 0;
                                
                                if (isRebase) {
                                    //printf("(rebase): %-7s %-16s 0x%08llX  %s\n", segName, sectionName(segIndex, segStartAddr+segOffset), segStartAddr+segOffset, typeName);
                                } else {
                                    // the ordinal is bits [0..15]
                                    uint16_t threadOrdinal = value & 0xFFFF;
                                    if (threadOrdinal >= ordinalTableSize) { assert(0); }
//                                    uint16_t ordinal = value & 0xFFFF;
                                    XRBindSymbol *obj = threadedHolder[threadOrdinal];
                                    [self addToDictionaries:segStartAddr + segOffset  symbol:(char*)obj.name.UTF8String libord:obj.libOrdinal addend:obj.addend];
                                    DEBUG_PRINT("\tTHREADED_APPLY (%p, %s)\n", (void*)resolvedAddress, obj.name.UTF8String);
                                }
                                
                                value &= ~(1ULL << 62);
                                delta = ( value & 0x3FF8000000000000 ) >> 51;
                            
                                // The delta is bits [51..61]
                                // And bit 62 is to tell us if we are a rebase (0) or bind (1)
                                segOffset += delta * sizeof(uintptr_t);
                        
                                
                                
                                
                       
                            } while ( delta != 0);
                            break;
                        }
                        default:
                            assert(0);
                    }
                    break;
                default:
                    assert(0);
            }
        }
    }
}

- (void)addToDictionaries:(uintptr_t)address symbol:(const char *)symbol libord:(uint64_t)ordinal addend:(uint64_t)addend {
    NSString *s = [NSString stringWithUTF8String:symbol];
    NSNumber *a = @(address);
    
    if (![s hasPrefix:@"_OBJC_CLASS_$_"]) { return; }
    
    if (self.addressObjCDictionary[a]) {
        if (xref_options.debug) {
            dprintf(STDERR_FILENO, "overriding dict: old %s, %p, new; %s, %p\n", self.addressObjCDictionary[a].name.UTF8String, self.addressObjCDictionary[a].address.pointerValue, symbol, (void*)address);
        }
    }
    XRBindSymbol * obj = [[XRBindSymbol alloc] initWithAddress:a symbol:s libord:ordinal addend:addend];
    self.addressObjCDictionary[a] = obj;
    self.stringObjCDictionary[s] = obj;
}

- (void)addToThreaded:(uintptr_t)address symbol:(const char *)symbol libord:(uint64_t)ordinal addend:(uint64_t)addend {
    NSString *s = [NSString stringWithUTF8String:symbol];
    NSNumber *a = @(address);
    XRBindSymbol * obj = [[XRBindSymbol alloc] initWithAddress:a symbol:s libord:ordinal addend:addend];
    [threadedHolder addObject:obj];
}

@end



