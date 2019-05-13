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

@implementation XRMachOLibrary (Opcode)

- (void)parseOpcodes {
    assert(self.dyldInfo);
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        threadedHolder = [NSMutableArray arrayWithCapacity:100];
        self.addressObjCDictionary = [NSMutableDictionary dictionaryWithCapacity:100];
    });
    
    uint8_t *bind_buffer = &self.data[self.dyldInfo->bind_off + self.file_offset];
    
    int i = 0;
    uint64_t bind_address = 0;
    char *symbol = NULL;
    char type = 0;
    uint64_t segment = 0;
    uint64_t seg_off = 0;
    uint64_t addend = 0;
    uint8_t dylib_ord = 0;
    uint64_t threaded_count = 0;
    uint8_t special = 0;
    BOOL done = NO;
    while (!done && i < self.dyldInfo->bind_size) {
        uint8_t opcode = BIND_OPCODE_MASK & bind_buffer[i];
        uint8_t imm = BIND_IMMEDIATE_MASK & bind_buffer[i];
        DEBUG_PRINT("0x%04X ", i);
        
        switch (opcode) {
            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: { // If less than 4 bytes
                dylib_ord = imm;
                DEBUG_PRINT("BIND_OPCODE_SET_DYLIB_ORDINAL_IMM (%d)\n", imm);
                break;
            } case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: { // If greater than 4 bytes
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                i += datalen - 1;
                dylib_ord = v;
                DEBUG_PRINT("BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB (0x%llx)\n", v);
                break;
            } case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: {
                special = imm;
                DEBUG_PRINT("BIND_OPCODE_SET_DYLIB_SPECIAL_IMM (%d)\n", special);
                break;
            } case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
                symbol = (char *)&bind_buffer[++i];
                while(bind_buffer[i] != BIND_OPCODE_DONE) { i++; }
                DEBUG_PRINT("BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM (0x%02x, %s)\n", imm, symbol);
                break;
            } case BIND_OPCODE_SET_TYPE_IMM: {
                type = BIND_IMMEDIATE_MASK & bind_buffer[i];
                DEBUG_PRINT("BIND_OPCODE_SET_TYPE_IMM (%d)\n", type);
                break;
            } case BIND_OPCODE_SET_ADDEND_SLEB: {
                uintptr_t datalen = 0;
                r_sleb128_decode(&bind_buffer[++i], &datalen, &addend);
                i += datalen - 1; // -1, cuz i++ later
                DEBUG_PRINT("BIND_OPCODE_SET_ADDEND_SLEB (0x%llx)\n", addend);
                break;
            } case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
                int datalen = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &seg_off);
                i += datalen - 1; // -1, cuz i++ later
                struct segment_command_64 *seg = (struct segment_command_64 *)self.segmentCommandsArray[imm].longValue;
                bind_address = seg->vmaddr + seg_off;
                segment = imm;
                DEBUG_PRINT("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB (%d, 0x%08llx) (%p)\n", imm, seg_off, (void*)(bind_address));
                
                break;
            } case BIND_OPCODE_ADD_ADDR_ULEB: {
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                i += datalen - 1; // -1, cuz i++ later
                bind_address += v;
                DEBUG_PRINT("BIND_OPCODE_ADD_ADDR_ULEB (0x%llx) (%p)\n", v, (void*)(bind_address));
                break;
            } case BIND_OPCODE_DO_BIND: {
                DEBUG_PRINT("BIND_OPCODE_DO_BIND (%p)\n", (void*)(bind_address));
                if (threaded_count > 0) {
                    threaded_count--;
                    [self addToThreaded:bind_address symbol:symbol libord:dylib_ord addend:addend];
                } else {
                    [self addToDictionaries:bind_address symbol:symbol libord:dylib_ord addend:addend];
                    bind_address += PTR_SIZE;
                }
                break;
            } case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                DEBUG_PRINT("BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB (%08llx) (%p)\n", v, (void*)(bind_address));
                [self addToDictionaries:bind_address symbol:symbol libord:dylib_ord addend:addend];
                bind_address += (v + PTR_SIZE);
                i += datalen - 1; // -1, cuz i++ later
                break;
            } case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
                DEBUG_PRINT("BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED (0x%lx) (%p)\n", imm * PTR_SIZE + PTR_SIZE, (void*)bind_address);
               [self addToDictionaries:bind_address symbol:symbol libord:dylib_ord addend:addend];
                bind_address += imm * PTR_SIZE + PTR_SIZE;
                break;
            } case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                int datalen = 0;
                uint64 count = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &count);
                i += datalen - 1; // -1, cuz i++ later
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                uint64_t skip = v;
                
                DEBUG_PRINT("BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB (%llu, 0x%08llx)\n", count, v);
                for (int j = 0; j < count; j++) {
                    DEBUG_PRINT("\tDO_BIND (%p)\n", (void*)(bind_address));
                    [self addToDictionaries:bind_address symbol:symbol libord:dylib_ord addend:addend];
                    bind_address += (skip + PTR_SIZE); // do bind, so sizeof(void*)
                }
                i += datalen - 1; // -1, cuz i++ later
                
                break;
            } case BIND_OPCODE_THREADED:
                
                switch (imm) {
                    case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: {
                        int datalen = 0;
                        assert(threaded_count == 0); // A count within a count? Da faaaaaa
                        r_uleb128_decode(&bind_buffer[++i], &datalen, &threaded_count);
                        i += datalen - 1; // -1, cuz i++ later
                        DEBUG_PRINT("BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB (%llu)\n", threaded_count);
                        break;
                    } case BIND_SUBOPCODE_THREADED_APPLY: {
                        DEBUG_PRINT("BIND_SUBOPCODE_THREADED_APPLY (%p)\n", (void*)(bind_address));
                     
                        uint64_t delta = 0;
                        do {
                            uintptr_t resolvedAddress = bind_address + seg_off;
                            uintptr_t offset = [self translateLoadAddressToFileOffset:resolvedAddress useFatOffset:NO] + self.file_offset;

                            uint64_t value = *(uintptr_t *)((uintptr_t)DATABUF(offset));

                            bool isRebase = (value & (1ULL << 62)) == 0;
                            if (isRebase) { /* Do nothing*/ }
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
                        
                        break;
                    } default:
                        break;
                }
                break;
            case BIND_OPCODE_DONE:
                DEBUG_PRINT("BIND_OPCODE_DONE\n");
                
                // This is not correct logic, but works-ish
                if (threaded_count == 0) {
                    done = YES;
                }
                break;
           
            default:
                assert(0);
                break;
        }

        i++;
    }
}

- (void)addToDictionaries:(uintptr_t)address symbol:(char *)symbol libord:(int)ordinal addend:(uint64_t)addend {
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

- (void)addToThreaded:(uintptr_t)address symbol:(char *)symbol libord:(int)ordinal addend:(uint64_t)addend {
    NSString *s = [NSString stringWithUTF8String:symbol];
    NSNumber *a = @(address);
    XRBindSymbol * obj = [[XRBindSymbol alloc] initWithAddress:a symbol:s libord:ordinal addend:addend];
    [threadedHolder addObject:obj];
}

@end



