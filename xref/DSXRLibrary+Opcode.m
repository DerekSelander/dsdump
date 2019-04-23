//
//  DSXRLibrary+Opcode.m
//  xref
//
//  Created by Derek Selander on 4/21/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "DSXRLibrary+Opcode.h"
#import "miscellaneous.h"
#import "DSXRObjCClass.h"
@import MachO;
@implementation DSXRLibrary (Opcode)



- (void)parseOpcodes:(int)fd {
    assert(self.dyldInfo);
    
    uint8_t *bind_buffer = calloc(self.dyldInfo->bind_size, 1);
    pread(fd, bind_buffer, self.dyldInfo->bind_size, self.dyldInfo->bind_off + self.file_offset);
    
    int i = 0;
    uint64_t pointer = 0;
    char *symbol = NULL;
    char type = 0;
    BOOL finished = NO;
    
    uint64_t addend = 0;
    uint8_t dylib_ord = 0;
    
    while (!finished && i < self.dyldInfo->bind_size) {
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
                DEBUG_PRINT("BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB (0x%llx)\n", v);
                break;
            } case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: {
                DEBUG_PRINT("BIND_OPCODE_SET_DYLIB_SPECIAL_IMM (%d)\n", imm);
                
                assert(0);
                break;
            } case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
                symbol = (char *)&bind_buffer[++i];
                while(bind_buffer[i] != BIND_OPCODE_DONE) {
                    i++;
                }
                DEBUG_PRINT("BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM (0x%02x, %s)\n", imm, symbol);
                break;
            } case BIND_OPCODE_SET_TYPE_IMM: {
                type = BIND_IMMEDIATE_MASK & bind_buffer[i];
                DEBUG_PRINT("BIND_OPCODE_SET_TYPE_IMM (%d)\n", type);
                break;
            } case BIND_OPCODE_SET_ADDEND_SLEB: {
                uintptr_t datalen = 0;
                uint64_t v = 0;
                r_sleb128_decode(&bind_buffer[++i], &datalen, &v);
                i += datalen - 1; // -1, cuz i++ later
                addend = v;
                DEBUG_PRINT("BIND_OPCODE_SET_ADDEND_SLEB (0x%llx)\n", v);
                break;
            } case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                i += datalen - 1; // -1, cuz i++ later

                struct segment_command_64 *seg = (struct segment_command_64 *)self.segmentCommandsArray[imm].longValue;
                pointer = seg->vmaddr + v;
                DEBUG_PRINT("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB (%d, 0x%08llx) (%p)\n", imm, v, (void*)pointer);
                break;
            } case BIND_OPCODE_ADD_ADDR_ULEB: {
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                i += datalen - 1; // -1, cuz i++ later
                pointer += v;
                DEBUG_PRINT("BIND_OPCODE_ADD_ADDR_ULEB (0x%llx) (%p)\n", v, (void*)(pointer));
                break;
            } case BIND_OPCODE_DO_BIND: {
                DEBUG_PRINT("BIND_OPCODE_DO_BIND (%p)\n", (void*)pointer);
                [self addToDictionaries:pointer symbol:symbol];
                pointer += sizeof(void *);
                break;
            } case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                DEBUG_PRINT("BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB (%08llx) (%p)\n", v, (void*)pointer);
                [self addToDictionaries:pointer symbol:symbol];
                pointer += (v + sizeof(void *));
                i += datalen - 1;

                break;
            } case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
                pointer += imm * sizeof(void *) + sizeof(void*);
                DEBUG_PRINT("BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED (0x%lx) (%p)\n", imm * sizeof(void*) + sizeof(void*), (void*)pointer);
                [self addToDictionaries:pointer symbol:symbol];
                break;
            } case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                i += datalen - 1; // -1, cuz i++ later
                uint64 count = v;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                uint64_t skip = v;
                
                DEBUG_PRINT("BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB (%llu, 0x%08llx)\n", count, v);
                for (int j = 0; j < count; j++) {
                    DEBUG_PRINT("\t(%p)\n", (void*)pointer);
                    [self addToDictionaries:pointer symbol:symbol];
                    pointer += (skip + sizeof(void *)); // do bind, so sizeof(void*)
                }
                i += datalen - 1; // -1, cuz i++ later
                
                break;
            } case BIND_OPCODE_THREADED:
                printf("BIND_OPCODE_THREADED Not implemented!\n");
                assert(0);
                break;
                
            case BIND_SUBOPCODE_THREADED_APPLY:
                printf("BIND_SUBOPCODE_THREADED_APPLY Not implemented!");
                assert(0);
                break;
            case BIND_OPCODE_DONE:
                DEBUG_PRINT("BIND_OPCODE_DONE\n");
                break;
           
            default:
                assert(0);
                break;
        }

        i++;
        pointer += addend;

    }
}

- (void)addToDictionaries:(uintptr_t)address symbol:(char *)symbol {
    
    NSString *s = [NSString stringWithUTF8String:symbol];
    NSNumber *a = @(address);
    
    if (self.addressObjCDictionary[a]) {
        
        dprintf(STDERR_FILENO, "overriding dict: old %s, %p, new; %s, %p\n", self.addressObjCDictionary[a].name.UTF8String, self.addressObjCDictionary[a].address.pointerValue, symbol, (void*)address);
    }
    DSXRObjCClass * obj = [[DSXRObjCClass alloc] initWithAddress:a symbol:s];
    
    self.stringObjCDictionary[s] = obj;
    self.addressObjCDictionary[a] = obj;
    
}

@end



