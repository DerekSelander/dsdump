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

//static uintptr_t get_sleb128(char *byte, uintptr_t* shift) {
//    uintptr_t result = 0;
//    *shift = 0;
//    size_t size = sizeof(signed int);
//    char *cur = byte;
//    do{
//  
//        
//        result |= ((0x7f & *cur) << *shift);
//        *shift += 7;
//    }while((*cur & 0x80) != 0);
//    
//    /* sign bit of byte is second high order bit (0x40) */
//    if ((*shift < size) && (*cur & 0x80)) {
//        /* sign extend */
//        result |= (~0 << *shift);
//    }
//    
//    
//    return result;
//}

- (void)parseOpcodes:(int)fd {
    assert(self.dyldinfo);
    
    uint8_t *bind_buffer = calloc(self.dyldinfo->bind_size, 1);
    pread(fd, bind_buffer, self.dyldinfo->bind_size, self.dyldinfo->bind_off + self.file_offset);
    
    int i = 0;
    uint64_t pointer = 0;
    char *symbol = NULL;
    char type = 0;
    BOOL finished = NO;

    uint8_t dylib_ord = 0;
    
    while (!finished && i < self.dyldinfo->bind_size) {
        uint8_t opcode = BIND_OPCODE_MASK & bind_buffer[i];
        uint8_t imm = BIND_IMMEDIATE_MASK & bind_buffer[i];
        int initial = i;
        switch (opcode) {
            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: { // If less than 4 bytes
                dylib_ord = imm;
                DEBUG_PRINT("0x%04x BIND_OPCODE_SET_DYLIB_ORDINAL_IMM (%d)\n", initial, imm);
                break;
            } case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: { // If greater than 4 bytes
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                i += datalen;
                DEBUG_PRINT("0x%04x BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB (%d)\n", initial, imm);
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
                DEBUG_PRINT("0x%04x BIND_OPCODE_SET_DYLIB_ORDINAL_IMM (0x%02x, %s)\n", initial, imm, symbol);
                break;
            } case BIND_OPCODE_SET_TYPE_IMM: {
                type = BIND_IMMEDIATE_MASK & bind_buffer[i];
                DEBUG_PRINT("0x%04x BIND_OPCODE_SET_TYPE_IMM (%d)\n", initial, type);
                break;
            } case BIND_OPCODE_SET_ADDEND_SLEB: {
                assert(0);
                break;
            } case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                i += datalen - 1; // -1, cuz i++ later

                struct segment_command_64 *seg = (struct segment_command_64 *)self.segmentCommandsArray[imm].longValue;
                pointer = seg->vmaddr + v;
                DEBUG_PRINT("0x%04x BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB (%d, 0x%08llx) (%p)\n", initial, imm, v, (void*)pointer);
                break;
            } case BIND_OPCODE_ADD_ADDR_ULEB: {
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                i += datalen - 1; // -1, cuz i++ later
                pointer += v;
                DEBUG_PRINT("0x%04x BIND_OPCODE_ADD_ADDR_ULEB (0x%llx) (%p)\n", initial, v, (void*)(pointer));
                break;
            } case BIND_OPCODE_DO_BIND: {
                DEBUG_PRINT("0x%04x BIND_OPCODE_DO_BIND (%p)\n", initial, (void*)pointer);
                [self addToDictionaries:pointer symbol:symbol];
                
                pointer += sizeof(void *);
                break;
            } case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
                
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                DEBUG_PRINT("0x%04x BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB (%08x) (%p)\n", initial, v, (void*)pointer);
                [self addToDictionaries:pointer symbol:symbol];
                pointer += (v + sizeof(void *));

                break;
            } case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
                pointer += imm * sizeof(void *) + sizeof(void*);
                DEBUG_PRINT("0x%04x BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED (0x%lx) (%p)\n", initial, imm * sizeof(void*) + sizeof(void*), (void*)pointer);
                break;
            } case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                int datalen = 0;
                uint64_t v = 0;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                i += datalen - 1; // -1, cuz i++ later
                uint64 count = v;
                r_uleb128_decode(&bind_buffer[++i], &datalen, &v);
                uint64_t skip = v;
                
                DEBUG_PRINT("0x%04x BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB (%llu, 0x%08llx)\n", initial, count, v);
                for (int j = 0; j < count; j++) {
                    DEBUG_PRINT("\t(%p)\n", (void*)pointer);
                    pointer += (skip + sizeof(void *)); // do bind, so sizeof(void*)
                }
                i += datalen - 1; // -1, cuz i++ later
                
                break;
            } case BIND_OPCODE_THREADED:
                assert(0);
                break;
                
            case BIND_SUBOPCODE_THREADED_APPLY:
                assert(0);
                break;
            case BIND_OPCODE_DONE:
                DEBUG_PRINT("0x%04x BIND_OPCODE_DONE\n", initial);
                break;
           
            default:
                assert(0);
                break;
        }

        i++;

    }
}

- (void)addToDictionaries:(uintptr_t)address symbol:(char *)symbol {
    
    NSString *s = [NSString stringWithUTF8String:symbol];
    NSNumber *a = @(address);
    DSXRObjCClass * obj = [[DSXRObjCClass alloc] initWithAddress:a symbol:s];
    
    self.stringDictionary[s] = obj;
    self.addressDictionary[a] = obj;
    
}

@end



