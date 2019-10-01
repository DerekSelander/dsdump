//
//  XRMachOLibrary+Disassemble.m
//  dsdump
//
//  Created by Derek Selander on 9/27/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary+Disassemble.h"

/////////////////////////////////////////////////////////
// muwahahahahahaha going to hell for this...
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#import "capstone.h"
#pragma clang diagnostic pop
// </muwahahahahahaha going to hell for this...>

#import <AppKit/AppKit.h>


@implementation XRMachOLibrary (Disassemble)

- (uintptr_t *)resolveMetadataFromCode:(uintptr_t)address   {
    
    cs_arch arch = self.header->cputype == CPU_TYPE_ARM64? CS_ARCH_ARM64 : CS_ARCH_X86;
    cs_mode mode = self.header->cputype == CPU_TYPE_ARM64? CS_MODE_ARM : CS_MODE_64;
    static csh handle = 0;
    static uint8_t *buffer = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        int err = cs_open(arch, mode, &handle);
        if (err != CS_ERR_OK) {
            assert(NO);
        }
        buffer = (uint8_t*)calloc(1000, sizeof(char)); // some high amount to be safe, particularly for variable ins x86
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    });
    
    if (!address) {
        return NULL;
    }
    
    cs_insn *instructions = NULL;
    cs_disasm(handle, (const uint8_t *)address, 200, address, 20, &instructions);
    
    // x86_64
    if (self.header->cputype == CPU_TYPE_X86_64) {
        for (int i = 0; i < 20; i++) {
            cs_insn insn = instructions[i];
            cs_x86_op *ops = insn.detail->x86.operands;
            auto opcount = insn.detail->x86.op_count;
            if (opcount == 2 && // Is there 2 operands?
                ops[0].type == X86_OP_REG && ops[0].reg == X86_REG_RAX && // is the first operand setting RAX?
                ops[1].type == X86_OP_MEM && ops[1].mem.base == X86_REG_RIP) {// is the second operand grabing memory from RIP?
                auto displacement = ops[1].mem.disp + insn.size;
                auto resolved = displacement + insn.address;
                return reinterpret_cast<uintptr_t*>(resolved);
            }
        }
    // ARM64(e)
    } else if (self.header->cputype == CPU_TYPE_ARM64) {
        for (int i = 1; i < 20; i++) {
            auto insnADD = instructions[i];
            auto insnADRP = instructions[i - 1];
            
            auto insnADDCount = insnADD.detail->arm64.op_count;
            auto insnADRPCount = insnADRP.detail->arm64.op_count;
            
            // Is it ADRP/ADD?
            if (insnADD.id != ARM64_INS_ADD && insnADRP.id != ARM64_INS_ADRP) {
                continue;
            }
            
            // Does this have the telltale since of the usual ADRP/ADD combo count?
            if (insnADDCount != 3 && insnADRPCount != 2) {
                continue;
            }
            
            // adrp "x8, #0x400008000"
            cs_arm64_op *opsADRP = insnADRP.detail->arm64.operands;
            if (opsADRP[0].type != ARM64_OP_REG && opsADRP[1].type != ARM64_OP_IMM) {
                continue;
            }
            
            // add "x8, x8, #0x98"
            cs_arm64_op *opsADD = insnADD.detail->arm64.operands;
            if (opsADD[1].type != ARM64_OP_REG && opsADD[2].type != ARM64_OP_IMM) {
                continue;
            }
            
            // does the ADD instruction in use equal the same ADRP register?
            if (opsADD[1].reg != opsADRP[0].reg) {
                continue;
            }
            
            return (uintptr_t*)(opsADRP[1].imm + opsADD[2].imm);
        }
    }
    return NULL;
}

@end
