//
//  XRMachOLibrary+FAT.m
//  xref
//
//  Created by Derek Selander on 5/1/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary+FAT.h"
#import "../payload.hpp"
#include <sys/types.h>
#include <sys/sysctl.h>


@implementation XRMachOLibrary (FAT)

-(NSString *)nameForCPU:(cpu_type_t)cputype subtype:(cpu_subtype_t)subtype {
    if (cputype == CPU_TYPE_X86_64 && subtype & (CPU_SUBTYPE_X86_64_H)) {
        return @"x86_64h";
    }
    
    if (cputype == CPU_TYPE_X86_64 && subtype & (CPU_SUBTYPE_X86_64_ALL)) {
        return @"x86_64";
    }
    
    if (cputype == CPU_TYPE_X86 && subtype & CPU_SUBTYPE_X86_64_ALL) {
        return @"i386";
    }
    
    if (cputype == CPU_TYPE_ARM64 && subtype == CPU_SUBTYPE_ARM64_ALL) {
        return @"arm64";
    }
    
    if (cputype == CPU_TYPE_ARM && subtype & CPU_SUBTYPE_ARM_V7) {
        return @"armv7";
    }
    
    if (cputype == CPU_TYPE_ARM64 && subtype & CPU_SUBTYPE_ARM64E) {
        return @"arm64e";
    }
    
    return [NSString stringWithFormat:@"(?) 0x%x %x", cputype, subtype];
}

- (intptr_t)offsetForDefaultArchitecture {
    return [self offsetForArchitecture:[self defaultArchitectureName] size:NULL];
}

- (intptr_t)offsetForArchitecture:(NSString *)architecture size:(size_t*)size {
    if (!architecture) {
        return FAT_OFFSET_BAD_NAME;
    }
    
    auto magic = *payload::GetData<uint32_t>(0);
    // big endian
    struct fat_header *fat  = payload::GetData<struct fat_header>(0); //(void*)payload::data;
    if (magic == MH_CIGAM_64 || magic == MH_MAGIC_64) {
        
        auto mach_header = payload::GetData<struct mach_header_64>(0);
        cpu_subtype_t cpu_subytpe =  mach_header->cpusubtype;
        cpu_subytpe = FIX_ENDIAN(cpu_subytpe);
        
        cpu_type_t cputype = mach_header->cputype;
        cputype = FIX_ENDIAN(cputype);
        
        if ([[self nameForCPU:cputype subtype:cpu_subytpe] isEqualToString:architecture]) {
            if (size) {
                *size = payload::size;
            }
            return 0;
        } else {
            if (size) {
                *size = 0;
            }
            return FAT_OFFSET_BAD_NAME;
        }
    }
 
    
    if (!(magic == FAT_MAGIC || magic == FAT_CIGAM)) {
        if (size) {
            *size = 0;
        }
        return FAT_OFFSET_BAD_NAME;
    }
    
    for (int i = 0; i < FIX_ENDIAN(fat->nfat_arch); i++) {
        struct fat_arch *arch = payload::GetData<struct fat_arch>(sizeof(struct fat_header) + sizeof(struct fat_arch) * i);
        NSString *ar = [self nameForCPU:FIX_ENDIAN(arch->cputype) subtype:FIX_ENDIAN(arch->cpusubtype)];
        if ([ar isEqualToString:architecture]) {
            if (size) {
                *size = FIX_ENDIAN(arch->size);
            }
            return FIX_ENDIAN(arch->offset);
        }
    }
    if (size) {
        *size = 0;
    }
    return FAT_OFFSET_BAD_NAME;
}

-(NSString *)printAllArchitectures {
    auto magic = *payload::GetData<uint32_t>(0);
    
    if (magic == MH_CIGAM_64) {
        auto machHeader = payload::GetData<struct mach_header_64>(0);
        NSString *name = [self nameForCPU:htonl(machHeader->cputype) subtype:htonl(machHeader->cpusubtype)];
        return [NSString stringWithFormat:@"[ %@ ]", name];
    }
    
    if (magic == MH_MAGIC_64) {
        auto machHeader = payload::GetData<struct mach_header_64>(0);
        NSString *name = [self nameForCPU:machHeader->cputype subtype:machHeader->cpusubtype];
        return [NSString stringWithFormat:@"[ %@ ]", name];
    }
    
    NSMutableString *retString = [NSMutableString string];
    struct fat_header *fat = payload::GetData<struct fat_header>(0); // (struct fat_header *)self.data;

    [retString appendString:@"["];
    for (int i = 0; i < FIX_ENDIAN(fat->nfat_arch); i++) {
//        struct fat_arch *arch = (void*)&self.data[sizeof(struct fat_header) + sizeof(struct fat_arch) * i];
        struct fat_arch *arch = payload::GetData<struct fat_arch>(sizeof(struct fat_header) + sizeof(struct fat_arch) * i);
        NSString *ar = [self nameForCPU:FIX_ENDIAN(arch->cputype) subtype:FIX_ENDIAN(arch->cpusubtype)];
        [retString appendFormat:@" %@ ", ar];
        if (i < FIX_ENDIAN(fat->nfat_arch) - 1) {
            [retString appendFormat:@"|"];
        }
    }
    [retString appendString:@"]"];
    
    return retString;

}

- (NSString *)defaultArchitectureName {
    static cpu_type_t this_cputype;
    static cpu_subtype_t this_cpusubtype;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        size_t len;
        sysctlbyname("hw.cputype", &this_cputype, &len, NULL, 0);
        assert(len == sizeof(uint32_t));
        sysctlbyname("hw.cpusubtype", &this_cpusubtype, &len, NULL, 0);
        assert(len == sizeof(uint32_t));
    });
    
    this_cputype |= CPU_ARCH_ABI64;
    
//    struct fat_header *fat = (struct fat_header *).data;
    struct fat_header *fat = payload::GetData<struct fat_header>(0);

    // Let's try the closest to the cpu type first...
    for (int i = 0; i < FIX_ENDIAN(fat->nfat_arch); i++) {
        auto arch = payload::GetData<struct fat_arch>(sizeof(struct fat_header) + sizeof(struct fat_arch) * i);
        if (FIX_ENDIAN(arch->cpusubtype) == this_cpusubtype && (FIX_ENDIAN(arch->cputype) == this_cputype)) {
            return [self nameForCPU:FIX_ENDIAN(arch->cputype) subtype:FIX_ENDIAN(arch->cpusubtype)];
        }
    }
    
    // If they don't have the right type, try x86_64
    for (int i = 0; i < FIX_ENDIAN(fat->nfat_arch); i++) {
//        struct fat_arch *arch = (void*)&self.data[sizeof(struct fat_header) + sizeof(struct fat_arch) * i];
        auto arch = payload::GetData<struct fat_arch>(sizeof(struct fat_header) + sizeof(struct fat_arch) * i);
        if (FIX_ENDIAN(arch->cputype) == CPU_TYPE_X86_64) {
            return [self nameForCPU:FIX_ENDIAN(arch->cputype) subtype:FIX_ENDIAN(arch->cpusubtype)];
        }
    }
    
    // Really!? OK, first 64 arch now...
    for (int i = 0; i < FIX_ENDIAN(fat->nfat_arch); i++) {
        auto arch = payload::GetData<struct fat_arch>(sizeof(struct fat_header) + sizeof(struct fat_arch) * i);
        if (FIX_ENDIAN(arch->cputype) & CPU_ARCH_ABI64) {
            return [self nameForCPU:FIX_ENDIAN(arch->cputype) subtype:FIX_ENDIAN(arch->cpusubtype)];
        }
    }
    
    return nil;
}


@end
