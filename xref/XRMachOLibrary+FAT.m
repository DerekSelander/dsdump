//
//  XRMachOLibrary+FAT.m
//  xref
//
//  Created by Derek Selander on 5/1/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary+FAT.h"
#include <sys/types.h>
#include <sys/sysctl.h>


@implementation XRMachOLibrary (FAT)


-(NSString *)nameForCPU:(cpu_type_t)cputype subtype:(cpu_subtype_t)subtype {
    
    if (cputype == CPU_TYPE_X86_64 && subtype == (CPU_SUBTYPE_LIB64|CPU_SUBTYPE_X86_64_H)) {
        return @"x86_64h";
    }
    
    if (cputype == CPU_TYPE_X86_64 && subtype & CPU_SUBTYPE_X86_64_ALL) {
        return @"x86_64";
    }
    
    if (cputype == CPU_TYPE_X86 && subtype & CPU_SUBTYPE_X86_64_ALL) {
        return @"i386";
    }
    
    if (cputype & CPU_TYPE_ARM && subtype & CPU_SUBTYPE_ARM_V7) {
        return @"armv7";
    }
    
    if (cputype & CPU_TYPE_ARM64 && subtype & CPU_SUBTYPE_ARM64_ALL) {
        return @"arm64";
    }
    
    if (cputype & CPU_TYPE_ARM64 && subtype & CPU_SUBTYPE_ARM64E) {
        return @"arm64e";
    }
    
    return [NSString stringWithFormat:@"(?) 0x%x %x", cputype, subtype];
}

- (intptr_t)offsetForDefaultArchitecture {
    return [self offsetForArchitecture:[self defaultArchitectureName]];
}

- (intptr_t)offsetForArchitecture:(NSString *)architecture {
    if (!architecture) {
        return FAT_OFFSET_BAD_NAME;
    }
    
    // big endian
    struct fat_header *fat  = (void*)self.data;
    if (*(uint32_t *)self.data == MH_CIGAM_64 || *(uint32_t *)self.data == MH_MAGIC_64) {
        
        cpu_subtype_t cpu_subytpe =  (*(cpu_subtype_t *)&self.data[8]);
        cpu_subytpe = FIX_ENDIAN(cpu_subytpe);
        
        cpu_type_t cputype = htonl(*(cpu_type_t *)&self.data[4]);
        cputype = FIX_ENDIAN(cputype);
        
        if ([[self nameForCPU:cputype subtype:cpu_subytpe] isEqualToString:architecture]) {
            return 0;
        } else {
            return FAT_OFFSET_BAD_NAME;
        }
    }
 
    
    if (!(*(uint32_t *)self.data == FAT_MAGIC || *(uint32_t *)self.data == FAT_CIGAM)) {
        return FAT_OFFSET_BAD_NAME;
    }
    
    for (int i = 0; i < FIX_ENDIAN(fat->nfat_arch); i++) {
        struct fat_arch *arch = (void*)&self.data[sizeof(struct fat_header) + sizeof(struct fat_arch) * i];
        NSString *ar = [self nameForCPU:FIX_ENDIAN(arch->cputype) subtype:FIX_ENDIAN(arch->cpusubtype)];
        if ([ar isEqualToString:architecture]) {
            return FIX_ENDIAN(arch->offset);
        }
    }
    
    return FAT_OFFSET_BAD_NAME;
}

-(void)printFatSymbolsIfPresent {
    if (!(*(uint32_t *)self.data == MH_CIGAM_64 || *(uint32_t *)self.data == MH_MAGIC_64)) {
        NSString *name = [self nameForCPU:*(uint32_t *)&self.data[4] subtype:*(uint32_t *)&self.data[8]];
        dprintf(STDERR_FILENO, "Arch %s%s%s\n", dcolor(DSCOLOR_RED), name.UTF8String, color_end());
        return;
    }
    
    struct fat_header *fat = (struct fat_header *)self.data;
    dprintf(STDERR_FILENO, "%sMultiple arches found: ", dcolor(DSCOLOR_RED));
    putc('[', stderr);
    for (int i = 0; i < FIX_ENDIAN(fat->nfat_arch); i++) {
        struct fat_arch *arch = (void*)&self.data[sizeof(struct fat_header) + sizeof(struct fat_arch) * i];
        NSString *ar = [self nameForCPU:FIX_ENDIAN(arch->cputype) subtype:FIX_ENDIAN(arch->cpusubtype)];
        dprintf(STDERR_FILENO, " %s ", ar.UTF8String);
        if (i < FIX_ENDIAN(fat->nfat_arch) - 1) {
            putc('|', stderr);
        }
    }
    putc(']', stderr);
    putc('\n', stderr);
    dprintf(STDERR_FILENO, "Use --arches (-A) (or ARCH env var) to specify arch, defaulting to: %s%s%s%s\n", color_end(), dcolor(DSCOLOR_CYAN), [[self defaultArchitectureName] UTF8String], color_end());
}

- (NSString *)defaultArchitectureName {
    static cpu_type_t cputype;
    static cpu_subtype_t cpusubtype;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        size_t len;
        sysctlbyname("hw.cputype", &cputype, &len, NULL, 0);
        assert(len == sizeof(uint32_t));
        sysctlbyname("hw.cpusubtype", &cpusubtype, &len, NULL, 0);
        assert(len == sizeof(uint32_t));
    });
    
    struct fat_header *fat = (struct fat_header *)self.data;

    // Let's try the closest to the cpu type first...
    for (int i = 0; i < FIX_ENDIAN(fat->nfat_arch); i++) {
        struct fat_arch *arch = (void*)&self.data[sizeof(struct fat_header) + sizeof(struct fat_arch) * i];
        if (FIX_ENDIAN(arch->cpusubtype) & cpusubtype && (FIX_ENDIAN(arch->cputype) & cputype)) {
            return [self nameForCPU:FIX_ENDIAN(arch->cputype) subtype:FIX_ENDIAN(arch->cpusubtype)];
        }
    }
    
    // If they don't have the right type, try x86_64
    for (int i = 0; i < FIX_ENDIAN(fat->nfat_arch); i++) {
        struct fat_arch *arch = (void*)&self.data[sizeof(struct fat_header) + sizeof(struct fat_arch) * i];
        if (FIX_ENDIAN(arch->cpusubtype) & CPU_TYPE_X86_64) {
            return [self nameForCPU:FIX_ENDIAN(arch->cputype) subtype:FIX_ENDIAN(arch->cpusubtype)];
        }
    }
    
    // Really!? OK, first 64 arch now...
    for (int i = 0; i < FIX_ENDIAN(fat->nfat_arch); i++) {
        struct fat_arch *arch = (void*)&self.data[sizeof(struct fat_header) + sizeof(struct fat_arch) * i];
        if (FIX_ENDIAN(arch->cpusubtype) & CPU_ARCH_ABI64) {
            return [self nameForCPU:FIX_ENDIAN(arch->cputype) subtype:FIX_ENDIAN(arch->cpusubtype)];
        }
    }
    
    return nil;
}


@end
