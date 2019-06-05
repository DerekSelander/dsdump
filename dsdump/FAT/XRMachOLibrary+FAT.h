//
//  XRMachOLibrary+FAT.h
//  xref
//
//  Created by Derek Selander on 5/1/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary.h"

NS_ASSUME_NONNULL_BEGIN

@interface XRMachOLibrary (FAT)

/// Architecture can't be found
#define FAT_OFFSET_BAD_NAME -1

/// Convenience for dealing with archs and endianness
#define FIX_ENDIAN(name) (((fat->nfat_arch) < (htonl(fat->nfat_arch))) ? (name) : (htonl(name)))

/// Used to display info if no arch is present and FAT
-(NSString*)printAllArchitectures;

/// Get offset for arch, returns FAT_OFFSET_BAD_NAME if can't find it
- (intptr_t)offsetForArchitecture:(NSString *)architecture;

/// Default arch name
- (NSString *)defaultArchitectureName;

/// Get default offset
- (intptr_t)offsetForDefaultArchitecture;

/// Return name for cpu/subcpu type
-(NSString *)nameForCPU:(cpu_type_t)cputype subtype:(cpu_subtype_t)subtype;
@end

NS_ASSUME_NONNULL_END
