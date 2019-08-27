//
//  XRSymbolEntry.h
//  xref
//
//  Created by Derek Selander on 5/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <mach-o/nlist.h>

NS_ASSUME_NONNULL_BEGIN
@class XRMachOLibrary;

@protocol TestProto <NSObject>
@property (nonatomic, assign) uint64_t address;

@end

// Used to reference symbols by address, originates from the symbol table
@interface XRSymbolEntry : NSObject <TestProto>

@property (nonatomic, assign) const char* name;
@property (nonatomic, assign) uint64_t address;
@property (nonatomic, assign) uint64_t flags;
@property (nonatomic, assign) uint64_t other;
@property (nonatomic, assign) const char* importName;
@property (nonatomic, assign) BOOL visited;

- (instancetype)initWithSymbol:(struct nlist_64 *)symbol machoLibrary:(XRMachOLibrary*)lib;

@end

NS_ASSUME_NONNULL_END
