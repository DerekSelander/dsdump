//
//  DSXRObjCClass.h
//  xref
//
//  Created by Derek Selander on 4/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Used for dyld opcode bind mapping
@interface XRBindSymbol : NSObject

@property (nonatomic, assign) NSNumber *address;
@property (nonatomic, assign) int symidx;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, readonly) NSString *shortName;
@property (nonatomic, assign) uint64_t addend;
@property (nonatomic, assign) uint64_t libOrdinal;

- (instancetype)initWithAddress:(NSNumber *)address symbol:(NSString *)symbol libord:(uint64_t)ordinal addend:(uint64_t)addend;

@end


NS_ASSUME_NONNULL_END
