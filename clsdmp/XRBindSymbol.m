//
//  DSXRObjCClass.m
//  xref
//
//  Created by Derek Selander on 4/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRBindSymbol.h"
#import "XRMachOLibrary+SymbolDumper.h"

@implementation XRBindSymbol

- (instancetype)initWithAddress:(NSNumber *)address symbol:(NSString *)symbol libord:(uint64_t)ordinal addend:(uint64_t)addend {
    if (self = [super init]) {
        self.name = symbol;
        self.address = address;
        self.libOrdinal = ordinal;
        self.addend = addend;
    }
    return self;
}

- (NSString *)shortName {
    NSInteger index = [self.name rangeOfString:@"_$_"].location;
    if (index) {
        return [self.name substringFromIndex:index + 3];
    }
    return self.name;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%p %@: <%p>", self.address.pointerValue, _name, self];
}

@end
