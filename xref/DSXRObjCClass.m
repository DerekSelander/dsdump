//
//  DSXRObjCClass.m
//  xref
//
//  Created by Derek Selander on 4/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "DSXRObjCClass.h"

@implementation DSXRObjCClass

- (instancetype)initWithAddress:(NSNumber *)address symbol:(NSString *)symbol {
    
    if (![symbol hasPrefix:@"_OBJC_CLASS_$_"]) { return nil; }
    
    if (self = [super init]) {
        self.name = symbol;
        self.address = address;
    }
    return self;
}

- (NSString *)shortName {
    return self.name.length > 14 ? [self.name substringFromIndex:14] : nil;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%p %@: <%p>", self.address.pointerValue, self.shortName, self];
}

@end
