//
//  DSXRObjCClass.h
//  xref
//
//  Created by Derek Selander on 4/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DSXRObjCClass : NSObject

@property (nonatomic, assign) NSNumber *address;
@property (nonatomic, assign) int symidx;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, readonly) NSString *shortName;

- (instancetype)initWithAddress:(NSNumber *)address symbol:(NSString *)symbol;

@end

NS_ASSUME_NONNULL_END
