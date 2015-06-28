//
//  Util.h
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Utility : NSObject

+ (NSString *)keyIDFromBytes:(const Byte *)bytes;
+ (NSUInteger)readNumber:(const Byte *)bytes length:(NSUInteger)length;
+ (NSString *)readString:(const Byte *)bytes maxLength:(NSUInteger)maxLength;
+ (NSString *)hexStringFromBytes:(const Byte *)bytes length:(NSUInteger)length;

@end
