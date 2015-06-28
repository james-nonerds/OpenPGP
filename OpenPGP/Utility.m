//
//  Util.m
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Utility.h"

@implementation Utility

+ (NSString *)keyIDFromBytes:(const Byte *)bytes {
    static const char *hexes = "0123456789abcdef";
    
    char keyId[17];
    
    for (int i = 0; i < 8 ; i++) {
        keyId[i * 2] = hexes[(unsigned)(bytes[i] & 0xf0) >> 4];
        keyId[(i * 2) + 1] = hexes[bytes[i] & 0xf];
    }
    
    keyId[8 * 2] = 0x0;
    
    
    return [NSString stringWithCString:keyId encoding:NSUTF8StringEncoding];
}

+ (NSUInteger)readNumber:(const Byte *)bytes length:(NSUInteger)length {
    NSUInteger number = 0;
    
    for (int i = 0; i < length; i++) {
        number <<= 8;
        number += bytes[i];
    }
    
    return number;
}

+ (NSString *)readString:(const Byte *)bytes maxLength:(NSUInteger)maxLength {
    char cString[maxLength + 1];
    strcpy(cString, (const char *) bytes);
    
    return [NSString stringWithCString:cString encoding:NSUTF8StringEncoding];
}

+ (NSString *)hexStringFromBytes:(const Byte *)bytes length:(NSUInteger)length {
    char output[length * 2 + 1];
    char *poutput = output;
    
    for (int i = 0; i < length; i++) {
        poutput += sprintf(poutput, "%02x", bytes[i]);
    }
    
    *poutput = '\0';
    
    return [NSString stringWithCString:output encoding:NSUTF8StringEncoding];
}

@end
