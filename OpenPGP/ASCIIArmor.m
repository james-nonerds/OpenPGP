//
//  ASCIIArmor.m
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "ASCIIArmor.h"

#pragma mark - Constants

#define CRC24_INIT 0xB704CEL
#define CRC24_POLY 0x1864CFBL

typedef NS_ENUM(NSUInteger, ASCIIArmorHeaderIndex) {
    PGPHeaderIndexKey = 0,
    PGPHeaderIndexValue = 1
};

typedef NS_ENUM(NSUInteger, ASCIIArmorReadState) {
    ASCIIArmorReadStateArmorHeader,
    ASCIIArmorReadStateHeaders,
    ASCIIArmorReadStateContent,
    ASCIIArmorReadStateFinished
};

static NSString *const PGPLineBreak = @"\r\n";

static NSString *const ASCIIArmorHeaderMessage =      @"-----BEGIN PGP MESSAGE-----";
static NSString *const ASCIIArmorHeaderPublicKey =    @"-----BEGIN PGP PUBLIC KEY BLOCK-----";
static NSString *const ASCIIArmorHeaderPrivateKey =   @"-----BEGIN PGP PRIVATE KEY BLOCK-----";
static NSString *const ASCIIArmorHeaderMessageXofY =  @"-----BEGIN PGP MESSAGE, PART %u/%y-----";
static NSString *const ASCIIArmorHeaderMessageX =     @"-----BEGIN PGP MESSAGE, PART %u-----";
static NSString *const ASCIIArmorHeaderSignature =    @"-----BEGIN PGP SIGNATURE-----";

#pragma mark - ASCIIArmor extension


@interface ASCIIArmor ()


#pragma mark Private class methods


/// Text to ASCIIArmor:

+ (ASCIIArmorHeaderType)typeForArmorHeader:(NSString *)armorHeader;
+ (NSData *)readContentString:(NSString *)contentString checksum:(NSString *)checksum;
+ (NSUInteger)checksumForBase64Data:(NSData *)data;
+ (NSUInteger)valueForChecksumString:(NSString *)checksumString;

/// ASCIIArmor to text:

+ (NSString *)armorHeaderForType:(ASCIIArmorHeaderType)type;
+ (NSString *)checksumStringForChecksum:(NSUInteger)checksum;


#pragma mark Private init


- (id)initWithHeaderType:(ASCIIArmorHeaderType)type headers:(NSDictionary *)headers content:(NSData *)content;


@end


#pragma mark - ASCIIArmor implementation


@implementation ASCIIArmor


#pragma mark Constructors


+ (ASCIIArmor *)armorFromText:(NSString *)text {
    NSArray *lines = [text componentsSeparatedByString:PGPLineBreak];
    
    ASCIIArmorReadState state = ASCIIArmorReadStateArmorHeader;
    
    ASCIIArmorHeaderType armorHeaderType = ASCIIArmorHeaderTypeUnknown;
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    NSMutableString *contentString = [NSMutableString string];
    NSString *checksumString = nil;
    
    for (NSString *line in lines) {
        switch (state) {
            case ASCIIArmorReadStateArmorHeader: {
                armorHeaderType = [ASCIIArmor typeForArmorHeader:line];
                
                if (armorHeaderType == ASCIIArmorHeaderTypeUnknown) {
                    NSLog(@"Text is not armored, first line is: %@", line);
                    return nil;
                }
                
                state = ASCIIArmorReadStateHeaders;
                continue;
            }
                
            case ASCIIArmorReadStateHeaders: {
                if ([line isEqualToString:@""]) {
                    state = ASCIIArmorReadStateContent;
                    continue;
                }
                
                NSArray *keyAndValue = [line componentsSeparatedByString:@": "];
                
                if (keyAndValue.count != 2) {
                    NSLog(@"Can't find headers: text on line is not properly formatted : %@", line);
                    return nil;
                }
                
                NSString *key = keyAndValue[PGPHeaderIndexKey];
                NSString *value = keyAndValue[PGPHeaderIndexValue];
                
                [headers setValue:value forKey:key];
                
                continue;
            }
                
            case ASCIIArmorReadStateContent: {
                if ([line characterAtIndex:0] == '=') {
                    checksumString = line;
                    state = ASCIIArmorReadStateFinished;
                    
                    continue;
                }
                
                [contentString appendString:line];
                
                continue;
            }
                
            case ASCIIArmorReadStateFinished: {
                continue;
            } // End case.
        } // End switch.
    } // End for loop.
    
    NSData *content = [ASCIIArmor readContentString:contentString checksum:checksumString];
    
    if (content == nil) {
        NSLog(@"Failed to read content.");
        return nil;
    }
    
    return [[self alloc] initWithHeaderType:armorHeaderType
                                    headers:[NSDictionary dictionaryWithDictionary:headers]
                                    content:content];
}

+ (ASCIIArmor *)armorFromPacketList:(PacketList *)packetList {
    return nil;
}


#pragma mark Properties


- (PacketList *)packetList {
    return nil;
}

- (NSString *)text {
    return nil;
}


#pragma mark Private class methods


+ (ASCIIArmorHeaderType)typeForArmorHeader:(NSString *)armorHeader {
    
    if ([armorHeader isEqualToString:ASCIIArmorHeaderMessage]) {
        
        return ASCIIArmorHeaderTypeMessage;
        
    } else if ([armorHeader isEqualToString:ASCIIArmorHeaderPublicKey]) {
        
        return ASCIIArmorHeaderTypePublicKey;
        
    } else if ([armorHeader isEqualToString:ASCIIArmorHeaderPrivateKey]) {
        
        return ASCIIArmorHeaderTypePrivateKey;
        
    } else if ([armorHeader isEqualToString:ASCIIArmorHeaderMessageXofY]) {
        
        return ASCIIArmorHeaderTypeMessageXofY;
        
    } else if ([armorHeader isEqualToString:ASCIIArmorHeaderMessageX]) {
        
        return ASCIIArmorHeaderTypeMessageX;
        
    } else if ([armorHeader isEqualToString:ASCIIArmorHeaderSignature]) {
        
        return ASCIIArmorHeaderTypeSignature;
    }
    
    return ASCIIArmorHeaderTypeUnknown;
}

+ (NSData *)readContentString:(NSString *)contentString checksum:(NSString *)checksumString {
    NSData *contentData = [[NSData alloc] initWithBase64EncodedString:contentString options:0];
    
    NSUInteger contentChecksum = [ASCIIArmor checksumForBase64Data:contentData];
    NSUInteger checksum = [ASCIIArmor valueForChecksumString:checksumString];
    
    return (contentChecksum == checksum) ? contentData : nil;
}

+ (NSUInteger)checksumForBase64Data:(NSData *)data {
    unsigned const char *octets = (unsigned const char *) data.bytes;
    unsigned long len = data.length;
    
    NSUInteger crc = CRC24_INIT;
    int i;
    while (len--) {
        crc ^= (*octets++) << 16;
        for (i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= CRC24_POLY;
        }
    }
    
    return crc & 0xFFFFFFL;
}

+ (NSUInteger)valueForChecksumString:(NSString *)checksumString {
    NSData *checksumData = [[NSData alloc] initWithBase64EncodedString:[checksumString substringFromIndex:1] options:0];

    const uint8_t *octets = (const uint8_t *) checksumData.bytes;
    
    return  (octets[0] << 020) +
            (octets[1] << 010) +
            (octets[2] << 000);
}

+ (NSString *)armorHeaderForType:(ASCIIArmorHeaderType)type {
    switch (type) {
        case ASCIIArmorHeaderTypeMessage:
            return ASCIIArmorHeaderMessage;
            
        case ASCIIArmorHeaderTypePublicKey:
            return ASCIIArmorHeaderPublicKey;
            
        case ASCIIArmorHeaderTypePrivateKey:
            return ASCIIArmorHeaderPrivateKey;
            
        case ASCIIArmorHeaderTypeMessageX:
            return ASCIIArmorHeaderMessageX;
            
        case ASCIIArmorHeaderTypeMessageXofY:
            return ASCIIArmorHeaderMessageXofY;
            
        case ASCIIArmorHeaderTypeSignature:
            return ASCIIArmorHeaderSignature;
            
        case ASCIIArmorHeaderTypeUnknown:
            return nil;
    }
}

+ (NSString *)checksumStringForChecksum:(NSUInteger)checksum {
    uint8_t octets[3];
    
    octets[0] = (checksum >> 020) & 0xFF;
    octets[1] = (checksum >> 010) & 0xFF;
    octets[2] = (checksum >> 000) & 0xFF;
    
    NSData *data = [NSData dataWithBytesNoCopy:octets length:3 freeWhenDone:NO];
    NSString *base64String = [data base64EncodedStringWithOptions:0];
    
    return [@"=" stringByAppendingString:base64String];
}

- (id)initWithHeaderType:(ASCIIArmorHeaderType)type headers:(NSDictionary *)headers content:(NSData *)content {
    self = [super init];
    
    if (self != nil) {
        _armorHeaderType = type;
        _headers = headers;
        _content = content;
    }
    
    return self;
}


@end
