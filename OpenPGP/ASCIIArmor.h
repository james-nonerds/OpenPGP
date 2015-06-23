//
//  ASCIIArmor.h
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PacketList.h"

typedef NS_ENUM(NSUInteger, ASCIIArmorHeaderType) {
    ASCIIArmorHeaderTypeUnknown,
    ASCIIArmorHeaderTypeMessage,
    ASCIIArmorHeaderTypePublicKey,
    ASCIIArmorHeaderTypePrivateKey,
    ASCIIArmorHeaderTypeMessageXofY,
    ASCIIArmorHeaderTypeMessageX,
    ASCIIArmorHeaderTypeSignature
};

#pragma mark - ASCIIArmor interface

@interface ASCIIArmor : NSObject

#pragma mark Properties

/// Configurable properties:
@property (nonatomic, readonly) ASCIIArmorHeaderType armorHeaderType;
@property (nonatomic, readonly) NSDictionary *headers;
@property (nonatomic, readonly) NSData *content;

/// Output properties:
@property (nonatomic, readonly) PacketList *packetList;
@property (nonatomic, readonly) NSString *text;

#pragma mark Constructors

+ (ASCIIArmor *)armorFromPacketList:(PacketList *)packetList;
+ (ASCIIArmor *)armorFromText:(NSString *)text;

@end
