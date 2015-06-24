//
//  Packet.h
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, PacketType) {
    PacketTypeReserved = 0,
    PacketTypePublicKeyEncryptedSessionKey = 1,
    PacketTypeSignature = 2,
    PacketTypeSymmetricKeyEncryptedSessionKey = 3,
    PacketTypeOnePassSignature = 4,
    PacketTypeSecretKey = 5,
    PacketTypePublicKey = 6,
    PacketTypeSecretSubkey = 7,
    PacketTypeCompressedData = 8,
    PacketTypeSymmetricallyEncryptedData = 9,
    PacketTypeMarker = 10,
    PacketTypeLiteralData = 11,
    PacketTypeTrust = 12,
    PacketTypeUserID = 13,
    PacketTypePublicSubkey = 14,
    PacketTypeUserAttribute = 17,
    PacketTypeSEIPData = 18,
    PacketTypeModificationDetectionCode = 19,
    PacketTypePrivateA = 60,
    PacketTypePrivateB = 61,
    PacketTypePrivateC = 62,
    PacketTypePrivateD = 63,
    PacketTypeUnknown = 255
};

@interface Packet : NSObject

@property (nonatomic, readonly) PacketType type;
@property (nonatomic, readonly) NSData *body;

+ (Packet *)packetWithType:(PacketType)type body:(NSData *)body;

@end
