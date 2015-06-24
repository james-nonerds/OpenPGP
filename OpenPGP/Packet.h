//
//  Packet.h
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>

@class MPI;

typedef NS_ENUM(NSUInteger, PacketType) {
    PacketTypeReserved = 0,
    PacketTypePKESKey = 1,
    PacketTypeSignature = 2,
    PacketTypeSKESKey = 3,
    PacketTypeOnePassSig = 4,
    PacketTypeSecretKey = 5,
    PacketTypePublicKey = 6,
    PacketTypeSecretSubkey = 7,
    PacketTypeCompressedData = 8,
    PacketTypeSEData = 9,
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

typedef NS_ENUM(NSUInteger, SymmetricAlgorithm) {
    SymmetricAlgorithmPlaintext = 0,
    SymmetricAlgorithmIdea = 1,
    SymmetricAlgorithmTripleDES = 2,
    SymmetricAlgorithmCast5 = 3,
    SymmetricAlgorithmBlowfish = 4,
    SymmetricAlgorithmAES128 = 7,
    SymmetricAlgorithmAES192 = 8,
    SymmetricAlgorithmAES256 = 9,
    SymmetricAlgorithmTwoFish = 10
};

typedef NS_ENUM(NSUInteger, PublicKeyAlgorithm) {
    PublicKeyAlgorithmRSAEncryptSign = 1,
    PublicKeyAlgorithmRSAEncrypt = 2,
    PublicKeyAlgorithmRSASign = 3,
    PublicKeyAlgorithmElGamal = 16,
    PublicKeyAlgorithmDSA = 17
};

@interface Packet : NSObject

+ (Packet *)packetWithType:(PacketType)type body:(NSData *)body;

@end

@interface PKESKeyPacket : Packet

@property (nonatomic, readonly) NSUInteger versionNumber;
@property (nonatomic, readonly) NSString *keyId;
@property (nonatomic, readonly) MPI *encryptedM;

@end


