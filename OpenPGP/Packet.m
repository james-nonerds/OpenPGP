//
//  Packet.m
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"
#import "MPI.h"

@interface Packet ()

+ (Packet *)packetWithBody:(NSData *)body;
+ (NSString *)keyIDFromBytes:(const Byte *)bytes;

@end

@implementation Packet

+ (Packet *)packetWithType:(PacketType)type body:(NSData *)body {
    Packet *packet = nil;
    
    switch (type) {
        case PacketTypePKESKey:
            packet = [PKESKeyPacket packetWithBody:body];
            
        case PacketTypeSignature:
        case PacketTypeSKESKey:
        case PacketTypeOnePassSig:
        case PacketTypeSecretKey:
        case PacketTypePublicKey:
        case PacketTypeSecretSubkey:
        case PacketTypeCompressedData:
        case PacketTypeSEData:
        case PacketTypeMarker:
        case PacketTypeLiteralData:
        case PacketTypeTrust:
        case PacketTypeUserID:
        case PacketTypePublicSubkey:
        case PacketTypeUserAttribute:
        case PacketTypeSEIPData:
        case PacketTypeModificationDetectionCode:
        case PacketTypePrivateA:
        case PacketTypePrivateB:
        case PacketTypePrivateC:
        case PacketTypePrivateD:
        case PacketTypeReserved:
        case PacketTypeUnknown:
            @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:@"Packet type not supported." userInfo:@{@"packetType": @(type)}];
    }
    
    return packet;
}

+ (Packet *)packetWithBody:(NSData *)body {
    @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                   reason:[NSString stringWithFormat:@"You must override this method in a subclass."]
                                 userInfo:@{@"method": NSStringFromSelector(_cmd)}];
}

+ (NSString *)keyIDFromBytes:(const Byte *)bytes {
    static const char *hexes = "0123456789abcdef";
    int		   i;
    
    char keyId[17];
    
    for (i = 0; i < 8 ; i++) {
        keyId[i * 2] = hexes[(unsigned)(bytes[i] & 0xf0) >> 4];
        keyId[(i * 2) + 1] = hexes[bytes[i] & 0xf];
    }
    
    keyId[8 * 2] = 0x0;
    
    
    return [NSString stringWithCString:keyId encoding:NSUTF8StringEncoding];
}

@end

@interface PKESKeyPacket ()

- (instancetype)initWithVersionNumber:(NSUInteger)versionNumber
                                keyId:(NSString *)keyId
                           encryptedM:(MPI *)encryptedM;

@end

#pragma mark - PKESKeyPacket implementation

@implementation PKESKeyPacket

#define PKESKeyPacketVersionIndex 0
#define PKESKeyPacketKeyIDIndex 1
#define PKESKeyPacketPKAIndex 9
#define PKESKeyPacketSessionKeyIndex 10
#define PKESKeyPacketSAIndex 10
#define PKESKeyPacketMSIIndex 11

#define PKESKeyPacketKeyIDLength 8

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    
    // Get version number:
    NSUInteger versionNumber = bytes[PKESKeyPacketVersionIndex];
    
    // Get key ID:
    Byte keyIdBytes[PKESKeyPacketKeyIDLength];
    memcpy(keyIdBytes, bytes + PKESKeyPacketKeyIDIndex, sizeof(Byte) * PKESKeyPacketKeyIDLength);
    
    NSString *keyId = [super keyIDFromBytes:keyIdBytes];
    
    // Get key algorithms out:
    PublicKeyAlgorithm publicKeyAlgorithm = bytes[PKESKeyPacketPKAIndex];
    
    switch (publicKeyAlgorithm) {
        case PublicKeyAlgorithmRSAEncryptSign:
        case PublicKeyAlgorithmRSAEncrypt: {
            MPI *encryptedM = [MPI mpiFromBytes:(bytes + PKESKeyPacketSAIndex)];
            
            return [[self alloc] initWithVersionNumber:versionNumber
                                                 keyId:keyId
                                            encryptedM:encryptedM];
        }
            
        default: {
            @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                           reason:@"Invalid public key algorithm."
                                         userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
        }
    }
}

- (instancetype)initWithVersionNumber:(NSUInteger)versionNumber
                                keyId:(NSString *)keyId
                           encryptedM:(MPI *)encryptedM {
    
    self = [super init];
    
    if (self != nil) {
        _encryptedM = encryptedM;
        _versionNumber = versionNumber;
        _keyId = keyId;
    }
    
    return self;
}

@end