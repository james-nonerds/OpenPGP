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
+ (NSUInteger)readNumber:(const Byte *)bytes length:(NSUInteger)length;

@end

@implementation Packet

+ (Packet *)packetWithType:(PacketType)type body:(NSData *)body {
    Packet *packet = nil;
    
    switch (type) {
        case PacketTypePKESKey:
            packet = [PKESKeyPacket packetWithBody:body];
            break;
            
        case PacketTypeSEIPData:
            packet = [SEIPDataPacket packetWithBody:body];
            break;
            
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
        case PacketTypeModificationDetectionCode:
        case PacketTypePrivateA:
        case PacketTypePrivateB:
        case PacketTypePrivateC:
        case PacketTypePrivateD:
        case PacketTypeReserved:
        case PacketTypeUnknown:
            @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                           reason:@"Packet type not supported."
                                         userInfo:@{@"packetType": @(type)}];
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

@end

@interface PKESKeyPacket ()

- (instancetype)initWithKeyId:(NSString *)keyId
                    encryptedM:(MPI *)encryptedM;

@end

#pragma mark - PKESKeyPacket implementation

@implementation PKESKeyPacket

#define PKESKeyPacketVersionNumber 3

#define PKESKeyPacketVersionIndex 0
#define PKESKeyPacketKeyIDIndex 1
#define PKESKeyPacketPKAIndex 9
#define PKESKeyPacketMPIIndex 10

#define PKESKeyPacketKeyIDLength 8

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    
    // Get version number:
    NSUInteger versionNumber = bytes[PKESKeyPacketVersionIndex];
    
    if (versionNumber != PKESKeyPacketVersionNumber) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Packet version not supported."
                                     userInfo:@{@"versionNumber": @(versionNumber)}];
    }
    
    // Get key ID:
    Byte keyIdBytes[PKESKeyPacketKeyIDLength];
    memcpy(keyIdBytes, bytes + PKESKeyPacketKeyIDIndex, sizeof(Byte) * PKESKeyPacketKeyIDLength);
    
    NSString *keyId = [super keyIDFromBytes:keyIdBytes];
    
    // Get key algorithms out:
    PublicKeyAlgorithm publicKeyAlgorithm = bytes[PKESKeyPacketPKAIndex];
    
    switch (publicKeyAlgorithm) {
        case PublicKeyAlgorithmRSAEncryptSign:
        case PublicKeyAlgorithmRSAEncrypt: {
            MPI *encryptedM = [MPI mpiFromBytes:(bytes + PKESKeyPacketMPIIndex)];
            
            return [[self alloc] initWithKeyId:keyId
                                    encryptedM:encryptedM];
        }
            
        default: {
            @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                           reason:@"Invalid public key algorithm."
                                         userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
        }
    }
}

- (instancetype)initWithKeyId:(NSString *)keyId
                   encryptedM:(MPI *)encryptedM {
    
    self = [super init];
    
    if (self != nil) {
        _encryptedM = encryptedM;
        _keyId = keyId;
    }
    
    return self;
}

@end

#pragma mark - SEIPDataPacket extension

@interface SEIPDataPacket ()

- (instancetype)initWithEncryptedData:(NSData *)encryptedData;

@end

#pragma mark - SEIPDataPacket implementation

@implementation SEIPDataPacket

#define SEIPDataPacketVersion 1

#define SEIPDataPacketVersionIndex 0
#define SEIPDataPacketEncryptedDataIndex 1

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    
    Byte versionNumber = bytes[SEIPDataPacketVersionIndex];
    
    if (versionNumber != SEIPDataPacketVersion) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Packet version not supported."
                                     userInfo:@{@"versionNumber": @(versionNumber)}];
    }
    
    return [[self alloc] initWithEncryptedData:[body subdataWithRange:NSMakeRange(1, body.length - 1)]];
}


- (instancetype)initWithEncryptedData:(NSData *)encryptedData {
    self = [super init];
    
    if (self != nil) {
        _encryptedData = encryptedData;
    }
    
    return self;
}

@end

#pragma mark - SignaturePacket extension

@interface SignaturePacket ()

+ (NSData *)subpacketsFromData:(NSData *)bytes atIndex:(NSUInteger)index;

- (instancetype)initV3WithSignatureType:(SignatureType)signatureType
                           creationTime:(NSUInteger)creationTime
                                  keyId:(NSString *)keyId
                              hashValue:(NSUInteger)hashValue
                             encryptedM:(MPI *)encryptedM;

- (instancetype)initV4WithSignatureType:(SignatureType)signatureType
                       hashedSubpackets:(NSData *)hashedSubpackets
                     unhashedSubpackets:(NSData *)unhashedSubpackets
                              hashValue:(NSUInteger)hashValue
                             encryptedM:(MPI *)encryptedM;

- (instancetype)initWithVersionNumber:(NSUInteger)versionNumber
                        signatureType:(SignatureType)signatureType
                            hashValue:(NSUInteger)hashValue
                           encryptedM:(MPI *)encryptedM;

@end

#pragma mark - SignaturePacket implementation

#define SignaturePacketVersionIndex 0

#define SignaturePacketV3HashLengthIndex 1
#define SignaturePacketV3SignatureTypeIndex 2
#define SignaturePacketV3CreationTimeIndex 3
#define SignaturePacketV3KeyIDIndex 7
#define SignaturePacketV3PKAlgorithmIndex 15
#define SignaturePacketV3HashAlgorithmIndex 16
#define SignaturePacketV3SignedHashIndex 17
#define SignaturePacketV3MPIIndex 19

#define SignaturePacketV4SignatureTypeIndex 1
#define SignaturePacketV4PKAlgorithmIndex 2
#define SignaturePacketV4HashAlgorithmIndex 3
#define SignaturePacketV4HashedSubpacketCountIndex 4

#define SignaturePacketV3HashLength 5

@implementation SignaturePacket

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    
    NSUInteger versionNumber = bytes[SignaturePacketVersionIndex];
    
    switch (versionNumber) {
        case 3: {
            NSUInteger hashLength = bytes[SignaturePacketV3HashLengthIndex];
            
            if (hashLength != SignaturePacketV3HashLength) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Packet version not supported."
                                      userInfo:@{@"versionNumber": @(versionNumber)}];
            }
            
            SignatureType signatureType = bytes[SignaturePacketV3SignatureTypeIndex];
            NSUInteger creationTime = [Packet readNumber:bytes + SignaturePacketV3CreationTimeIndex
                                                  length:4];
            
            NSString *keyId = [Packet keyIDFromBytes:bytes + SignaturePacketV3KeyIDIndex];
            
            PublicKeyAlgorithm publicKeyAlgorithm = bytes[SignaturePacketV3PKAlgorithmIndex];
            
            if (publicKeyAlgorithm != PublicKeyAlgorithmRSAEncryptSign) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Public key algorithm not supported."
                                      userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
            }
            
            HashAlgorithm hashAlgorithm = bytes[SignaturePacketV3HashAlgorithmIndex];
            
            if (hashAlgorithm != HashAlgorithmSHA256) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Hash algorithm not supported."
                                      userInfo:@{@"hashAlgorithm": @(hashAlgorithm)}];
            }
            
            NSUInteger hashValue = [Packet readNumber:bytes + SignaturePacketV3SignedHashIndex
                                               length:2];
            
            MPI *encryptedM = [MPI mpiFromBytes:(bytes + SignaturePacketV3MPIIndex)];
            
            return [[self alloc] initV3WithSignatureType:signatureType
                                            creationTime:creationTime
                                                   keyId:keyId
                                               hashValue:hashValue
                                              encryptedM:encryptedM];
        }
            
        case 4: {
            SignatureType signatureType = bytes[SignaturePacketV4SignatureTypeIndex];
            
            PublicKeyAlgorithm publicKeyAlgorithm = bytes[SignaturePacketV4PKAlgorithmIndex];
            
            if (publicKeyAlgorithm != PublicKeyAlgorithmRSAEncryptSign) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Public key algorithm not supported."
                                      userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
            }
            
            HashAlgorithm hashAlgorithm = bytes[SignaturePacketV4HashAlgorithmIndex];
            
            if (hashAlgorithm != HashAlgorithmSHA256) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Hash algorithm not supported."
                                      userInfo:@{@"hashAlgorithm": @(hashAlgorithm)}];
            }
            
            // Get hashed subpackets:
            NSData *hashedSubpackets = [SignaturePacket subpacketsFromData:body atIndex:SignaturePacketV4HashedSubpacketCountIndex];
            
            // Get unhashed subpackets:
            NSUInteger unhashedSubpacketIndex = SignaturePacketV4HashedSubpacketCountIndex + 2 + hashedSubpackets.length;
            NSData *unhashedSubpackets = [SignaturePacket subpacketsFromData:body atIndex:unhashedSubpacketIndex];
            
            NSUInteger hashValueIndex = unhashedSubpacketIndex + 2 + unhashedSubpackets.length;
            NSUInteger hashValue = [Packet readNumber:(bytes + hashValueIndex) length:2];
            
            MPI *encryptedM = [MPI mpiFromBytes:(bytes + hashValueIndex + 2)];
            
            return [[self alloc] initV4WithSignatureType:signatureType
                                        hashedSubpackets:hashedSubpackets
                                      unhashedSubpackets:unhashedSubpackets
                                               hashValue:hashValue
                                              encryptedM:encryptedM];
        }
            
        default: {
            @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                           reason:@"Packet version not supported."
                                         userInfo:@{@"versionNumber": @(versionNumber)}];
        }
    }
    
    return nil;
}

+ (NSData *)subpacketsFromData:(NSData *)data atIndex:(NSUInteger)index {
    const Byte *bytes = data.bytes;
    
    NSUInteger subpacketCount = [Packet readNumber:bytes length:2];
    
    return (subpacketCount > 0) ? [data subdataWithRange:NSMakeRange(index + 2, subpacketCount)] : nil;
}

- (instancetype)initV3WithSignatureType:(SignatureType)signatureType
                           creationTime:(NSUInteger)creationTime
                                  keyId:(NSString *)keyId
                              hashValue:(NSUInteger)hashValue
                             encryptedM:(MPI *)encryptedM {
    
    self = [self initWithVersionNumber:3
                         signatureType:signatureType
                             hashValue:hashValue
                            encryptedM:encryptedM];
    
    if (self != nil) {
        _keyId = keyId;
        _creationTime = creationTime;
    }
    
    return self;
}

- (instancetype)initV4WithSignatureType:(SignatureType)signatureType
                       hashedSubpackets:(NSData *)hashedSubpackets
                     unhashedSubpackets:(NSData *)unhashedSubpackets
                              hashValue:(NSUInteger)hashValue
                             encryptedM:(MPI *)encryptedM {
    
    self = [self initWithVersionNumber:4
                         signatureType:signatureType
                             hashValue:hashValue
                            encryptedM:encryptedM];
    
    if (self != nil) {
        _hashedSubpackets = hashedSubpackets;
        _unhashedSubpackets = unhashedSubpackets;
    }
    
    return self;
}

- (instancetype)initWithVersionNumber:(NSUInteger)versionNumber
                        signatureType:(SignatureType)signatureType
                            hashValue:(NSUInteger)hashValue
                           encryptedM:(MPI *)encryptedM {
    self = [super init];
    
    if (self != nil) {
        _versionNumber = versionNumber;
        _signatureType = signatureType;
        _hashValue = hashValue;
        _encryptedM = encryptedM;
    }
    
    return self;
}

@end













