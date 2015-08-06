//
//  PKESPacket.m
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "PKESPacket.h"
#import "MPI.h"
#import "Utility.h"

#pragma mark - PKESKeyPacket constants

#define PKESKeyPacketVersionNumber 3

#define PKESKeyPacketVersionIndex 0
#define PKESKeyPacketKeyIDIndex 1
#define PKESKeyPacketPKAIndex 9
#define PKESKeyPacketMPIIndex 10

#define PKESKeyPacketKeyIDLength 8

#pragma mark - PKESKeyPacket extension

@interface PKESKeyPacket ()

- (instancetype)initWithKeyId:(NSString *)keyId
                   encryptedM:(MPI *)encryptedM;

@end

#pragma mark - PKESKeyPacket implementation

@implementation PKESKeyPacket

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
    
    NSString *keyId = [Utility keyIDFromBytes:keyIdBytes];
    
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
    
    self = [super initWithType:PacketTypePKESKey];
    
    if (self != nil) {
        _encryptedM = encryptedM;
        _keyId = keyId;
    }
    
    return self;
}

@end

