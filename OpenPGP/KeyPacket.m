//
//  PublicKeyPacket.m
//  OpenPGP
//
//  Created by James Knight on 6/26/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <openssl/sha.h>
#import "KeyPacket.h"
#import "MPI.h"
#import "Utility.h"

#define PublicKeyPacketVersionNumber 4

@interface KeyPacket ()

- (instancetype)initWithPublicKey:(PublicKey *)publicKey;
- (instancetype)initWithSecretKey:(SecretKey *)secretKey;

- (instancetype)initWithPublicKey:(PublicKey *)publicKey
                        secretKey:(SecretKey *)secretKey;

@end

@implementation KeyPacket

+ (KeyPacket *)packetWithBody:(NSData *)body {
    
    const Byte *bytes = body.bytes;
    NSUInteger currentIndex = 0;
    
    NSUInteger versionNumber = bytes[currentIndex++];
    
    if (versionNumber != PublicKeyPacketVersionNumber) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Packet version not supported."
                                     userInfo:@{@"versionNumber": @(versionNumber)}];
    }
    
    NSUInteger creationTime = [Utility readNumber:bytes + currentIndex length:4];
    currentIndex += 4;
    
    PublicKeyAlgorithm publicKeyAlgorithm = bytes[currentIndex++];
    
    if (publicKeyAlgorithm != PublicKeyAlgorithmRSAEncryptSign) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Public key algorithm not supported."
                                     userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
    }
    
    MPI *n = [MPI mpiFromBytes:bytes + currentIndex];
    currentIndex += n.length;
    
    MPI *e = [MPI mpiFromBytes:bytes + currentIndex];
    currentIndex += e.length;
    
    
    // Calculate fingerprint:
    Byte fingerprintBytes[currentIndex + 3];
    
    fingerprintBytes[0] = 0x99;
    fingerprintBytes[1] = (currentIndex >> 8) & 0xFF;
    fingerprintBytes[2] = currentIndex & 0xFF;
    
    memcpy(fingerprintBytes + 3, bytes, currentIndex);
    
    Byte fingerprintOutput[SHA_DIGEST_LENGTH];
    SHA1(fingerprintBytes, currentIndex + 3, fingerprintOutput);
    
    NSString *fingerprint = [Utility hexStringFromBytes:fingerprintOutput length:SHA_DIGEST_LENGTH];
    
    PublicKey *publicKey = [PublicKey keyWithCreationTime:creationTime
                                              fingerprint:fingerprint
                                                        n:n
                                                        e:e];
    
    // If we're at the end of the packet then we have just a public key:
    if (currentIndex == body.length) {
        return [[self alloc] initWithPublicKey:publicKey];
    }
    
    // Finish secret key:
    
    NSUInteger stringToKey = bytes[currentIndex++];
    
    if (stringToKey != 0) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"String to key convention not supported."
                                     userInfo:@{@"stringToKey": @(stringToKey)}];
    }
    
    
    MPI *d = [MPI mpiFromBytes:bytes + currentIndex];
    currentIndex += d.length;
    
    MPI *p = [MPI mpiFromBytes:bytes + currentIndex];
    currentIndex += p.length;
    
    MPI *q = [MPI mpiFromBytes:bytes + currentIndex];
    currentIndex += q.length;
    
    MPI *u = [MPI mpiFromBytes:bytes + currentIndex];
    
    SecretKey *secretKey = [SecretKey keyWithPublicKey:publicKey
                                                     d:d
                                                     p:p
                                                     q:q
                                                     u:u];
    
    return [[self alloc] initWithSecretKey:secretKey];
}

- (instancetype)initWithPublicKey:(PublicKey *)publicKey {
    return [self initWithPublicKey:publicKey secretKey:nil];
}

- (instancetype)initWithSecretKey:(SecretKey *)secretKey {
    return [self initWithPublicKey:nil secretKey:secretKey];
}


- (instancetype)initWithPublicKey:(PublicKey *)publicKey
                        secretKey:(SecretKey *)secretKey {
    self = [super init];
    
    if (self != nil) {
        _publicKey = publicKey;
        _secretKey = secretKey;
    }
    
    return self;
}

@end








