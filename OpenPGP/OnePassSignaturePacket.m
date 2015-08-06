//
//  OnePassSignaturePacket.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "OnePassSignaturePacket.h"
#import "Utility.h"

@interface OnePassSignaturePacket ()

- (instancetype)initWithSignatureType:(SignatureType)signatureType keyId:(NSString *)keyId isNested:(BOOL)isNested;

@end

@implementation OnePassSignaturePacket

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    NSUInteger currentIndex = 0;
    
    // Get version number:
    NSUInteger versionNumber = bytes[currentIndex++];
    
    if (versionNumber != 3) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Packet version not supported."
                                     userInfo:@{@"versionNumber": @(versionNumber)}];
    }
    
    SignatureType signatureType = bytes[currentIndex++];
    
    PublicKeyAlgorithm publicKeyAlgorithm = bytes[currentIndex++];
    
    if (publicKeyAlgorithm != PublicKeyAlgorithmRSAEncryptSign) {
        [NSException exceptionWithName:NSInternalInconsistencyException
                                reason:@"Public key algorithm not supported."
                              userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
    }
    
    HashAlgorithm hashAlgorithm = bytes[currentIndex++];
    
    if (hashAlgorithm != HashAlgorithmSHA256) {
        [NSException exceptionWithName:NSInternalInconsistencyException
                                reason:@"Hash algorithm not supported."
                              userInfo:@{@"hashAlgorithm": @(hashAlgorithm)}];
    }
    
    NSString *keyId = [Utility keyIDFromBytes:bytes + currentIndex];
    currentIndex += 8;
    
    BOOL isNested = !(bytes[currentIndex]);
    
    return [[self alloc] initWithSignatureType:signatureType keyId:keyId isNested:isNested];
}

- (instancetype)initWithSignatureType:(SignatureType)signatureType keyId:(NSString *)keyId isNested:(BOOL)isNested {
    self = [super initWithType:PacketTypeOnePassSig];
    
    if (self != nil) {
        _signatureType = signatureType;
        _keyId = keyId;
        _isNested = isNested;
    }
    
    return self;
}

@end
