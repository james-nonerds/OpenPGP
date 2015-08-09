//
//  Signature.m
//  OpenPGP
//
//  Created by James Knight on 6/24/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Crypto.h"
#import "Signature.h"
#import "KeyPacket.h"
#import "SignaturePacket.h"
#import "UserIDPacket.h"
#import "Utility.h"

@implementation Signature

+ (Signature *)signatureForKeyPacket:(KeyPacket *)keyPacket
                        userIdPacket:(UserIDPacket *)userIdPacket
                        signatureKey:(SecretKey *)signatureKey {
    NSMutableData *signatureBody = [NSMutableData data];
    
    NSData *keyBody = keyPacket.body;
    
    Byte keyHeader[3];
    
    keyHeader[0] = 0x99;
    [Utility writeNumber:keyBody.length bytes:keyHeader + 1 length:2];
    
    [signatureBody appendBytes:keyHeader length:3];
    [signatureBody appendData:keyBody];
    
    NSData *userIdBody = userIdPacket.body;
    
    Byte userIdHeader[5];
    
    userIdHeader[0] = 0xB4;
    [Utility writeNumber:userIdBody.length bytes:userIdHeader + 1 length:4];
    
    [signatureBody appendBytes:userIdHeader length:5];
    [signatureBody appendData:userIdBody];
    
    NSData *hashData = [Crypto hashData:signatureBody];
    NSData *signatureData = [Crypto signData:hashData withSecretKey:signatureKey];
    
    NSString *keyId = nil;
    
    if (keyPacket.publicKey) {
        keyId = keyPacket.publicKey.keyID;
    } else {
        keyId = keyPacket.secretKey.publicKey.keyID;
    }
    
    return [[self alloc] initWithType:SignatureTypeUserIDCertificationGeneric data:signatureData keyID:keyPacket.publicKey.keyID];
}

+ (Signature *)signatureForSignaturePacket:(SignaturePacket *)signaturePacket {
    return [[self alloc] initWithType:signaturePacket.signatureType data:signaturePacket.signatureData keyID:signaturePacket.keyId];
}

- (instancetype)initWithType:(SignatureType)type data:(NSData *)data keyID:(NSString *)keyID {
    self = [super init];
    
    if (self != nil) {
        _type = type;
        _data = data;
        _keyID = keyID;
    }
    
    return self;
}


@end
