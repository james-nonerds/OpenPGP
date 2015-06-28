//
//  Keyring.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Keyring.h"

@interface Keyring () {
    NSMutableDictionary *_publicKeysByUserId, *_publicKeysByKeyId;
    NSMutableDictionary *_secretKeysByUserId, *_secretKeysByKeyId;
    NSMutableDictionary *_publicSubkeysByKeyId, *_publicSubkeysByUserId;
    NSMutableDictionary *_secretSubkeysByKeyId, *_secretSubkeysByUserId;
}

- (void)addPublicSubkey:(PublicKey *)publicSubkey forUserId:(NSString *)userId;
- (void)addSecretSubkey:(SecretKey *)secretSubkey forUserId:(NSString *)userId;

@end

@implementation Keyring

+ (Keyring *)keyring {
    return [[self alloc] init];
}

- (instancetype)init {
    self = [super init];
    
    if (self != nil) {
        _publicKeysByUserId = [NSMutableDictionary dictionary];
        _publicKeysByKeyId = [NSMutableDictionary dictionary];
        
        _secretKeysByUserId = [NSMutableDictionary dictionary];
        _secretKeysByKeyId = [NSMutableDictionary dictionary];
        
        _publicSubkeysByKeyId = [NSMutableDictionary dictionary];
        _publicSubkeysByUserId = [NSMutableDictionary dictionary];
        
        _secretSubkeysByKeyId = [NSMutableDictionary dictionary];
        _secretSubkeysByUserId = [NSMutableDictionary dictionary];
    }
    
    return self;
}

- (void)addPublicKey:(PublicKey *)publicKey forUserId:(NSString *)userId {
    if (_publicKeysByUserId[userId]) {
//        NSLog(@"Overwriting public key w/ user id: %@", userId);
    }
    
    _publicKeysByUserId[userId] = publicKey;
    _publicKeysByKeyId[publicKey.keyID] = publicKey;
    
}


- (void)addSecretKey:(SecretKey *)secretKey forUserId:(NSString *)userId {
    if (_secretKeysByUserId[userId]) {
//        NSLog(@"Overwriting secret key w/ user id: %@", userId);
    }
    
    [self addPublicKey:secretKey.publicKey forUserId:userId];
    
    _secretKeysByUserId[userId] = secretKey;
    _secretKeysByKeyId[secretKey.publicKey.keyID] = secretKey;
    
    for (SecretKey *subkey in secretKey.subkeys) {
        [self addSecretSubkey:subkey forUserId:userId];
    }
}

- (void)addPublicSubkey:(PublicKey *)publicSubkey forUserId:(NSString *)userId {
    if (_publicSubkeysByUserId[userId]) {
        NSLog(@"Overwriting public subkey w/ user id: %@", userId);
    }
    
    _publicSubkeysByUserId[userId] = publicSubkey;
    _publicSubkeysByKeyId[publicSubkey.keyID] = publicSubkey;
}

- (void)addSecretSubkey:(SecretKey *)secretSubkey forUserId:(NSString *)userId {
    if (_secretSubkeysByUserId[userId]) {
        NSLog(@"Overwriting secret subkey w/ user id: %@", userId);
    }
    
    _secretSubkeysByUserId[userId] = secretSubkey;
    _secretSubkeysByKeyId[secretSubkey.publicKey.keyID] = secretSubkey;
}

- (PublicKey *)publicKeyForUserId:(NSString *)userId {
    return _publicKeysByUserId[userId] ?: _publicSubkeysByUserId[userId];
}

- (PublicKey *)publicKeyForKeyId:(NSString *)keyId {
    return _publicKeysByKeyId[keyId] ?: _publicSubkeysByKeyId[keyId];
}

- (SecretKey *)secretKeyForUserId:(NSString *)userId {
    return _secretKeysByUserId[userId] ?: _secretKeysByUserId[userId];
}

- (SecretKey *)secretKeyForKeyId:(NSString *)keyId {
    return _secretKeysByKeyId[keyId] ?: _secretSubkeysByKeyId[keyId];
}

@end
