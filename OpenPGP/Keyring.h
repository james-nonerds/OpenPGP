//
//  Keyring.h
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Key.h"

@interface Keyring : NSObject

+ (Keyring *)keyring;

- (void)addPublicKey:(PublicKey *)publicKey forUserId:(NSString *)userId;
- (void)addSecretKey:(SecretKey *)secretKey forUserId:(NSString *)userId;

- (NSArray *)publicKeysForUserId:(NSString *)userId;
- (PublicKey *)publicKeyForKeyId:(NSString *)keyId;

- (NSArray *)secretKeysForUserId:(NSString *)userId;
- (SecretKey *)secretKeyForKeyId:(NSString *)keyId;

@end
