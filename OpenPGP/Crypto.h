//
//  Crypto.h
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import "Key.h"

typedef NS_ENUM(NSUInteger, CompressionAlgorithm) {
    CompressionAlgorithmDefault = 1
};

typedef NS_ENUM(NSUInteger, HashAlgorithm) {
    HashAlgorithmMD5 = 1,
    HashAlgorithmSHA1 = 2,
    HashAlgorithmRipeMD = 3,
    HashAlgorithmSHA256 = 8,
    HashAlgorithmSHA384 = 9,
    HashAlgorithmSHA512 = 10,
    HashAlgorithmSHA224 = 11
};

typedef NS_ENUM(NSUInteger, PublicKeyAlgorithm) {
    PublicKeyAlgorithmRSAEncryptSign = 1,
    PublicKeyAlgorithmRSAEncrypt = 2,
    PublicKeyAlgorithmRSASign = 3,
    PublicKeyAlgorithmElGamal = 16,
    PublicKeyAlgorithmDSA = 17
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

@interface Crypto : NSObject

+ (NSData *)decryptData:(NSData *)data withSecretKey:(SecretKey *)key;
+ (NSData *)decryptMessage:(MPI *)message withSecretKey:(SecretKey *)key;

+ (NSData *)decryptData:(NSData *)data withSymmetricKey:(const Byte *)symmetricKey;

@end
