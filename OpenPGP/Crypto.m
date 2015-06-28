//
//  Crypto.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <openssl/aes.h>
#import <openssl/rsa.h>
#import "Crypto.h"

@interface RSAWrapper : NSObject

@property (nonatomic, readonly) RSA *rsa;

@property (nonatomic, readonly) BIGNUM *n;
@property (nonatomic, readonly) BIGNUM *e;

@property (nonatomic, readonly) BIGNUM *d;
@property (nonatomic, readonly) BIGNUM *p;
@property (nonatomic, readonly) BIGNUM *q;

+ (instancetype)rsaWithPublicKey:(PublicKey *)publicKey;
+ (instancetype)rsaWithSecretKey:(SecretKey *)secretKey;

- (instancetype)initWithPublicKey:(PublicKey *)publicKey;
- (instancetype)initWithSecretKey:(SecretKey *)secretKey;

- (instancetype)initWithN:(BIGNUM *)n
                        e:(BIGNUM *)e
                        d:(BIGNUM *)d
                        p:(BIGNUM *)p
                        q:(BIGNUM *)q;

@end

@interface Crypto ()

+ (NSData *)decryptBytes:(const Byte *)bytes length:(NSUInteger)length withSecretKey:(SecretKey *)key;

@end

@implementation Crypto

+ (NSData *)decryptData:(NSData *)data withSecretKey:(SecretKey *)key {
    return [self decryptBytes:data.bytes length:data.length withSecretKey:key];
}

+ (NSData *)decryptMessage:(MPI *)message withSecretKey:(SecretKey *)key {
    
    NSUInteger length = BN_num_bytes(message.bn);
    Byte mpibuf[length];
    
    memset(mpibuf, 0, length);
    
    BN_bn2bin(message.bn, mpibuf);
    
    return [self decryptBytes:mpibuf length:length withSecretKey:key];
}

+ (NSData *)decryptBytes:(const Byte *)bytes length:(NSUInteger)length withSecretKey:(SecretKey *)key {
    RSAWrapper *rsaWrapper = [RSAWrapper rsaWithSecretKey:key];
    
    if (RSA_check_key(rsaWrapper.rsa) != 1) {
        NSLog(@"Error with key.");
        return nil;
    }
    
    Byte outbuf[8192];
    
    NSUInteger outLength = RSA_private_decrypt((int) length, bytes, outbuf, rsaWrapper.rsa, 3);
    
    return [NSData dataWithBytes:outbuf length:outLength];
}

+ (NSData *)decryptData:(NSData *)data withSymmetricKey:(const Byte *)symmetricKey {
    NSUInteger length = data.length + kCCBlockSizeAES128;
    
    Byte outbuf[length];
    Byte iv[16];
    size_t num = 0;
    
    memset(outbuf, 0, length);
    memset(iv, 0, 16);
    
    CCCryptorStatus     err;
    CCCryptorRef        cryptor;
    
    cryptor = NULL;
    
    err = CCCryptorCreateWithMode(kCCDecrypt, kCCModeCFB, kCCAlgorithmAES, ccNoPadding, iv, symmetricKey, kCCKeySizeAES256, NULL, 0, 0, 0, &cryptor);
    
    err = CCCryptorUpdate(cryptor, data.bytes, data.length, outbuf, length, &num);
    err = CCCryptorFinal(cryptor, outbuf, length, NULL);
    
    NSLog(@"%s", outbuf);
    
    return [NSData dataWithBytes:data.bytes length:data.length];
}

@end

@implementation RSAWrapper

+ (instancetype)rsaWithPublicKey:(PublicKey *)publicKey {
    return [[self alloc] initWithPublicKey:publicKey];
}

+ (instancetype)rsaWithSecretKey:(SecretKey *)secretKey {
    return [[self alloc] initWithSecretKey:secretKey];
}

- (instancetype)initWithPublicKey:(PublicKey *)publicKey {
    return [self initWithN:publicKey.n.bn
                         e:publicKey.e.bn
                         d:nil
                         p:nil
                         q:nil];
}

- (instancetype)initWithSecretKey:(SecretKey *)secretKey {
    return [self initWithN:secretKey.publicKey.n.bn
                         e:secretKey.publicKey.e.bn
                         d:secretKey.d.bn
                         p:secretKey.p.bn
                         q:secretKey.q.bn];
}

- (instancetype)initWithN:(BIGNUM *)n
                        e:(BIGNUM *)e
                        d:(BIGNUM *)d
                        p:(BIGNUM *)p
                        q:(BIGNUM *)q {
    self = [super init];
    
    if (self != nil) {
        _rsa = RSA_new();
        
        _rsa->n = BN_dup(n);
        _rsa->e = BN_dup(e);
        
        _rsa->d = BN_dup(d);
        _rsa->p = BN_dup(p);
        _rsa->q = BN_dup(q);
    }
    
    return self;
}

- (void)dealloc {
    RSA_free(_rsa);
}

@end