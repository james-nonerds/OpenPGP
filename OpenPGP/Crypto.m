//
//  Crypto.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <openssl/aes.h>
#import <openssl/objects.h>
#import <openssl/rsa.h>
#import <openssl/sha.h>
#import "Crypto.h"
#import "Key.h"
#import "Keypair.h"

@interface RSAWrapper : NSObject

@property (nonatomic, readonly) RSA *rsa;

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

@implementation Crypto

+ (NSData *)hashData:(NSData *)data {
    Byte hash[SHA256_DIGEST_LENGTH];
    SHA256(data.bytes, data.length, hash);
    
    return [NSData dataWithBytes:hash length:SHA256_DIGEST_LENGTH];
}

#pragma mark RSA decrypt/encrypt

+ (NSData *)decryptData:(NSData *)data withSecretKey:(SecretKey *)key {
    
    RSAWrapper *rsaWrapper = [RSAWrapper rsaWithSecretKey:key];
    
    if (RSA_check_key(rsaWrapper.rsa) != 1) {
        NSLog(@"Error with key.");
        return nil;
    }
    
    Byte outbuf[8192];
    
    NSInteger outLength = RSA_private_decrypt((int) data.length, data.bytes, outbuf, rsaWrapper.rsa, RSA_NO_PADDING);
    
    return outLength > 0 ? [NSData dataWithBytes:outbuf length:outLength] : nil;
}

+ (NSData *)encryptData:(NSData *)data withPublicKey:(PublicKey *)key {
    
    RSAWrapper *rsaWrapper = [RSAWrapper rsaWithPublicKey:key];
    
    if (RSA_check_key(rsaWrapper.rsa) != 1) {
        NSLog(@"Error with key.");
        return nil;
    }
    
    Byte outbuf[8192];
    
    NSInteger outLength = RSA_public_encrypt((int) data.length, data.bytes, outbuf, rsaWrapper.rsa, RSA_NO_PADDING);
    
    return outLength > 0 ? [NSData dataWithBytes:outbuf length:outLength] : nil;}

#pragma mark RSA sign/verify

+ (NSData *)signData:(NSData *)data withSecretKey:(SecretKey *)key {
    
    RSAWrapper *rsaWrapper = [RSAWrapper rsaWithSecretKey:key];
    
    if (RSA_check_key(rsaWrapper.rsa) != 1) {
        NSLog(@"Error with key.");
        return nil;
    }
    
    Byte outbuf[8192];
    unsigned int outLen;
    
    int res = RSA_sign(NID_sha256, data.bytes, (unsigned int) data.length, outbuf, &outLen, rsaWrapper.rsa);
    
    return res && outLen > 0 ? [NSData dataWithBytes:outbuf length:outLen] : nil;
}

+ (BOOL)verifyData:(NSData *)messageData withSignatureData:(NSData *)signatureData withPublicKey:(PublicKey *)key {
    
    RSAWrapper *rsaWrapper = [RSAWrapper rsaWithPublicKey:key];
    
    return RSA_verify(NID_sha256, messageData.bytes, (unsigned int) messageData.length, signatureData.bytes, (unsigned int) signatureData.length, rsaWrapper.rsa);
}

#pragma mark AES decrypt/encrypt

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
    
    if (err) {
        NSLog(@"Error with CCCryptor create: %i", err);
    }
    
    err = CCCryptorUpdate(cryptor, data.bytes, data.length, outbuf, length, &num);
    
    if (err) {
        NSLog(@"Error with CCCryptor update: %i", err);
    }
    
    err = CCCryptorFinal(cryptor, outbuf, length, NULL);
    
    if (err) {
        NSLog(@"Error with CCCryptor final: %i", err);
    }
    
    NSUInteger sz_pre = kCCBlockSizeAES128 + 2;
    NSUInteger sz_mdc_hash = 20; // SHA1
    NSUInteger sz_mdc = 2 + sz_mdc_hash;
    NSUInteger sz_plaintext =  num - sz_pre - sz_mdc;
    
    // TODO: Verify plaintext integrity.
    
    Byte *plaintext = outbuf + sz_pre;
    
    return [NSData dataWithBytes:plaintext length:sz_plaintext];
}

+ (NSData *)encryptData:(NSData *)data withSymmetricKey:(const Byte *)symmetricKey {
    
    // TODO Add Preamble and MDC:
    
    Byte outbuf[data.length];
    Byte iv[16];
    size_t num = 0;
    
    memset(outbuf, 0, data.length);
    memset(iv, 0, 16);
    
    CCCryptorStatus     err;
    CCCryptorRef        cryptor;
    
    cryptor = NULL;
    
    err = CCCryptorCreateWithMode(kCCEncrypt, kCCModeCFB, kCCAlgorithmAES, ccNoPadding, iv, symmetricKey, kCCKeySizeAES256, NULL, 0, 0, 0, &cryptor);
    if (err) {
        NSLog(@"Error with CCCryptor create: %i", err);
    }
    
    err = CCCryptorUpdate(cryptor, data.bytes, data.length, outbuf, data.length, &num);
    
    if (err) {
        NSLog(@"Error with CCCryptor update: %i", err);
    }
    
    err = CCCryptorFinal(cryptor, outbuf, data.length, NULL);
    
    if (err) {
        NSLog(@"Error with CCCryptor final: %i", err);
    }
    
    return [NSData dataWithBytes:outbuf length:data.length];
}

#pragma mark Keypair

+ (Keypair *)generateKeypairWithBits:(int)bits {
    RSA *rsa;
    BIGNUM *bne;
    BN_CTX *ctx;
    
    ctx = BN_CTX_new();
    
    bne = BN_new();
    BN_set_word(bne, RSA_F4);
    
    rsa = RSA_new();
    RSA_generate_key_ex(rsa, bits, bne, NULL);
    
    NSDate *now = [NSDate date];
    NSUInteger timestamp = [now timeIntervalSince1970];
    
    MPI *n = [MPI mpiWithBIGNUM:rsa->n];
    MPI *e = [MPI mpiWithBIGNUM:rsa->e];
    
    MPI *d = [MPI mpiWithBIGNUM:rsa->d];
    MPI *p = [MPI mpiWithBIGNUM:rsa->p];
    MPI *q = [MPI mpiWithBIGNUM:rsa->q];
    MPI *u = [MPI mpiWithBIGNUM:BN_mod_inverse(NULL, rsa->p, rsa->q, ctx)];
    
    RSA_free(rsa);
    BN_CTX_free(ctx);
    
    PublicKey *publicKey = [PublicKey keyWithCreationTime:timestamp n:n e:e];
    SecretKey *secretKey = [SecretKey keyWithPublicKey:publicKey d:d p:p q:q u:u];
    
    RSAWrapper *publicKeyWrapper = [RSAWrapper rsaWithPublicKey:publicKey];
    RSAWrapper *secretKeyWrapper = [RSAWrapper rsaWithSecretKey:secretKey];
    
    return [Keypair keypairWithPublicKey:publicKey secretKey:secretKey];
}

@end

#pragma mark - RSAWrapper

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