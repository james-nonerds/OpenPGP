//
//  Key.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Key.h"

@interface Key () {
    NSMutableArray *_subkeys;
}

@end

@implementation Key

- (instancetype)init {
    self = [super init];
    
    if (self != nil) {
        _subkeys = [NSMutableArray array];
    }
    
    return self;
}

- (void)addSubkey:(Key *)subkey {
    [_subkeys addObject:subkey];
}

- (NSArray *)subkeys {
    return [NSArray arrayWithArray:_subkeys];
}

@end

@interface PublicKey ()

- (instancetype)initWithCreationTime:(NSUInteger)creationTime
                         fingerprint:(NSString *)fingerprint
                                   n:(MPI *)n
                                   e:(MPI *)e;

@end

@implementation PublicKey

+ (PublicKey *)keyWithCreationTime:(NSUInteger)creationTime
                       fingerprint:(NSString *)fingerprint
                                 n:(MPI *)n
                                 e:(MPI *)e {
    
    return [[self alloc] initWithCreationTime:creationTime
                                  fingerprint:fingerprint
                                            n:n
                                            e:e];
}


+ (PublicKey *)keyWithCreationTime:(NSUInteger)creationTime n:(MPI *)n e:(MPI *)e {
    return [[self alloc] initWithCreationTime:creationTime fingerprint:nil n:n e:e];
}

- (instancetype)initWithCreationTime:(NSUInteger)creationTime
                         fingerprint:(NSString *)fingerprint
                                   n:(MPI *)n
                                   e:(MPI *)e {
    
    self = [super init];
    
    if (self != nil) {
        _creationTime = creationTime;
        _fingerprint = fingerprint;
        _n = n;
        _e = e;
    }
    
    return self;
}

- (NSString *)keyID {
    NSString *fingerprint = self.fingerprint;
    return [fingerprint substringWithRange:NSMakeRange(fingerprint.length - 16, 16)];
}

@end

@interface SecretKey ()

- (instancetype)initWithPublicKey:(PublicKey *)publicKey
                                d:(MPI *)d
                                p:(MPI *)p
                                q:(MPI *)q
                                u:(MPI *)u;

@end

@implementation SecretKey

+ (SecretKey *)keyWithPublicKey:(PublicKey *)publicKey
                              d:(MPI *)d
                              p:(MPI *)p
                              q:(MPI *)q
                              u:(MPI *)u {
    
    return [[self alloc] initWithPublicKey:publicKey
                                         d:d
                                         p:p
                                         q:q
                                         u:u];
}

- (instancetype)initWithPublicKey:(PublicKey *)publicKey
                                d:(MPI *)d
                                p:(MPI *)p
                                q:(MPI *)q
                                u:(MPI *)u {
    
    self = [super init];
    
    if (self != nil) {
        _publicKey = publicKey;
        _d = d;
        _p = p;
        _q = q;
        _u = u;
    }
    
    return self;
}



@end