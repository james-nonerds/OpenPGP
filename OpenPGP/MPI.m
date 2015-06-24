//
//  MPI.m
//  OpenPGP
//
//  Created by James Knight on 6/24/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "MPI.h"

@interface MPI () {
    BIGNUM *_bn;
}

- (id)initWithBIGNUM:(BIGNUM *)bn length:(NSUInteger)length;

@end

@implementation MPI

+ (MPI *)mpiFromBytes:(const Byte *)bytes {
    unsigned bitCount = (bytes[0] << 8) | bytes[1];
    unsigned length = (bitCount + 7) / 8;  // Taken from NetPGP, poor man's CEIL.
    
    Byte mpiBytes[length];
    memcpy(mpiBytes, bytes + 2, length);
    
    BIGNUM *bn = BN_bin2bn(mpiBytes, (int) length, NULL);
    
    return [[self alloc] initWithBIGNUM:bn length:length];
}

- (id)initWithBIGNUM:(BIGNUM *)bn length:(NSUInteger)length {
    self = [super init];
    
    if (self != nil) {
        _bn = bn;
        _length = length;
    }
    
    return self;
}

- (void)dealloc {
    BN_free(_bn);
    _bn = NULL;
}

- (BIGNUM *)bn {
    return _bn;
}

@end
