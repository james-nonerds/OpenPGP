//
//  MPI.h
//  OpenPGP
//
//  Created by James Knight on 6/24/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/BN.h>

@interface MPI : NSObject

@property (nonatomic, readonly) NSUInteger length;
@property (nonatomic, readonly) BIGNUM *bn;

+ (MPI *)mpiFromBytes:(const Byte *)bytes byteCount:(NSUInteger)byteCount;
+ (MPI *)mpiFromBytes:(const Byte *)bytes;

@end
