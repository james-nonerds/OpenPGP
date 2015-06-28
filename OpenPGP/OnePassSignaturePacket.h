//
//  OnePassSignaturePacket.h
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"
#import "Signature.h"

@interface OnePassSignaturePacket : Packet

@property (nonatomic, readonly) SignatureType signatureType;
@property (nonatomic, readonly) NSString *keyId;
@property (nonatomic, readonly) BOOL isNested;

@end
