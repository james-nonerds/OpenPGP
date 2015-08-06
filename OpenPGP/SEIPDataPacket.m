//
//  SEIPDataPacket.m
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "SEIPDataPacket.h"

#pragma mark -SEIPDataPacket constants

#define SEIPDataPacketVersion 1

#define SEIPDataPacketVersionIndex 0
#define SEIPDataPacketEncryptedDataIndex 1

#pragma mark - SEIPDataPacket extension

@interface SEIPDataPacket ()

- (instancetype)initWithEncryptedData:(NSData *)encryptedData;

@end

#pragma mark - SEIPDataPacket implementation

@implementation SEIPDataPacket

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    
    Byte versionNumber = bytes[SEIPDataPacketVersionIndex];
    
    if (versionNumber != SEIPDataPacketVersion) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Packet version not supported."
                                     userInfo:@{@"versionNumber": @(versionNumber)}];
    }
    
    return [[self alloc] initWithEncryptedData:[body subdataWithRange:NSMakeRange(1, body.length - 1)]];
}


- (instancetype)initWithEncryptedData:(NSData *)encryptedData {
    self = [super initWithType:PacketTypeSEIPData];
    
    if (self != nil) {
        _encryptedData = encryptedData;
    }
    
    return self;
}

@end

