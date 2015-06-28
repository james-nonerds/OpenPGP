//
//  SEIPDataPacket.h
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"

#pragma mark - SEIPDataPacket interface

@interface SEIPDataPacket : Packet

@property (nonatomic, readonly) NSData *encryptedData;

@end

