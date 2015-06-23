//
//  Packetlist.m
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "PacketList.h"

@interface PacketList ()

@property (nonatomic, strong) NSArray *packets;

@end

@implementation PacketList

+ (instancetype)packetListFromData:(NSData *)data {
    return [[self alloc] init];
}

+ (instancetype)packetListWithPackets:(NSArray *)packets {
    return [[self alloc] init];
}

+ (instancetype)emptyPacketList {
    return [[self alloc] init];
}

@end
