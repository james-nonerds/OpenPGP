//
//  Packetlist.m
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "PacketList.h"
#import "Packet.h"
#import "PacketReader.h"

@interface PacketList ()

@property (nonatomic, strong) NSArray *packets;

- (instancetype)initWithPackets:(NSArray *)packets;

@end

@implementation PacketList

+ (instancetype)packetListFromData:(NSData *)data {
    PacketReader *reader = [PacketReader readerWithData:data];
    
    NSMutableArray *packets = [NSMutableArray array];
    
    while (!reader.isComplete) {
        NSError *error = nil;
        Packet *packet = [reader readPacketWithError:&error];
        
        if (error != nil) {
            NSLog(@"Error reading packet: %@", error);
        }
        
        [packets addObject:packet];
    }
    
    return [self packetListWithPackets:[NSArray arrayWithArray:packets]];
}

+ (instancetype)packetListWithPackets:(NSArray *)packets {
    return [[self alloc] initWithPackets:packets];
}

+ (instancetype)emptyPacketList {
    return [[self alloc] initWithPackets:@[]];
}

- (instancetype)initWithPackets:(NSArray *)packets {
    self = [super init];
    
    if (self != nil) {
        _packets = packets;
    }
    
    return self;
}

@end
