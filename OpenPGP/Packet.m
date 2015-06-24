//
//  Packet.m
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"

@implementation Packet

+ (Packet *)packetWithType:(PacketType)type body:(NSData *)body {
    return [[self alloc] initWithType:type body:body];
}

- (id)initWithType:(PacketType)type body:(NSData *)body {
    self = [super init];
    
    if (self != nil) {
        _type = type;
        _body = body;
    }
    
    return self;
}

@end
