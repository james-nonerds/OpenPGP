//
//  UserIDPacket.m
//  OpenPGP
//
//  Created by James Knight on 6/26/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "UserIDPacket.h"
#import "Utility.h"

@interface UserIDPacket ()

- (instancetype)initWithUserID:(NSString *)userId;

@end

@implementation UserIDPacket

+ (Packet *)packetWithBody:(NSData *)body {
    NSString *userId = [Utility readString:body.bytes maxLength:body.length];
    
    return [[self alloc] initWithUserID:userId];
}

- (instancetype)initWithUserID:(NSString *)userId {
    self = [super init];
    
    if (self != nil) {
        _userId = userId;
    }
    
    return self;
}

@end
