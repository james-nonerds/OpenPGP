//
//  Packet.m
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"
#import "PKESPacket.h"
#import "KeyPacket.h"
#import "LiteralDataPacket.h"
#import "OnePassSignaturePacket.h"
#import "SEIPDataPacket.h"
#import "SignaturePacket.h"
#import "UserIDPacket.h"

@interface Packet ()

@property (nonatomic, assign) PacketType packetType;

@end

@implementation Packet

+ (Packet *)packetWithType:(PacketType)type body:(NSData *)body {
    Packet *packet = nil;
    
    switch (type) {
        case PacketTypePKESKey:
            packet = [PKESKeyPacket packetWithBody:body];
            break;
            
        case PacketTypeSEIPData:
            packet = [SEIPDataPacket packetWithBody:body];
            break;
            
        case PacketTypeSignature:
            packet = [SignaturePacket packetWithBody:body];
            break;
            
        case PacketTypePublicKey:
        case PacketTypePublicSubkey:
        case PacketTypeSecretKey:
        case PacketTypeSecretSubkey:
            packet = [KeyPacket packetWithBody:body];
            break;
            
        case PacketTypeUserID:
            packet = [UserIDPacket packetWithBody:body];
            break;
            
        case PacketTypeOnePassSig:
            packet = [OnePassSignaturePacket packetWithBody:body];
            break;
            
        case PacketTypeLiteralData:
            packet = [LiteralDataPacket packetWithBody:body];
            break;
            
        case PacketTypeSKESKey:
        case PacketTypeCompressedData:
        case PacketTypeSEData:
        case PacketTypeMarker:
        case PacketTypeTrust:
        case PacketTypeUserAttribute:
        case PacketTypeModificationDetectionCode:
        case PacketTypePrivateA:
        case PacketTypePrivateB:
        case PacketTypePrivateC:
        case PacketTypePrivateD:
        case PacketTypeReserved:
        case PacketTypeUnknown:
        default:
            @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                           reason:@"Packet type not supported."
                                         userInfo:@{@"packetType": @(type)}];
    }
    
    packet.packetType = type;
    
    return packet;
}

+ (Packet *)packetWithBody:(NSData *)body {
    @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                   reason:[NSString stringWithFormat:@"You must override this method in a subclass."]
                                 userInfo:@{@"method": NSStringFromSelector(_cmd)}];
}

@end













