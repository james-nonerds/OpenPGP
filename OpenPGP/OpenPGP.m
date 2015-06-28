//
//  OpenPGP.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "OpenPGP.h"
#import "ASCIIArmor.h"
#import "Key.h"
#import "Keyring.h"
#import "Packet.h"
#import "Signature.h"
#import "PKESPacket.h"
#import "KeyPacket.h"
#import "LiteralDataPacket.h"
#import "OnePassSignaturePacket.h"
#import "SEIPDataPacket.h"
#import "SignaturePacket.h"
#import "UserIDPacket.h"
#import "Utility.h"

@interface OpenPGP ()

+ (NSError *)errorWithCause:(NSString *)cause;

+ (void)readPublicKeyMessages:(NSArray *)publicKeyMessages intoKeyring:(Keyring *)keyring;
+ (void)readSecretKeyMessages:(NSArray *)secretKeyMessages intoKeyring:(Keyring *)keyring;

+ (void)readPublicKeyMessage:(NSString *)publicKeyMessage intoKeyring:(Keyring *)keyring;
+ (void)readSecretKeyMessage:(NSString *)secretKeyMessage intoKeyring:(Keyring *)keyring;

+ (PacketList *)decryptPacketList:(PacketList *)packetList withKeyring:(Keyring *)keyring;

@end

@implementation OpenPGP

+ (void)decryptAndVerifyMessage:(NSString *)message
                     privateKey:(NSString *)privateKey
                     publicKeys:(NSArray *)publicKeys
                completionBlock:(void (^)(NSString *decryptedMessage, NSArray *verifiedUserIds))completionBlock
                     errorBlock:(void (^)(NSError *))errorBlock {
    if (message == nil || publicKeys == nil) {
        errorBlock([OpenPGP errorWithCause:@"OpenPGP decryptAndVerifyMessage: Neither data nor publicKeys can be nil."]);
        return;
    }
    
    if (publicKeys.count < 1) {
        errorBlock([OpenPGP errorWithCause:@"OpenPGP decryptAndVerifyMessage: Public keys is empty."]);
        return;
    }
    
    Keyring *keyring = [Keyring keyring];
    
    [self readSecretKeyMessage:privateKey intoKeyring:keyring];
    [self readPublicKeyMessages:publicKeys intoKeyring:keyring];
    
    ASCIIArmor *asciiArmor = [ASCIIArmor armorFromText:message];
    PacketList *packetList = [PacketList packetListFromData:asciiArmor.content];
    
    [self decryptPacketList:packetList withKeyring:keyring];
}

+ (void)readPublicKeyMessages:(NSArray *)publicKeyMessages intoKeyring:(Keyring *)keyring {
    
    for (NSString *publicKeyMessage in publicKeyMessages) {
        [self readPublicKeyMessage:publicKeyMessage intoKeyring:keyring];
    }
    
}

+ (void)readSecretKeyMessages:(NSArray *)secretKeyMessages intoKeyring:(Keyring *)keyring {
    
    for (NSString *secretKeyMessage in secretKeyMessages) {
        [self readSecretKeyMessage:secretKeyMessage intoKeyring:keyring];
    }
    
}

+ (void)readPublicKeyMessage:(NSString *)publicKeyMessage intoKeyring:(Keyring *)keyring {
    
    ASCIIArmor *armor = [ASCIIArmor armorFromText:publicKeyMessage];
    PacketList *packetList = [PacketList packetListFromData:armor.content];
    
    NSString *userId = nil;
    
    PublicKey *publicKey = nil;
    Signature *signature = nil;
    
    PublicKey *publicSubkey = nil;
    Signature *subkeySignature = nil;
    
    BOOL lastKeyWasSubkey = NO;
    
    for (Packet *packet in packetList.packets) {
        switch (packet.packetType) {
            case PacketTypeUserID:
                userId = ((UserIDPacket *) packet).userId;
                break;
                
            case PacketTypePublicKey:
                publicKey = ((KeyPacket *) packet).publicKey;
                break;
                
            case PacketTypePublicSubkey:
                publicSubkey = ((KeyPacket *) packet).publicKey;
                lastKeyWasSubkey = YES;
                break;
                
            case PacketTypeSignature:
                if (lastKeyWasSubkey) {
                    subkeySignature = ((SignaturePacket *) packet).signature;
                    lastKeyWasSubkey = NO;
                } else {
                    signature = ((SignaturePacket *) packet).signature;
                }
                break;
                
            default:
                NSLog(@"Unsupported packet type: %lu", packet.packetType);
                break;
        }
    }
    
    if (publicSubkey) {
        [publicKey addSubkey:publicSubkey];
    }
    
    // TODO: Verify key.
    [keyring addPublicKey:publicKey forUserId:userId];
}

+ (void)readSecretKeyMessage:(NSString *)secretKeyMessage intoKeyring:(Keyring *)keyring {
    
    ASCIIArmor *armor = [ASCIIArmor armorFromText:secretKeyMessage];
    PacketList *packetList = [PacketList packetListFromData:armor.content];
    
    NSString *userId = nil;
    
    SecretKey *secretKey = nil;
    Signature *signature = nil;
    
    SecretKey *secretSubkey = nil;
    Signature *subkeySignature = nil;
    
    BOOL lastKeyWasSubkey = NO;
    
    for (Packet *packet in packetList.packets) {
        switch (packet.packetType) {
            case PacketTypeUserID:
                userId = ((UserIDPacket *) packet).userId;
                break;
                
            case PacketTypeSecretKey:
                secretKey = ((KeyPacket *) packet).secretKey;
                break;
                
            case PacketTypeSecretSubkey:
                secretSubkey = ((KeyPacket *) packet).secretKey;
                lastKeyWasSubkey = YES;
                break;
                
            case PacketTypeSignature:
                if (lastKeyWasSubkey) {
                    subkeySignature = ((SignaturePacket *) packet).signature;
                    lastKeyWasSubkey = NO;
                } else {
                    signature = ((SignaturePacket *) packet).signature;
                }
                break;
                
            default:
                NSLog(@"Unsupported packet type: %lu", packet.packetType);
                break;
        }
    }
    
    if (secretSubkey) {
        [secretKey addSubkey:secretSubkey];
    }
    
    // TODO: Verify key.
    
    [keyring addSecretKey:secretKey forUserId:userId];
}


+ (PacketList *)decryptPacketList:(PacketList *)packetList withKeyring:(Keyring *)keyring {
    NSMutableArray *sessionKeyPackets = [NSMutableArray array];
    SEIPDataPacket *dataPacket = nil;
    
    for (Packet *packet in packetList.packets) {
        switch (packet.packetType) {
            case PacketTypePKESKey: {
                [sessionKeyPackets addObject:packet];
                break;
            }
                
            case PacketTypeSEIPData: {
                dataPacket = (SEIPDataPacket *) packet;
                break;
            }
                
            default: {
                NSLog(@"Unsupported packet type: %lu", packet.packetType);
                break;
            }
        }
    }
    
    SecretKey *decryptionKey = nil;
    PKESKeyPacket *keyPacket = nil;
    
    for (PKESKeyPacket *packet in sessionKeyPackets) {
        decryptionKey = [keyring secretKeyForKeyId:packet.keyId];
        
        if (decryptionKey != nil) {
            keyPacket = packet;
            break;
        }
    }
    
    if (decryptionKey == nil) {
        return nil;
    }
    
    NSData *decryptedM = [Crypto decryptMessage:keyPacket.encryptedM withSecretKey:decryptionKey];
    
    const Byte *bytes = decryptedM.bytes;
    NSUInteger currentIndex = 0;
    
    if (bytes[currentIndex++] != '\0' || bytes[currentIndex++] != '\x2') {
        return nil;
    }
    
    while (bytes[currentIndex++]!= '\0' && currentIndex < decryptedM.length);
    
    SymmetricAlgorithm symmetricAlgorithm = bytes[currentIndex++];
    
//    NSUInteger checksum = [Utility readNumber:bytes + currentIndex length:2];
//    currentIndex += 2;
    
    // TODO: CHECK CHECKSUM.
    
    NSData *decryptedData = [Crypto decryptData:dataPacket.encryptedData withSymmetricKey:bytes + currentIndex];
    
    return nil;
}

+ (NSError *)errorWithCause:(NSString *)cause {
    return [NSError errorWithDomain:@"OpenPGP"
                               code:-1
                           userInfo:@{@"cause": cause}];
}

@end
