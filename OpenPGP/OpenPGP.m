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
#import "Keypair.h"
#import "LiteralDataPacket.h"
#import "OnePassSignaturePacket.h"
#import "PacketReader.h"
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
    if (message == nil || publicKeys == nil || privateKey == nil) {
        errorBlock([OpenPGP errorWithCause:@"OpenPGP decryptAndVerifyMessage: Neither message, publicKeys, nor privateKey can be nil."]);
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
    
    PacketList *decryptedPacketList =  [self decryptPacketList:packetList withKeyring:keyring];
    
    LiteralDataPacket *literalDataPacket = nil;
    SignaturePacket *signaturePacket = nil;
    
    for (Packet *packet in decryptedPacketList.packets) {
        switch (packet.packetType) {
            case PacketTypeLiteralData:
                literalDataPacket = (LiteralDataPacket *) packet;
                break;
            
            case PacketTypeSignature:
                signaturePacket = (SignaturePacket *) packet;
                break;
                
            default:
                break;
        }
    }
    
    NSString *decryptedMessage = [[NSString alloc] initWithData:literalDataPacket.literalData encoding:NSUTF8StringEncoding];
    NSString *signatureKeyId = signaturePacket.keyId;
    
    PublicKey *publicKey = [keyring publicKeyForKeyId:signatureKeyId];
    
    completionBlock(decryptedMessage, @[publicKey.userId]);
}


+ (void)signAndEncryptMessage:(NSString *)message
                   privateKey:(NSString *)privateKey
                   publicKeys:(NSArray *)publicKeys
              completionBlock:(void (^)(NSString *encryptedMessage))completionBlock
                   errorBlock:(void (^)(NSError *))errorBlock {
    
    if (message == nil || publicKeys == nil || privateKey == nil) {
        errorBlock([OpenPGP errorWithCause:@"OpenPGP signAndEncryptMessage: Neither message, publicKeys, nor privateKey can be nil."]);
        return;
    }
    
    if (publicKeys.count < 1) {
        errorBlock([OpenPGP errorWithCause:@"OpenPGP decryptAndVerifyMessage: Public keys is empty."]);
        return;
    }
    
    Keyring *keyring = [Keyring keyring];
    
    [self readSecretKeyMessage:privateKey intoKeyring:keyring];
    [self readPublicKeyMessages:publicKeys intoKeyring:keyring];
    
    LiteralDataPacket *literalDataPacket = [LiteralDataPacket packetWithText:message];
    Signature *signature = [Signature signatureForLiteralDataPacket:literalDataPacket signatureKey:keyring.secretKeys.firstObject];
    
    OnePassSignaturePacket *onePassPacket = [OnePassSignaturePacket packetWithSignature:signature];
    SignaturePacket *signaturePacket = [SignaturePacket packetWithSignature:signature];
    
    PacketList *packetList = [PacketList packetListWithPackets:@[onePassPacket, literalDataPacket, signaturePacket]];
    ASCIIArmor *armor = [ASCIIArmor armorFromPacketList:packetList type:ASCIIArmorTypeMessage];
    
    NSLog(@"Signed message:\n%@", armor.text);
    
    completionBlock(armor.text);
}


+ (void)generateKeypairWithOptions:(NSDictionary *)options
                   completionBlock:(void(^)(NSString *publicKey, NSString *privateKey))completionBlock
                        errorBlock:(void(^)(NSError *error))errorBlock {
    
    NSNumber *bits = options[@"bits"] ?: @(1024);
    NSString *userId = options[@"userId"] ?: @"James Knight <james@jknight.co>";
    
    Keypair *keypair = [Crypto generateKeypairWithBits:bits.intValue];
    
    PacketList *publicKeyPacketList = [self exportPublicKey:keypair.publicKey
                                                     userId:userId
                                               signatureKey:keypair.secretKey];
    
    PacketList *secretKeyPacketList = [self exportSecretKey:keypair.secretKey
                                                     userId:userId];
    
    ASCIIArmor *publicKeyArmor = [ASCIIArmor armorFromPacketList:publicKeyPacketList type:ASCIIArmorTypePublicKey];
    ASCIIArmor *secretKeyArmor = [ASCIIArmor armorFromPacketList:secretKeyPacketList type:ASCIIArmorTypePrivateKey];
    
    NSString *publicKeyString = publicKeyArmor.text;
    NSString *secretKeyString = secretKeyArmor.text;
    
    completionBlock(publicKeyString, secretKeyString);
}


#pragma mark - Private

+ (PacketList *)exportPublicKey:(PublicKey *)publicKey userId:(NSString *)userId signatureKey:(SecretKey *)signatureKey {
    KeyPacket *publicKeyPacket = [KeyPacket packetWithPublicKey:publicKey];
    UserIDPacket *userIdPacket = [UserIDPacket packetWithUserId:userId];
    
    Signature *signature = [Signature signatureForKeyPacket:publicKeyPacket userIdPacket:userIdPacket signatureKey:signatureKey];
    SignaturePacket *signaturePacket = [SignaturePacket packetWithSignature:signature];
    
    return [PacketList packetListWithPackets:@[publicKeyPacket, userIdPacket, signaturePacket]];
}

+ (PacketList *)exportSecretKey:(SecretKey *)secretKey userId:(NSString *)userId {
    KeyPacket *secretKeyPacket = [KeyPacket packetWithSecretKey:secretKey];
    UserIDPacket *userIdPacket = [UserIDPacket packetWithUserId:userId];
    
    Signature *signature = [Signature signatureForKeyPacket:secretKeyPacket userIdPacket:userIdPacket signatureKey:secretKey];
    SignaturePacket *signaturePacket = [SignaturePacket packetWithSignature:signature];
    
    return [PacketList packetListWithPackets:@[secretKeyPacket, userIdPacket, signaturePacket]];
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
//                lastKeyWasSubkey = YES;
                break;
                
            case PacketTypeSignature:
                if (lastKeyWasSubkey) {
                    signature = [Signature signatureForSignaturePacket:(SignaturePacket *)packet];
                    lastKeyWasSubkey = NO;
                } else {
                    subkeySignature = [Signature signatureForSignaturePacket:(SignaturePacket *)packet];
                }
                break;
                
            default:
                NSLog(@"Unsupported packet type: %lu", packet.packetType);
                break;
        }
    }
    
    if (publicKey != nil) {
        publicKey.userId = userId;
    }
    
    // TODO: Verify key signatures.
    
    if (publicSubkey) {
        [publicKey addSubkey:publicSubkey];
        publicSubkey.userId = userId;
        
        [keyring addPublicKey:publicSubkey forUserId:userId];
    }
    
    // TODO: Verify key.
    [keyring addPublicKey:publicKey forUserId:userId];
}

+ (void)readSecretKeyMessage:(NSString *)secretKeyMessage intoKeyring:(Keyring *)keyring {
    
    ASCIIArmor *armor = [ASCIIArmor armorFromText:secretKeyMessage];
    PacketList *packetList = [PacketList packetListFromData:armor.content];
    
    NSString *userId = nil;
    
    SecretKey *secretKey = nil;
    
    SecretKey *secretSubkey = nil;
    
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
                break;
                
            default:
                NSLog(@"Unsupported packet type: %lu", packet.packetType);
                break;
        }
    }
    
    if (secretKey != nil) {
        secretKey.userId = userId;
    }
    
    if (secretSubkey) {
        [secretKey addSubkey:secretSubkey];
        secretSubkey.userId = userId;
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
    
    if (symmetricAlgorithm != SymmetricAlgorithmAES256) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Unsupported symmetric algorithm."
                                     userInfo:@{@"symmetricAlgorithm": @(symmetricAlgorithm)}];
    }
    
//    NSUInteger checksum = [Utility readNumber:bytes + currentIndex length:2];
//    currentIndex += 2;
    
    // TODO: CHECK CHECKSUM.
    
    NSData *decryptedData = [Crypto decryptData:dataPacket.encryptedData withSymmetricKey:bytes + currentIndex];
    
    return [PacketList packetListFromData:decryptedData];
}

+ (NSError *)errorWithCause:(NSString *)cause {
    return [NSError errorWithDomain:@"OpenPGP"
                               code:-1
                           userInfo:@{@"cause": cause}];
}

@end
