//
//  OpenPGPTests.m
//  OpenPGPTests
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "ASCIIArmor.h"
#import "OpenPGP.h"

@interface OpenPGPTests : XCTestCase

@property (nonatomic, strong) NSString *message;
@property (nonatomic, strong) NSString *publicKey;
@property (nonatomic, strong) NSString *privateKey;
@property (nonatomic, strong) NSArray *publicKeys;

@end

@implementation OpenPGPTests

- (void)setUp {
    [super setUp];
    
    NSString *messagePath = [[NSBundle bundleForClass:[self class]] pathForResource:@"message" ofType:@"txt"];
    NSString *publicPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"public-key" ofType:@"gpg"];
    NSString *privatePath = [[NSBundle bundleForClass:[self class]] pathForResource:@"private-key" ofType:@"gpg"];
    NSString *publicKeyJsonPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"all-public-keys" ofType:@"json"];
    
    self.message = [NSString stringWithContentsOfFile:messagePath encoding:NSUTF8StringEncoding error:nil];
    self.publicKey = [NSString stringWithContentsOfFile:publicPath encoding:NSUTF8StringEncoding error:nil];
    self.privateKey = [NSString stringWithContentsOfFile:privatePath encoding:NSUTF8StringEncoding error:nil];
    self.publicKeys = [NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:publicKeyJsonPath] options:NSJSONReadingAllowFragments error:nil];
}

- (void)tearDown {
    [super tearDown];
}

//- (void)testReadArmor {
//    
//    ASCIIArmor *armor = [ASCIIArmor armorFromText:self.message];
//    
//    XCTAssertEqual(armor.type, ASCIIArmorTypeMessage);
//    
//    for (NSString *key in armor.headers) {
//        if ([key isEqualToString:@"Version"]) {
//            XCTAssertEqualObjects(armor.headers[key], @"OpenPGP.js v0.11.1");
//        } else if ([key isEqualToString:@"Comment"]) {
//            XCTAssertEqualObjects(armor.headers[key], @"http://openpgpjs.org");
//        } else {
//            XCTFail(@"Unknown header: %@, %@", key, armor.headers[key]);
//        }
//    }
//}
//- (void)testArmorText {
//    ASCIIArmor *keyArmor = [ASCIIArmor armorFromText:self.publicKey];
//    NSString *keyText = keyArmor.text;
//    
//    XCTAssertNotNil(keyText);
//}
//
//- (void)testWriteArmor {
//    
//    ASCIIArmor *keyArmor = [ASCIIArmor armorFromText:self.privateKey];
//    PacketList *packetList = [PacketList packetListFromData:keyArmor.content];
//    
//    ASCIIArmor *keyArmorOutput = [ASCIIArmor armorFromPacketList:packetList type:ASCIIArmorTypePrivateKey];
//    
//    NSString *asciiArmorText = keyArmorOutput.text;
//    
//    NSLog(@"Wrote armor:\n%@", asciiArmorText);
//    
//    ASCIIArmor *textArmor = [ASCIIArmor armorFromText:asciiArmorText];
//    
//    PacketList *outList = [PacketList packetListFromData:textArmor.content];
//    
//    XCTAssertEqual(packetList.packets.count, outList.packets.count);
//}
//- (void)testReadMessage {
//    ASCIIArmor *armor = [ASCIIArmor armorFromText:self.message];
//    
//    PacketList *packetList = [PacketList packetListFromData:armor.content];
//    XCTAssertNotNil(packetList, @"Failed to create packet list.");
//}
//
//- (void)testReadPublicKey {
//    ASCIIArmor *armor = [ASCIIArmor armorFromText:self.publicKey];
//    
//    PacketList *packetList = [PacketList packetListFromData:armor.content];
//    XCTAssertNotNil(packetList, @"Failed to create packet list.");
//}
//
//- (void)testReadSecretKey {
//    ASCIIArmor *armor = [ASCIIArmor armorFromText:self.privateKey];
//    
//    PacketList *packetList = [PacketList packetListFromData:armor.content];
//    XCTAssertNotNil(packetList, @"Failed to create packet list.");
//}
//
//- (void)testGenerateKey {
//    NSDictionary *options = @{
//                              
//                              };
//    [OpenPGP generateKeypairWithOptions:options completionBlock:^(NSString *publicKey, NSString *privateKey) {
//        
//        XCTAssertNotNil(publicKey);
//        XCTAssertNotNil(privateKey);
//        
//        NSLog(@"Generated publicKey:\n%@", publicKey);
//        NSLog(@"Generated privateKey:\n%@", privateKey);
//        
//    } errorBlock:^(NSError *error) {
//        XCTFail(@"Generate keys failed: %@", error);
//    }];
//}

- (void)testSignAndEncrypt {
    [OpenPGP signAndEncryptMessage:@"Hello!" privateKey:self.privateKey publicKeys:self.publicKeys completionBlock:^(NSString *encryptedMessage) {
        
    } errorBlock:^(NSError *error) {
        XCTFail(@"Decrypt and verify failed: %@", error);
    }];
}

- (void)testHumanPractice {
    [OpenPGP decryptAndVerifyMessage:self.message privateKey:self.privateKey publicKeys:self.publicKeys completionBlock:^(NSString *decryptedMessage, NSArray *verifiedUserIds) {
        NSLog(@"Successfully decrypted message: %@", decryptedMessage);
        
        if ([decryptedMessage isEqualToString:@"D"]) {
            
        }
        
    } errorBlock:^(NSError *error) {
        XCTFail(@"Decrypt and verify failed: %@", error);
    }];
}


@end
