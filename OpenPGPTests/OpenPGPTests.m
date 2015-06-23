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

@interface OpenPGPTests : XCTestCase

@property (nonatomic, strong) NSString *message;

@end

@implementation OpenPGPTests

- (void)setUp {
    [super setUp];
    
    NSString *messagePath = [[NSBundle bundleForClass:[self class]] pathForResource:@"message" ofType:@"txt"];
    self.message = [NSString stringWithContentsOfFile:messagePath encoding:NSUTF8StringEncoding error:nil];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testReadArmor {
    
    ASCIIArmor *armor = [ASCIIArmor armorFromText:self.message];
    
    XCTAssertEqual(armor.armorHeaderType, ASCIIArmorHeaderTypeMessage);
    
    for (NSString *key in armor.headers) {
        if ([key isEqualToString:@"Version"]) {
            XCTAssertEqualObjects(armor.headers[key], @"OpenPGP.js v0.11.1");
        } else if ([key isEqualToString:@"Comment"]) {
            XCTAssertEqualObjects(armor.headers[key], @"http://openpgpjs.org");
        } else {
            XCTFail(@"Unknown header: %@, %@", key, armor.headers[key]);
        }
    }
}

@end
