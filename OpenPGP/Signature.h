//
//  Signature.h
//  OpenPGP
//
//  Created by James Knight on 6/24/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, SignatureType) {
    SignatureTypeBinary = 0x00,
    SignatureTypeCanonicalText = 0x01,
    SignatureTypeStandalone = 0x02,
    
    SignatureTypeUserIDCertificationGeneric = 0x10,
    SignatureTypeUserIDCertificationPersona = 0x11,
    SignatureTypeUserIDCertificationCasual = 0x12,
    SignatureTypeUserIDCertificationPositive = 0x13,
    
    SignatureTypeBindingSubkey = 0x18,
    SignatureTypeBindingPrimaryKey = 0x19,
    
    SignatureTypeDirectKey = 0x1F,
    
    SignatureTypeRevocationKey = 0x20,
    SignatureTypeRevocationSubkey = 0x28,
    SignatureTypeRevocationCertification = 0x30,
    
    SignatureTypeTimestamp = 0x40,
    
    SignatureTypeThirdPartyConfirmation = 0x50
};

@interface Signature : NSObject

@end
