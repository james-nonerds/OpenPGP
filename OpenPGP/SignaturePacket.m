//
//  SignaturePacket.m
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "SignaturePacket.h"
#import "MPI.h"
#import "Utility.h"

#pragma mark - SignaturePacket constants

typedef NS_ENUM(NSUInteger, SubpacketLength) {
    PacketLengthOneOctet,
    PacketLengthTwoOctet,
    PacketLengthFiveOctet
};

typedef NS_ENUM(NSUInteger, SignatureSubpacketType) {
    SignatureSubpacketReservedA = 0,
    SignatureSubpacketReservedB = 1,
    SignatureSubpacketCreationTime = 2,
    SignatureSubpacketExpirationTime = 3,
    SignatureSubpacketExportableCertification = 4,
    SignatureSubpacketTrustSignature = 5,
    SignatureSubpacketRegularExpression = 6,
    SignatureSubpacketRevocable = 7,
    SignatureSubpacketReservedC = 8,
    SignatureSubpacketKeyExpirationTime = 9,
    SignatureSubpacketPlaceholder = 10,
    SignatureSubpacketPreferredSymmetricAlgorithms = 11,
    SignatureSubpacketRevocationKey = 12,
    SignatureSubpacketReservedD = 13,
    SignatureSubpacketReservedE = 14,
    SignatureSubpacketReservedF = 15,
    SignatureSubpacketIssuer = 16,
    SignatureSubpacketReservedG = 17,
    SignatureSubpacketReservedH = 18,
    SignatureSubpacketReservedI = 19,
    SignatureSubpacketNotationData = 20,
    SignatureSubpacketPreferredHashAlgorithms = 21,
    SignatureSubpacketPreferredCompressionAlgorithms = 22,
    SignatureSubpacketKeyServerPreferences = 23,
    SignatureSubpacketPreferredKeyServer = 24,
    SignatureSubpacketPrimaryUserID = 25,
    SignatureSubpacketPolicyURI = 26,
    SignatureSubpacketKeyFlags = 27,
    SignatureSubpacketUserID = 28,
    SignatureSubpacketReasonForRevocation = 29,
    SignatureSubpacketFeatures = 30,
    SignatureSubpacketSignatureTarge = 31,
    SignatureSubpacketEmbeddedSignature = 32,
    SignatureSubpacketPrivateA = 100,
    SignatureSubpacketPrivateB = 101,
    SignatureSubpacketPrivateC = 102,
    SignatureSubpacketPrivateD = 103,
    SignatureSubpacketPrivateE = 104,
    SignatureSubpacketPrivateF = 105,
    SignatureSubpacketPrivateG = 106,
    SignatureSubpacketPrivateH = 107,
    SignatureSubpacketPrivateI = 108,
    SignatureSubpacketPrivateJ = 109,
    SignatureSubpacketPrivateK = 110
};

#define SignaturePacketVersionIndex 0

#define SignaturePacketV3HashLengthIndex 1
#define SignaturePacketV3SignatureTypeIndex 2
#define SignaturePacketV3CreationTimeIndex 3
#define SignaturePacketV3KeyIDIndex 7
#define SignaturePacketV3PKAlgorithmIndex 15
#define SignaturePacketV3HashAlgorithmIndex 16
#define SignaturePacketV3SignedHashIndex 17
#define SignaturePacketV3MPIIndex 19

#define SignaturePacketV4SignatureTypeIndex 1
#define SignaturePacketV4PKAlgorithmIndex 2
#define SignaturePacketV4HashAlgorithmIndex 3
#define SignaturePacketV4HashedSubpacketCountIndex 4

#define SignaturePacketV3HashLength 5

#pragma mark - SignaturePacket extension


@interface SignaturePacket ()

@property (nonatomic, readonly) NSData *hashData;

+ (NSUInteger)readPacketLength:(const Byte *)bytes index:(NSUInteger *)index;

- (instancetype)initV3WithSignatureType:(SignatureType)signatureType
                           creationTime:(NSUInteger)creationTime
                                  keyId:(NSString *)keyId
                        signedHashValue:(NSUInteger)signedHashValue
                             encryptedM:(MPI *)encryptedM;

- (instancetype)initV4WithSignatureType:(SignatureType)signatureType
                               hashData:(NSData *)hashData
                       hashedSubpackets:(NSData *)hashedSubpackets
                     unhashedSubpackets:(NSData *)unhashedSubpackets
                        signedHashValue:(NSUInteger)signedHashValue
                             encryptedM:(MPI *)encryptedM;

- (instancetype)initWithVersionNumber:(NSUInteger)versionNumber
                        signatureType:(SignatureType)signatureType
                      signedHashValue:(NSUInteger)signedHashValue
                           encryptedM:(MPI *)encryptedM;

- (void)readSubpackets:(NSData *)subpackets;


@end


#pragma mark - SignaturePacket implementation


@implementation SignaturePacket

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    
    NSUInteger versionNumber = bytes[SignaturePacketVersionIndex];
    
    switch (versionNumber) {
        case 3: {
            NSUInteger hashLength = bytes[SignaturePacketV3HashLengthIndex];
            
            if (hashLength != SignaturePacketV3HashLength) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Packet version not supported."
                                      userInfo:@{@"versionNumber": @(versionNumber)}];
            }
            
            SignatureType signatureType = bytes[SignaturePacketV3SignatureTypeIndex];
            NSUInteger creationTime = [Utility readNumber:bytes + SignaturePacketV3CreationTimeIndex
                                                  length:4];
            
            NSString *keyId = [Utility keyIDFromBytes:bytes + SignaturePacketV3KeyIDIndex];
            
            PublicKeyAlgorithm publicKeyAlgorithm = bytes[SignaturePacketV3PKAlgorithmIndex];
            
            if (publicKeyAlgorithm != PublicKeyAlgorithmRSAEncryptSign) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Public key algorithm not supported."
                                      userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
            }
            
            HashAlgorithm hashAlgorithm = bytes[SignaturePacketV3HashAlgorithmIndex];
            
            if (hashAlgorithm != HashAlgorithmSHA256) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Hash algorithm not supported."
                                      userInfo:@{@"hashAlgorithm": @(hashAlgorithm)}];
            }
            
            NSUInteger signedHashValue = [Utility readNumber:bytes + SignaturePacketV3SignedHashIndex
                                                      length:2];
            
            MPI *encryptedM = [MPI mpiFromBytes:(bytes + SignaturePacketV3MPIIndex)];
            
            return [[self alloc] initV3WithSignatureType:signatureType
                                            creationTime:creationTime
                                                   keyId:keyId
                                         signedHashValue:signedHashValue
                                              encryptedM:encryptedM];
        }
            
        case 4: {
            SignatureType signatureType = bytes[SignaturePacketV4SignatureTypeIndex];
            
            PublicKeyAlgorithm publicKeyAlgorithm = bytes[SignaturePacketV4PKAlgorithmIndex];
            
            if (publicKeyAlgorithm != PublicKeyAlgorithmRSAEncryptSign) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Public key algorithm not supported."
                                      userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
            }
            
            HashAlgorithm hashAlgorithm = bytes[SignaturePacketV4HashAlgorithmIndex];
            
            if (hashAlgorithm != HashAlgorithmSHA256) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Hash algorithm not supported."
                                      userInfo:@{@"hashAlgorithm": @(hashAlgorithm)}];
            }
            
            // Get hashed subpackets out:
            
            NSUInteger hashedSubpacketLength = [Utility readNumber:bytes + SignaturePacketV4HashedSubpacketCountIndex length:2];
            
            NSUInteger hashedSubpacketIndex = SignaturePacketV4HashedSubpacketCountIndex + 2;
            NSRange hashedSubpacketRange = NSMakeRange(hashedSubpacketIndex, hashedSubpacketLength);
            
            NSData *hashedSubpackets = [body subdataWithRange:hashedSubpacketRange];
            
            // Close off "hashed data":
            NSUInteger unhashedSubpacketCountIndex = hashedSubpacketIndex + hashedSubpacketLength;
            NSRange hashedRange = NSMakeRange(0, unhashedSubpacketCountIndex);
            
            NSData *hashData = [body subdataWithRange:hashedRange];
            
            // Get unhashed subpackets out:
            NSUInteger unhashedSubpacketLength = [Utility readNumber:(bytes + unhashedSubpacketCountIndex) length:2];
            NSUInteger unhashedSubpacketIndex = unhashedSubpacketCountIndex + 2;
            NSRange unhashedSubpacketRange = NSMakeRange(unhashedSubpacketIndex, unhashedSubpacketLength);
            
            NSData *unhashedSubpackets = [body subdataWithRange:unhashedSubpacketRange];
            
            // Get signed hash value:
        
            NSUInteger hashValueIndex = unhashedSubpacketIndex + unhashedSubpacketLength;
            NSUInteger signedHashValue = [Utility readNumber:(bytes + hashValueIndex) length:2];
            
            // Get MPI:
            
            MPI *encryptedM = [MPI mpiFromBytes:(bytes + hashValueIndex + 2)];
            
            return [[self alloc] initV4WithSignatureType:signatureType
                                                hashData:hashData
                                        hashedSubpackets:hashedSubpackets
                                      unhashedSubpackets:unhashedSubpackets
                                         signedHashValue:signedHashValue
                                              encryptedM:encryptedM];
        }
            
        default: {
            @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                           reason:@"Packet version not supported."
                                         userInfo:@{@"versionNumber": @(versionNumber)}];
        }
    }
    
    return nil;
}

+ (NSUInteger)readPacketLength:(const Byte *)bytes index:(NSUInteger *)index {
    
    NSUInteger currentIndex = *index;
    const Byte firstOctet = bytes[currentIndex++];
    
    if (firstOctet >= 0 && firstOctet <= 191) {
        *index = currentIndex;
        return firstOctet;
    }
    
    const Byte secondOctet = bytes[currentIndex++];
    
    if (firstOctet >= 192 && firstOctet <= 254) {
        *index = currentIndex;
        return ((firstOctet - 192) << 8) + secondOctet + 192;
    }
    
    const Byte thirdOctet = bytes[currentIndex++];
    const Byte fourthOctet = bytes[currentIndex++];
    const Byte fifthOctet = bytes[currentIndex++];
    
    *index = currentIndex;
    return (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8) | fifthOctet;
}

- (instancetype)initV3WithSignatureType:(SignatureType)signatureType
                           creationTime:(NSUInteger)creationTime
                                  keyId:(NSString *)keyId
                        signedHashValue:(NSUInteger)signedHashValue
                             encryptedM:(MPI *)encryptedM {
    
    self = [self initWithVersionNumber:3
                         signatureType:signatureType
                       signedHashValue:signedHashValue
                            encryptedM:encryptedM];
    
    if (self != nil) {
        _keyId = keyId;
        _creationTime = creationTime;
    }
    
    return self;
}

- (instancetype)initV4WithSignatureType:(SignatureType)signatureType
                               hashData:(NSData *)hashData
                       hashedSubpackets:(NSData *)hashedSubpackets
                     unhashedSubpackets:(NSData *)unhashedSubpackets
                        signedHashValue:(NSUInteger)signedHashValue
                             encryptedM:(MPI *)encryptedM {
    
    self = [self initWithVersionNumber:4
                         signatureType:signatureType
                       signedHashValue:signedHashValue
                            encryptedM:encryptedM];
    
    if (self != nil) {
        [self readSubpackets:hashedSubpackets];
        [self readSubpackets:unhashedSubpackets];
    }
    
    return self;
}

- (instancetype)initWithVersionNumber:(NSUInteger)versionNumber
                        signatureType:(SignatureType)signatureType
                      signedHashValue:(NSUInteger)signedHashValue
                           encryptedM:(MPI *)encryptedM {
    self = [super init];
    
    if (self != nil) {
        _versionNumber = versionNumber;
        _signatureType = signatureType;
        _signedHashValue = signedHashValue;
        _encryptedM = encryptedM;
    }
    
    return self;
}

- (void)readSubpackets:(NSData *)subpackets {
    const Byte *bytes = subpackets.bytes;
    NSUInteger currentIndex = 0;
    
    while (currentIndex < subpackets.length) {
        NSUInteger packetLength = [SignaturePacket readPacketLength:bytes index:&currentIndex];
        SignatureSubpacketType type = bytes[currentIndex++];
        
        const Byte *packetBytes = bytes + currentIndex;
        
        switch(type) {
            case SignatureSubpacketCreationTime: {
                _creationTime = [Utility readNumber:packetBytes length:4];
                break;
            }
                
            case SignatureSubpacketIssuer: {
                _keyId = [Utility keyIDFromBytes:packetBytes];
                
                break;
            }
                
            case SignatureSubpacketPreferredSymmetricAlgorithms: {
                NSMutableArray *array = [NSMutableArray array];
                
                for (int i = 0; i < packetLength; i++) {
                    SymmetricAlgorithm symmetricAlgorithm = packetBytes[i];
                    [array addObject:@(symmetricAlgorithm)];
                }
                
                _preferredSymmetricAlgorithms = [NSArray arrayWithArray:array];
                
                break;
            }
                
            case SignatureSubpacketPreferredHashAlgorithms: {
                
                NSMutableArray *array = [NSMutableArray array];
                
                for (int i = 0; i < packetLength; i++) {
                    HashAlgorithm hashAlgorithm = packetBytes[i];
                    [array addObject:@(hashAlgorithm)];
                }
                
                _preferredSymmetricAlgorithms = [NSArray arrayWithArray:array];
                
                break;
            }
                
            case SignatureSubpacketPreferredCompressionAlgorithms: {
                
                NSMutableArray *array = [NSMutableArray array];
                
                for (int i = 0; i < packetLength; i++) {
                    CompressionAlgorithm compressionAlgorithm = packetBytes[i];
                    [array addObject:@(compressionAlgorithm)];
                }
                
                _preferredSymmetricAlgorithms = [NSArray arrayWithArray:array];
                
                break;
            }
                
            case SignatureSubpacketUserID: {
                char userID[packetLength];
                strcpy(userID, (const char *) packetBytes);
                
                _userId = [NSString stringWithCString:userID encoding:NSUTF8StringEncoding];
                
                break;
            }
                
            case SignatureSubpacketKeyFlags: {
                NSMutableArray *array = [NSMutableArray array];
                
                for (int i = 0; i < packetLength; i++) {
                    NSUInteger flag = packetBytes[i];
                    [array addObject:@(flag)];
                }
                
                _keyFlags= [NSArray arrayWithArray:array];
            }
                
            case SignatureSubpacketFeatures: {
                NSMutableArray *array = [NSMutableArray array];
                
                for (int i = 0; i < packetLength; i++) {
                    NSUInteger flag = packetBytes[i];
                    [array addObject:@(flag)];
                }
                
                _features = [NSArray arrayWithArray:array];
            }
                
            default:
                break;
        }
        
        currentIndex += packetLength - 1;
    }
}

- (Signature *)signature {
    return nil;
}

@end




