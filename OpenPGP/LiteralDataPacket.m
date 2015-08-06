//
//  LiteralDataPacket.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "LiteralDataPacket.h"
#import "Utility.h"

@interface LiteralDataPacket ()

- (instancetype)initWithDataFormat:(DataFormat)dataFormat
                          filename:(NSString *)filename
                              date:(NSUInteger)date
                       literalData:(NSData *)data;

@end

@implementation LiteralDataPacket

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    NSUInteger currentIndex = 0;
    
    DataFormat dataFormat = bytes[currentIndex++];
    
    NSUInteger filenameLength = bytes[currentIndex++];
    
    NSString *filename = (filenameLength > 0) ? [Utility readString:bytes + currentIndex maxLength:filenameLength] : nil;
    currentIndex += filenameLength;
    
    NSUInteger date = [Utility readNumber:bytes + currentIndex length:4];
    currentIndex += 4;
    
    NSRange dataRange = NSMakeRange(currentIndex, body.length - currentIndex);
    NSData *literalData = [body subdataWithRange:dataRange];
    
    return [[self alloc] initWithDataFormat:dataFormat filename:filename date:date literalData:literalData];
}

- (instancetype)initWithDataFormat:(DataFormat)dataFormat
                          filename:(NSString *)filename
                              date:(NSUInteger)date
                       literalData:(NSData *)literalData {
    self = [super initWithType:PacketTypeLiteralData];
    
    if (self != nil) {
        _dataFormat = dataFormat;
        _filename = filename;
        _date = date;
        _literalData = literalData;
    }
    
    return self;
}

- (NSString *)textData {
    if (self.dataFormat == DataFormatText || self.dataFormat == DataFormatUTF8) {
        return [[NSString alloc] initWithData:self.data encoding:NSUTF8StringEncoding];
    }
    
    return nil;
}

@end
