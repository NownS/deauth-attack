#pragma once
#include <cstdint>
#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push,1)

struct RadiotapHdr final{
    uint8_t headerRevision_;
    uint8_t headerPad_;
    uint16_t hlen_;

    uint16_t hlen() {return hlen_;}
};
typedef RadiotapHdr *PRadiotabHdr;

struct Dot11Hdr {
    uint8_t version_:2;
    uint8_t type_:2;
    uint8_t subtype_:4;
    uint8_t flags_;
    uint16_t duration_;
    uint8_t destination_[6];
    uint8_t source_[6];
    uint8_t bssid_[6];
    uint16_t numbers;

    uint16_t duration() {return duration_;}
    Mac destination() {return Mac(destination_);}
    Mac source() {return Mac(source_);}
    Mac bssid() {return Mac(bssid_);}
};
typedef Dot11Hdr *PDot11Hdr;

struct Dot11WirelessMgntFixed {
    uint64_t timestamp_;
    uint16_t beaconInterval_;
    uint16_t capabilitiesInfo_;
};
typedef Dot11WirelessMgntFixed *PDot11WirelessMgntFixed;

struct Dot11WirelessMgntTaggedHdr {
    uint8_t eid_;
    uint8_t length_;
};
typedef Dot11WirelessMgntTaggedHdr *PDot11WirelessMgntTaggedHdr;

typedef struct _SimpleRadiotapHdr final{
    uint8_t headerRevision_ = 0;
    uint8_t headerPad_ = 0;
    uint16_t hlen_ = 12;
    uint32_t present_ = 0x00008004;
    uint8_t data_rate_= 0x02;
    uint8_t strange_data[3] = {0x00, 0x18, 0x00};

    uint16_t hlen() {return hlen_;}
} SimpleRadiotapHdr;
typedef SimpleRadiotapHdr *PSimpleRadiotabHdr;

typedef struct _DeauthDot11Hdr {
    uint8_t types_ = 0xc0;
    uint8_t flags_ = 0x00;
    uint16_t duration_ = 0x013a;
    Mac destination_ = Mac::broadcastMac();
    Mac source_;
    Mac bssid_;
    uint16_t numbers = 0x0000;
    uint16_t fixed = 0x0007;

    uint16_t duration() {return duration_;}
} DeauthDot11Hdr;
typedef DeauthDot11Hdr *PDeauthDot11Hdr;

typedef struct _AuthDot11Hdr {
    uint8_t types_ = 0xb0;
    uint8_t flags_ = 0x00;
    uint16_t duration_ = 0x013a;
    Mac destination_;
    Mac source_;
    Mac bssid_;
    uint16_t numbers = 0x0000;
    uint16_t fixed[3] = {0x0000, 0x0001, 0x0000};

    uint16_t duration() {return duration_;}
} AuthDot11Hdr;
typedef AuthDot11Hdr *PAuthDot11Hdr;

#pragma pack(pop)

