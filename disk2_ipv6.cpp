#include <pcap.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <sstream>
#include <regex>
#include <vector>

using namespace std;

bool modifyFromHeader(u_char *data, int length) {
    string payload(reinterpret_cast<const char*>(data), length);
    bool modified = false;

    // Find the From header
    size_t fromPos = payload.find("From:");

    if (fromPos != string::npos) {
        // Locate the start of the SIP URI (which follows "sip:")
        size_t sipPos = payload.find("tel:", fromPos);
        if (sipPos != string::npos) {
            // Locate the position of the phone number start (right after "sip:")
            size_t phoneStart = sipPos + 4;  // "sip:" is 4 characters

            // Locate the end of the phone number (either at '@' or any non-digit character)
            size_t phoneEnd = payload.find('>', phoneStart);
            if (phoneEnd != string::npos) {
                // Get the phone number substring
                string phoneNumber = payload.substr(phoneStart, phoneEnd - phoneStart);

                // Find the digit '7' and replace it with '2'
                size_t digitPos = phoneNumber.find('7');
                if (digitPos != string::npos) {
                    // Modify the phone number by replacing '7' with '2'
                    phoneNumber[digitPos] = '2';

                    // Replace the original phone number in the payload with the modified one
                    payload.replace(phoneStart, phoneEnd - phoneStart, phoneNumber);
                    modified = true;
                }
            }
        }
    }

    if (modified) {
        // Copy the modified payload back into the data buffer
        memcpy(data, payload.c_str(), min(length, static_cast<int>(payload.size())));
    }

    return modified;
}

void processPcapFile(const string &filename, const string &outputFilename) {
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(filename.c_str(), errbuff);
    if (pcap == nullptr) {
        cerr << "Error opening pcap file " << filename << ": " << errbuff << endl;
        return;
    }

    pcap_dumper_t *pcap_dumper = pcap_dump_open(pcap, outputFilename.c_str());
    if (pcap_dumper == nullptr) {
        cerr << "Error opening output pcap file " << outputFilename << endl;
        pcap_close(pcap);
        return;
    }

    struct pcap_pkthdr *header;
    const u_char *data;

    // Iterate through all packets in the pcap file
    while (pcap_next_ex(pcap, &header, &data) >= 0) {
        // Copy original data to modify if necessary
        u_char *modifiedData = new u_char[header->caplen];
        memcpy(modifiedData, data, header->caplen);

        // Check if it's an IPv4 packet (EtherType 0x0800)
        if (data[12] == 0x86 && data[13] == 0xDD) {
            int ipv6HeaderLength = 40;  // IPv6 header is always 40 bytes long
            int udpHeaderLength = 8;    // UDP header length
            u_char *payload = modifiedData + 14 + ipv6HeaderLength + udpHeaderLength;
            int payloadLength = header->caplen - 14 - ipv6HeaderLength - udpHeaderLength;

            // Modify only the From header
            modifyFromHeader(payload, payloadLength);
        }

        // Save the packet (whether modified or not)
        pcap_dump((u_char *)pcap_dumper, header, modifiedData);

        // Clean up memory
        delete[] modifiedData;
    }

    pcap_dump_close(pcap_dumper);
    pcap_close(pcap);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <pcap file> <output pcap file>" << endl;
        return 1;
    }

    string inputFile = argv[1];
    string outputFile = argv[2];

    cout << "Processing file: " << inputFile << endl;
    processPcapFile(inputFile, outputFile);

    cout << "Modified pcap saved to: " << outputFile << endl;

    return 0;
}
