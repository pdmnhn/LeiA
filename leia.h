#ifndef CAN_EFF_FLAG
#define CAN_EFF_FLAG 0x80000000UL
#endif

#ifndef LEIA_HPP
#define LEIA_HPP

#include <stdint.h>
#include <vector>
#include "aes.h"

using namespace std;

namespace leia
{
    const static uint16_t COUNTER_MAX = 0xFFFF;
    const static uint64_t EPOCH_MAX = 0xFFFFFFFFFFFFFF;
    const static uint8_t BYTES = 16;
    const static bool SUCCESS = true;
    const static bool FAILURE = false;

    static uint8_t key[BYTES], in[BYTES]; // 128-bit AES

    enum LeiACommand : uint8_t
    {
        DATA = 0b00,
        MAC_OF_DATA = 0b01,
        EPOCH = 0b10,
        MAC_OF_EPOCH = 0b11
    };

    uint32_t getExtendedCanID(uint16_t canID, uint16_t counter, LeiACommand command)
    {
        /*
        canID -> 11 bit CAN identifier
        counter -> 16 bit counter for LeiA
        command -> 2 bit command for LeiA
        Returns 32 bit uint with 29 bit extended CAN ID to be used with the MCP-2515 Library
        ORed with the CAN_EFF_FLAG flag
        */
        uint32_t exCanID = (canID << 18) | (command << 16) | counter | CAN_EFF_FLAG;
        return exCanID;
    }

    class LeiAState

    {
    private:
        uint8_t LONG_TERM_KEY[BYTES];
        uint64_t epoch;
        uint8_t sessionKey[BYTES];
        uint16_t counter;
        void generateSessionKey();
        void updateCounters();

    public:
        LeiAState(uint8_t longTermKey[]);
        vector<uint8_t> generateMAC(uint8_t data[]);
        uint16_t getCounter()
        {
            return this->counter;
        }
        bool resyncOfReceiver(uint64_t senderEpoch,
                              uint16_t senderCounter,
                              uint8_t senderMAC[]);
        vector<uint8_t> resyncOfSender();
        bool authenticate(uint8_t data[],
                          uint8_t senderMAC[]);
    };
}

#include "leia.cpp"

#endif