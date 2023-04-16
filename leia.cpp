#include <cstring>
#include "leia.h"

using namespace leia;

void LeiAState::generateSessionKey()
{
    struct AES_ctx ctx;

    for (uint8_t i = 0; i < BYTES; i++)
    {
        this->sessionKey[i] = (this->epoch >> (i * 8)) & 0xFF;
    }

    AES_init_ctx(&ctx, LONG_TERM_KEY);
    AES_ECB_encrypt(&ctx, this->sessionKey);
}

void LeiAState::updateCounters()
{
    if (this->counter == COUNTER_MAX)
    {
        if (this->epoch == EPOCH_MAX)
        {
            this->epoch = 0;
        }
        else
        {
            this->epoch++;
        }
        this->counter = 0;
        this->generateSessionKey(); // generate session key only when the epoch changes
    }
    else
    {
        this->counter++;
    }
}

LeiAState::LeiAState(uint8_t longTermKey[])
/*
Params:
    longTermKey[] -> an array of size 16
*/
{
    memcpy(this->LONG_TERM_KEY, longTermKey, BYTES);
    this->epoch = 0;
    this->counter = 0;
    this->generateSessionKey();
}

vector<uint8_t> LeiAState::generateMAC(uint8_t data[])
/*
Params:
    data[] -> an array of size 16
*/
{
    struct AES_ctx ctx;
    vector<uint8_t> MAC(BYTES);
    memcpy(MAC.data(), data, BYTES);

    AES_init_ctx(&ctx, this->sessionKey);
    AES_ECB_encrypt(&ctx, MAC.data());

    this->updateCounters();

    return MAC;
}

bool LeiAState::resyncOfReceiver(uint64_t senderEpoch,
                                 uint16_t senderCounter,
                                 uint8_t senderMAC[])
/*
Resync on the receiver ECU
Params:
    senderMAC[] -> an array of size 16
Returns:
    true -> Resync SUCCEEDED
    false -> Resync FAILED
*/
{
    uint8_t senderValue[BYTES] = {0}, receiverValue[BYTES] = {0};

    uint64_t originalEpoch = this->epoch;

    senderValue[BYTES - 1] = senderCounter & 0xFF;
    senderValue[BYTES - 2] = (senderCounter >> 8) & 0xFF;

    receiverValue[BYTES - 1] = this->counter & 0xFF;
    receiverValue[BYTES - 2] = (this->counter >> 8) & 0xFF;

    for (uint8_t i = 0; i < 7; i++)
    {
        senderValue[BYTES - (i + 3)] = (senderEpoch >> (i * 8)) & 0xFF;
        receiverValue[BYTES - (i + 3)] = (this->epoch >> (i * 8)) & 0xFF;
    }

    // receiverValue < senderValue
    if (memcmp(receiverValue, senderValue, BYTES) < 0)
    {
        this->epoch = senderEpoch;
        this->generateSessionKey();
        vector<uint8_t> receiverMAC = this->generateMAC(senderValue);
        if (memcmp(senderMAC, receiverMAC.data(), 8) == 0)
        {
            this->counter = senderCounter;
            return SUCCESS;
        }
        else
        {
            this->epoch = originalEpoch;
        }
    }

    return FAILURE;
}

vector<uint8_t> LeiAState::resyncOfSender()
{
    uint8_t senderValue[BYTES] = {0};

    senderValue[BYTES - 1] = this->counter & 0xFF;
    senderValue[BYTES - 2] = (this->counter >> 8) & 0xFF;

    for (uint8_t i = 0; i < 7; i++)
    {
        senderValue[BYTES - (i + 3)] = (this->epoch >> (i * 8)) & 0xFF;
    }

    return this->generateMAC(senderValue);
}

bool LeiAState::authenticate(uint8_t data[],
                             uint8_t senderMAC[])
/*
Params:
    data[] -> an array of size 16
    senderMAC[] -> an array of size 16

Verify Authentication on the sender side
*/
{
    uint64_t originalEpoch = this->epoch;
    uint16_t originalCounter = this->counter;
    vector<uint8_t> MAC = this->generateMAC(data);
    memcpy(MAC.data() + 8, MAC.data(), 8);

    if (memcmp(MAC.data(), senderMAC, BYTES) == 0)
    {
        return SUCCESS;
    }

    this->epoch = originalEpoch;
    this->counter = originalCounter;

    return FAILURE;
}