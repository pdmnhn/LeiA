#include <cstring>
#include "leia.h"

using namespace leia;

void LeiAState::generateSessionKey()
{
    struct AES_ctx ctx;

    for (uint8_t i = 0; i < BYTES; i++)
    {
        in[i] = (this->epoch >> (i * 8)) & 0xFF;
    }

    AES_init_ctx(&ctx, LONG_TERM_KEY);
    AES_ECB_encrypt(&ctx, in);
    memcpy(this->sessionKey, in, BYTES);
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
    uint8_t i;

    memcpy(in, data, BYTES);

    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, in);

    vector<uint8_t> MAC(BYTES);

    memcpy(MAC.data(), in, 8);
    memcpy(MAC.data() + 8, in, 8);

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
    uint8_t senderValue[9] = {0}, receiverValue[9] = {0};

    vector<uint8_t> receiverMAC;
    uint16_t originalEpoch = this->epoch;

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
    if (memcmp(receiverValue, senderValue, 9) < 0)
    {
        this->epoch = senderEpoch;
        this->generateSessionKey();
        receiverMAC = this->generateMAC(senderValue);
        if (memcmp(senderMAC, receiverMAC.data(), BYTES))
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

    this->epoch << 16 | this->counter;
    this->updateCounters();
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
    vector<uint8_t> MAC;

    this->updateCounters();
    MAC = this->generateMAC(data);

    if (memcmp(MAC.data(), senderMAC, BYTES))
    {
        return SUCCESS;
    }

    this->epoch = originalEpoch;
    this->counter = originalCounter;

    return FAILURE;
}