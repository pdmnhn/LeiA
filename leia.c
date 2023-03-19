#include <stdint.h>
#include "aes.h"
#define COUNTER_MAX 0xFFFF
#define EPOCH_MAX 0xFFFFFFFFFFFFFF
#define BYTES 16
#define SUCCESS 1
#define FAILURE 0

static uint8_t key[BYTES], in[BYTES]; // 128-bit AES

struct LeiAState
{
    __uint128_t LONG_TERM_KEY;
    uint64_t epoch;
    __uint128_t sessionKey;
    uint16_t counter;
};

void initLeiAState(struct LeiAState *state, __uint128_t key)
{
    state->LONG_TERM_KEY = key;
    state->epoch = 0;
    state->counter = 0;
}

void generateSessionKey(struct LeiAState *state)
{
    struct AES_ctx ctx;
    uint8_t i;

    for (i = 0; i < BYTES; ++i)
    {
        key[i] = (state->LONG_TERM_KEY >> (i * 8)) & 0xFF;
        in[i] = (state->epoch >> (i * 8)) & 0xFF;
    }

    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, in);
    state->sessionKey = 0;

    for (i = 0; i < BYTES; ++i)
    {
        state->sessionKey = state->sessionKey | in[i] << (i * 8);
    }
}

void updateCounters(struct LeiAState *state)
{
    if (state->counter == COUNTER_MAX)
    {
        if (state->epoch == EPOCH_MAX)
        {
            state->epoch = 0;
        }
        else
        {
            ++state->epoch;
        }
        state->counter = 0;
    }
    else
    {
        ++state->counter;
    }
    generateSessionKey(state);
}

__uint128_t generateMAC(struct LeiAState *state, __uint128_t data)
{

    struct AES_ctx ctx;
    uint8_t i;
    __uint128_t MAC = 0;

    updateCounters(state);

    for (i = 0; i < BYTES; ++i)
    {
        key[i] = (state->sessionKey >> (i * 8)) & 0xFF;
    }

    for (i = 0; i < BYTES; ++i)
    {
        in[i] = (data >> (i * 8)) & 0xFF;
    }

    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, in);

    for (i = 0; i < BYTES; ++i)
    {
        MAC = MAC | in[i] << (i * 8);
    }

    return MAC;
}

/*
Resync on the receiver ECU

Returns:
    1 -> Resync SUCCEEDED
    0 -> Resync FAILED
*/

uint8_t resyncOfReceiver(struct LeiAState *state,
                         uint64_t senderEpoch,
                         uint16_t senderCounter,
                         __uint128_t senderMAC)
{
    __uint128_t senderValue, receiverValue, receiverMAC;
    uint16_t originalEpoch = state->epoch;

    senderValue = senderEpoch << 16 | senderCounter;
    receiverValue = state->epoch << 16 | state->counter;

    if (senderValue > receiverValue)
    {
        state->epoch = senderEpoch;
        generateSessionKey(state);
        receiverMAC = generateMAC(state, senderValue);
        if (senderMAC == receiverMAC)
        {
            state->counter = senderCounter;
            return SUCCESS;
        }
        else
        {
            state->epoch = originalEpoch;
        }
    }

    return FAILURE;
}

__uint128_t resyncOfSender(struct LeiAState *state)
{
    __uint128_t senderValue = state->epoch << 16 | state->counter;
    updateCounters(state);
    return generateMAC(state, senderValue);
}

/*
Verify Authentication on the sender side
*/

uint8_t authenticate(struct LeiAState *state,
                     __uint128_t data,
                     __uint128_t senderMAC)
{
    uint64_t originalEpoch = state->epoch;
    uint16_t originalCounter = state->counter;
    __uint128_t MAC;

    updateCounters(state);
    MAC = generateMAC(state, data);

    if (MAC == senderMAC)
    {
        return SUCCESS;
    }

    state->epoch = originalEpoch;
    state->counter = originalCounter;

    return FAILURE;
}