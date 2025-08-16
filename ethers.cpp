/**
 * MIT License
 *
 * Copyright (c) 2017 Richard Moore <me@ricmoo.com>
 * Copyright (c) 2017 Yuet Loo Wong <contact@yuetloo.com>
 */

#include "ethers.h"
#include <string.h>
#include "keccak256.h"
#include "types.h"
#include "uECC.h"

static uint32_t readbe(uint8_t *data, uint16_t offset, uint16_t length) {
    data += offset;
    uint32_t result = 0;
    for (uint16_t i = 0; i < length; i++) {
        result <<= 8;
        result += *(data++);
    }
    return result;
}

static bool _setField(Transaction *transaction, uint8_t *data, uint16_t offset, uint16_t length, uint8_t *index) {
    switch (*index) {
        case 0: // nonce
            if (length > 4) { return false; }
            transaction->nonce = readbe(data, offset, length);
            break;

        case 1: // gasPrice
            if (length > 5) { return false; }
            if (length > 2) {
                transaction->gasPrice = readbe(data, offset, length - 2);
                transaction->gasPriceLow = readbe(data, offset + length - 2, 2);
            } else {
                transaction->gasPrice = 0;
                transaction->gasPriceLow = readbe(data, offset, length);
            }
            break;

        case 2: // gasLimit
            if (length > 4) { return false; }
            transaction->gasLimit = readbe(data, offset, length);
            break;

        case 3: // to
            if (length != 0 && length != 20) { return false; }
            transaction->address = &data[offset];
            transaction->hasAddress = (length == 20);
            break;

        case 4: // value
            if (length > 32) { return false; }
            transaction->value = &data[offset];
            transaction->valueLength = length;
            break;

        case 5: // data
            transaction->data = &data[offset];
            transaction->dataLength = length;
            break;

        case 6: // v
            if (length == 1) {
                int16_t v = (((int16_t)(data[offset])) - 35) / 2;
                if (v < 0) { v = 0; }
                transaction->chainId = v;
            } else {
                transaction->chainId = 0;
            }
            break;

        case 7:
        case 8:
            return true;

        default:
            return false;
    }

    (*index)++;
    return true;
}

bool ethers_privateKeyToAddress(const uint8_t *privateKey, uint8_t *address) {
    uint8_t publicKey[64];

    bool success = uECC_compute_public_key(privateKey, publicKey, uECC_secp256k1());
    if (!success) { return false; }

    uint8_t hashed[32];
    ethers_keccak256(publicKey, 64, hashed);

    memcpy(address, &hashed[12], 20);
    return true;
}

void ethers_keccak256(const uint8_t *data, uint16_t length, uint8_t *result) {
    SHA3_CTX context;
    keccak_init(&context);
    keccak_update(&context, (const unsigned char*)data, (size_t)length);
    keccak_final(&context, (unsigned char*)result);

    // Clear out the contents of what we hashed (in case it was secret)
    memset((char*)&context, 0, sizeof(SHA3_CTX));
}

bool ethers_sign(const uint8_t *privateKey, const uint8_t *digest, uint8_t *result) {
    // Sign the digest
    int success = uECC_sign(
        (const uint8_t*)(privateKey),
        (const uint8_t*)(digest),
        32,
        (uint8_t*)result,
        uECC_secp256k1()
    );

    return (success == 1);
} 