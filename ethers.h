/**
 * MIT License
 *
 * Copyright (c) 2017 Richard Moore <me@ricmoo.com>
 * Copyright (c) 2017 Yuet Loo Wong <contact@yuetloo.com>
 */

#ifndef __ETHERS_H__
#define __ETHERS_H__

#include <stdint.h>
#include <stdbool.h>

#define ETHERS_CHECKSUM_ADDRESS_LENGTH (43)

typedef struct {
    uint8_t *rawData;
    uint16_t rawDataLength;

    uint32_t nonce;
    uint32_t gasPrice;
    uint16_t gasPriceLow;
    uint32_t gasLimit;

    uint8_t *address;
    bool hasAddress;

    uint8_t *value;
    uint8_t valueLength;

    uint8_t *data;
    uint16_t dataLength;

    uint8_t chainId;
} Transaction;

// Function prototypes
bool ethers_decodeTransaction(Transaction* transaction, uint8_t * data, uint16_t length);
bool ethers_privateKeyToAddress(const uint8_t *privateKey, uint8_t *address);
void ethers_addressToChecksumAddress(const uint8_t *address, char *checksumAddress);
bool ethers_privateKeyToChecksumAddress(const uint8_t *privateKey, char *address);
void ethers_keccak256(const uint8_t *data, uint16_t length, uint8_t *result);
bool ethers_sign(const uint8_t *privateKey, const uint8_t *digest, uint8_t *result);
uint8_t ethers_getStringLength(uint8_t *value, uint8_t length);
uint8_t ethers_toString(uint8_t *amountWei, uint8_t amountWeiLength, uint8_t skip, char *result);

#endif 