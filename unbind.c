/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"
#include <tss2/tss2_mu.h>

int Unbind(tpmCtx* ctx, 
            const char* keySecret, 
            size_t keySecretLength, 
            const char* publicKeyBytes, 
            size_t publicKeyBytesLength,
            const char* privateKeyBytes, 
            size_t privateKeyBytesLength,
            const char* encryptedBytes, 
            size_t encryptedBytesLength,
            char** decryptedData,
            int* decryptedDataLength)
{
    TSS2_RC                 rval;
    TPM2_HANDLE             bindingKeyHandle = 0;
    TPM2B_PRIVATE           inPrivate = {0};
    TPM2B_PUBLIC            inPublic = {0};
    TSS2L_SYS_AUTH_COMMAND  sessionData = {0};
    TPM2B_NAME              name  = {0};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TSS2L_SYS_AUTH_COMMAND  authSession = {0};
    TPM2B_PUBLIC_KEY_RSA    cipherText = {0};
    TPMT_RSA_DECRYPT        scheme = {0};
    size_t                  offset = 0;

    TPM2B_DATA label = {
        .size = sizeof("TPM2"),
        .buffer = "TPM2",
    };
    
    TPM2B_PUBLIC_KEY_RSA message = {
        .size = sizeof(((TPM2B_PUBLIC_KEY_RSA*)0)->buffer)
    };

    *decryptedDataLength = 0;

    offset = 0;
    rval = Tss2_MU_TPM2B_PUBLIC_Unmarshal(publicKeyBytes, publicKeyBytesLength, &offset, &inPublic);
    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_MU_TPM2B_PUBLIC_Unmarshal returned error code: %x", rval);
        return rval;
    }

    offset = 0;
    rval = Tss2_MU_TPM2B_PRIVATE_Unmarshal(privateKeyBytes, privateKeyBytesLength, &offset, &inPrivate);
    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_MU_TPM2B_PRIVATE_Unmarshal returned error code: %x", rval);
        return rval;
    }

    rval = Tss2_Sys_Load(ctx->sys, 
                            TPM_HANDLE_PRIMARY, 
                            &sessionData, 
                            &inPrivate,
                            &inPublic,
                            &bindingKeyHandle,
                            &name,
                            &sessionsDataOut);

    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Load returned error code: %x", rval);
        return rval;
    }

    // key password
    authSession.count = 1;
    memcpy(&authSession.auths[0].hmac, keySecret, keySecretLength);
    authSession.auths[0].hmac.size = keySecretLength;

    // encrypted data
    cipherText.size = encryptedBytesLength;
    memcpy(cipherText.buffer, encryptedBytes, encryptedBytesLength);

    scheme.scheme = TPM2_ALG_OAEP;
    scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;

    rval = Tss2_Sys_RSA_Decrypt(ctx->sys, 
                                bindingKeyHandle, 
                                &authSession, 
                                &cipherText, 
                                &scheme, 
                                &label, 
                                &message, 
                                &sessionsDataOut);

    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_RSA_Decrypt returned error code: %x", rval);
        return rval;
    }

    Tss2_Sys_FlushContext(ctx->sys, bindingKeyHandle);
    
    *decryptedData = (unsigned char*)calloc(message.size, 1);
    if (!decryptedData)
    {
        ERROR("Could not allocate decrypted buffer");
        return -1;
    }

    memcpy(*decryptedData, message.buffer, message.size);
    *decryptedDataLength = message.size;
    
    return TSS2_RC_SUCCESS;
}