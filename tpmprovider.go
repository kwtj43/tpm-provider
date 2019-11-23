/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tpmprovider

// #include "tpm.h"
import "C"

type CertifiedKey struct {
	Version        int
	Usage          int
	PublicKey      []byte
	PrivateKey     []byte
	KeySignature   []byte
	KeyAttestation []byte
	KeyName        []byte
}

// provides go visibility to values defined in tpm.h (shared with c code)
const (
	None = C.TPM_VERSION_UNKNOWN
	V12  = C.TPM_VERSION_10 // KWT: not supported, remove
	V20  = C.TPM_VERSION_20

	NV_IDX_ENDORSEMENT_KEY = C.NV_IDX_ENDORSEMENT_KEY
	NV_IDX_ASSET_TAG       = C.NV_IDX_ASSET_TAG
	TPM_HANDLE_AIK         = C.TPM_HANDLE_AIK
	TPM_HANDLE_EK          = C.TPM_HANDLE_EK_CERT
	TPM_HANDLE_PRIMARY     = C.TPM_HANDLE_PRIMARY

	Binding = C.TPM_CERTIFIED_KEY_USAGE_BINDING
	Signing = C.TPM_CERTIFIED_KEY_USAGE_SIGNING
)

type TpmProvider interface {

	//
	// Releases the resources associated with the TpmProvider.
	//
	Close()

	//
	//
	//
	Version() C.TPM_VERSION

	//
	// TODO
	//
	TakeOwnership(tpmOwnerSecretKey string) error

	//
	// TODO
	//
	IsOwnedWithAuth(tpmOwnerSecretKey string) (bool, error)

	//
	// Used in tasks.provision_aik.go
	//
	CreateAik(tpmOwnerSecretKey string, aikSecretKey string) error

	//
	// Used in tasks.provision_aik.go to facilitate handshakes with HVS
	//
	GetAikBytes(tpmOwnerSecretKey string) ([]byte, error)

	//
	// Used in tasks.provision_aik.go to facilitate handshakes with HVS
	//
	GetAikName(tpmOwnerSecretKey string) ([]byte, error)

	//
	// ActivateCredential uses the TPM to decrypt 'secretBytes'.
	//
	// Used in tasks.provision_aik.go to decrypt HVS data.
	//
	ActivateCredential(tpmOwnerSecretKey string, aikSecretKey string, credentialBytes []byte, secretBytes []byte) ([]byte, error)

	//
	// TODO
	//
	GetTpmQuote(aikSecretKey string, nonce []byte, pcrBanks []string, pcrs []int) ([]byte, error)

	//
	// Checks to see if data has been written to nvram at 'nvIndex'
	//
	NvIndexExists(nvIndex uint32) (bool, error)

	//
	// Allocate nvram of size 'indexSize' at 'nvIndex'
	//
	NvDefine(tpmOwnerSecretKey string, nvIndex uint32, indexSize uint16) error

	//
	// Deletes data at nvram index 'nvIndex'
	//
	NvRelease(tpmOwnerSecretKey string, nvIndex uint32) error

	//
	// Reads data at nvram index 'nvIndex'
	//
	NvRead(tpmOwnerSecretKey string, nvIndex uint32) ([]byte, error)

	//
	// Writes data to nvram index 'nvIndex'
	//
	NvWrite(tpmOwnerSecretKey string, nvIndex uint32, data []byte) error

	//
	// TODO
	//
	CreatePrimaryHandle(tpmOwnerSecretKey []byte, handle uint32) error

	//
	// TODO
	//
	CreateSigningKey(keySecret []byte, aikSecretKey []byte) (*CertifiedKey, error)

	//
	// TODO
	//
	CreateBindingKey(keySecret []byte, aikSecretKey []byte) (*CertifiedKey, error)

	//
	// TODO
	//
	Unbind(certifiedKey *CertifiedKey, keySecret []byte, encryptedData []byte) ([]byte, error)

	//
	// TODO
	// HASH MUST BE 32BYTES (RSA/SHA256)
	//
	Sign(certifiedKey *CertifiedKey, keySecret []byte, hash []byte) ([]byte, error)

	//
	// TODO
	//
	PublicKeyExists(handle uint32) (bool, error)

	// Remove...?
	ReadPublic(tpmOwnerSecretKey string, handle uint32) ([]byte, error)
}
