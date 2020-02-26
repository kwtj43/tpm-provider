// +build unit_test

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tpmprovider

// #include "tpm.h"
import "C"

import (
	"github.com/stretchr/testify/mock"
)

type MockedTpmFactory struct {
	TpmProvider *MockedTpmProvider
}

func (mockedTpmFactory MockedTpmFactory) NewTpmProvider() (TpmProvider, error) {
	return mockedTpmFactory.TpmProvider, nil
}

//-------------------------------------------------------------------------------------------------
// Mocked TpmProvider interface
//-------------------------------------------------------------------------------------------------
type MockedTpmProvider struct {
	mock.Mock
}

func (mockedTpm MockedTpmProvider) Close() {
	_ = mockedTpm.Called()
	return
}

func (mockedTpm MockedTpmProvider) Version() C.TPM_VERSION {
	args := mockedTpm.Called()
	return args.Get(0).(C.TPM_VERSION)
}

func (mockedTpm MockedTpmProvider) TakeOwnership(tpmOwnerSecretKey string) error {
	args := mockedTpm.Called(tpmOwnerSecretKey)
	return args.Error(0)
}

func (mockedTpm MockedTpmProvider) IsOwnedWithAuth(tpmOwnerSecretKey string) (bool, error) {
	args := mockedTpm.Called(tpmOwnerSecretKey)
	return args.Bool(0), args.Error(1)
}

func (mockedTpm MockedTpmProvider) CreateAik(tpmOwnerSecretKey string, aikSecretKey string) error {
	args := mockedTpm.Called(tpmOwnerSecretKey, aikSecretKey)
	return args.Error(0)
}

func (mockedTpm MockedTpmProvider) GetAikBytes(tpmOwnerSecretKey string) ([]byte, error) {
	args := mockedTpm.Called(tpmOwnerSecretKey)
	return args.Get(0).([]byte), args.Error(1)
}

func (mockedTpm MockedTpmProvider) GetAikName(tpmOwnerSecretKey string) ([]byte, error) {
	args := mockedTpm.Called(tpmOwnerSecretKey)
	return args.Get(0).([]byte), args.Error(1)
}

func (mockedTpm MockedTpmProvider) ActivateCredential(tpmOwnerSecretKey string, aikSecretKey string, credentialBytes []byte, secretBytes []byte) ([]byte, error) {
	args := mockedTpm.Called(tpmOwnerSecretKey, aikSecretKey, credentialBytes, secretBytes)
	return args.Get(0).([]byte), args.Error(1)
}

func (mockedTpm MockedTpmProvider) GetTpmQuote(aikSecretKey string, nonce []byte, pcrBanks []string, pcrs []int) ([]byte, error) {
	args := mockedTpm.Called(aikSecretKey, nonce, pcrBanks, pcrs)
	return args.Get(0).([]byte), args.Error(1)
}

func (mockedTpm MockedTpmProvider) NvIndexExists(nvIndex uint32) (bool, error) {
	args := mockedTpm.Called(nvIndex)
	return args.Bool(0), args.Error(1)
}

func (mockedTpm MockedTpmProvider) NvDefine(tpmOwnerSecretKey string, nvIndex uint32, indexSize uint16) error {
	args := mockedTpm.Called(tpmOwnerSecretKey, nvIndex, indexSize)
	return args.Error(0)
}

func (mockedTpm MockedTpmProvider) NvRelease(tpmOwnerSecretKey string, nvIndex uint32) error {
	args := mockedTpm.Called(tpmOwnerSecretKey, nvIndex)
	return args.Error(0)
}

func (mockedTpm MockedTpmProvider) NvRead(tpmOwnerSecretKey string, nvIndex uint32) ([]byte, error) {
	args := mockedTpm.Called(tpmOwnerSecretKey, nvIndex)
	return args.Get(0).([]byte), args.Error(1)
}

func (mockedTpm MockedTpmProvider) NvWrite(tpmOwnerSecretKey string, nvIndex uint32, data []byte) error {
	args := mockedTpm.Called(tpmOwnerSecretKey, nvIndex, data)
	return args.Error(0)
}

func (mockedTpm MockedTpmProvider) CreatePrimaryHandle(tpmOwnerSecretKey []byte, handle uint32) error {
	args := mockedTpm.Called(tpmOwnerSecretKey, handle)
	return args.Error(0)
}

func (mockedTpm MockedTpmProvider) CreateSigningKey(keySecret []byte, aikSecretKey []byte) (*CertifiedKey, error) {
	args := mockedTpm.Called(keySecret, aikSecretKey)
	return args.Get(0).(*CertifiedKey), args.Error(1)
}

func (mockedTpm MockedTpmProvider) CreateBindingKey(keySecret []byte, aikSecretKey []byte) (*CertifiedKey, error) {
	args := mockedTpm.Called(keySecret, aikSecretKey)
	return args.Get(0).(*CertifiedKey), args.Error(1)
}

func (mockedTpm MockedTpmProvider) Unbind(certifiedKey *CertifiedKey, keySecret []byte, encryptedData []byte) ([]byte, error) {
	args := mockedTpm.Called(certifiedKey, keySecret, encryptedData)
	return args.Get(0).([]byte), args.Error(1)
}

func (mockedTpm MockedTpmProvider) Sign(certifiedKey *CertifiedKey, keySecret []byte, hash []byte) ([]byte, error) {
	args := mockedTpm.Called(certifiedKey, keySecret, hash)
	return args.Get(0).([]byte), args.Error(1)
}

func (mockedTpm MockedTpmProvider) PublicKeyExists(handle uint32) (bool, error) {
	args := mockedTpm.Called(handle)
	return args.Bool(0), args.Error(1)
}
