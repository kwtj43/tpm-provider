/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

import (
	"errors"
	"runtime"
)

//
// TODO
//
type TpmFactory interface {
	NewTpmProvider() (TpmProvider, error)
}

//
// TODO
//
func NewTpmFactory() (TpmFactory, error) {
	if runtime.GOOS == "linux" {
		return linuxTpmFactory{}, nil
	} else {
		return nil, errors.New("Unsuportted tpm factory platform " + runtime.GOOS)
	}
}