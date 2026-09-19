// Copyright 2026 Hajime Hoshi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main_test

import (
	"errors"
	"testing"

	"github.com/tmc/keyring"

	"github.com/hajimehoshi/kagi"
)

type passwordProvider struct {
	password string
	err      error
}

func (p *passwordProvider) Get(service, account string) (string, error) {
	if service != "kagi" || account != "master" {
		return "", keyring.ErrNotFound
	}
	return p.password, p.err
}

func (p *passwordProvider) Set(service, account, password string) error {
	return keyring.ErrNotSupported
}

func (p *passwordProvider) Delete(service, account string) error {
	return keyring.ErrNotSupported
}

func TestLoadMasterPassword(t *testing.T) {
	provider := &passwordProvider{
		password: " \tmaster password\r\n",
	}
	keyring.RegisterProvider("test", 100, provider)
	got, err := main.LoadMasterPassword()
	if err != nil {
		t.Fatal(err)
	}
	if want := "master password"; got != want {
		t.Errorf("LoadMasterPassword() = %q, want %q", got, want)
	}
}

func TestLoadMasterPasswordErrors(t *testing.T) {
	unavailable := errors.New("unavailable")
	for _, want := range []error{keyring.ErrNotFound, unavailable} {
		provider := &passwordProvider{
			err: want,
		}
		keyring.RegisterProvider("test", 100, provider)
		password, err := main.LoadMasterPassword()
		if !errors.Is(err, want) {
			t.Errorf("LoadMasterPassword() error = %v, want %v", err, want)
		}
		if password != "" {
			t.Errorf("LoadMasterPassword() returned a password on failure")
		}
	}
}
