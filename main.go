// Copyright 2015 Hajime Hoshi
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

package main

import (
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/tmc/keyring"
	"golang.org/x/term"
)

type Filter = func(str string) string

func ParseFilter(line string) Filter {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	name := fields[1]
	if !strings.HasPrefix(fields[1], "@") {
		return nil
	}
	name = name[1:]
	args := fields[2:]
	var filter Filter
	switch name {
	case "replace":
		if len(args) != 2 {
			return nil
		}
		filter = func(str string) string {
			return strings.ReplaceAll(str, args[0], args[1])
		}
	case "skip":
		if len(args) != 1 {
			return nil
		}
		filter = func(str string) string {
			return filterSkip(str, []rune(args[0]))
		}
	case "substring":
		if len(args) < 1 || 2 < len(args) {
			return nil
		}
		start := 0
		end := -1
		s, err := strconv.Atoi(args[0])
		if err == nil {
			start = s
		}
		if 2 <= len(args) {
			e, err := strconv.Atoi(args[1])
			if err == nil {
				end = e
			}
		}
		filter = func(str string) string {
			return filterSubstring(str, start, end)
		}
	case "digit":
		filter = filterDigits
	case "uppercase":
		filter = strings.ToUpper
	case "lowercase":
		filter = strings.ToLower
	}
	return filter
}

func filterDigits(str string) string {
	for i := 0; i < 20; i++ {
		str = strings.ReplaceAll(str, string(rune('a'+i)), string(rune('0'+i%10)))
		str = strings.ReplaceAll(str, string(rune('A'+i)), string(rune('0'+i%10)))
	}
	for i := 20; i < 26; i++ {
		str = strings.ReplaceAll(str, string(rune('a'+i)), "")
		str = strings.ReplaceAll(str, string(rune('A'+i)), "")
	}
	str = strings.ReplaceAll(str, "+", "")
	str = strings.ReplaceAll(str, "/", "")
	return str
}

func filterSkip(str string, chars []rune) string {
	for _, c := range chars {
		str = strings.Replace(str, string(c), "", -1)
	}
	return str
}

func filterSubstring(str string, start, end int) string {
	if 0 <= end {
		end := end
		if len(str) <= end {
			end = len(str)
		}
		return str[start:end]
	} else {
		return str[start:]
	}
}

type Site struct {
	Name    string
	Filters []Filter
}

func showUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s SITES_FILE\n       %s -set-master-password\n", os.Args[0], os.Args[0])
	flag.PrintDefaults()
}

func (s *Site) Password(masterPass string) string {
	str := fmt.Sprintf("%s:%s", s.Name, masterPass)
	bytePass := sha512.Sum512([]byte(str))
	pass := base64.StdEncoding.EncodeToString(bytePass[:])[0:32]
	for _, filter := range s.Filters {
		pass = filter(pass)
	}
	return pass
}

func loadSites(filename string) []*Site {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	fileContent, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(fileContent), "\n")
	sites := []*Site{}
	latestFilters := []Filter{}
	for _, line := range lines {
		line := strings.TrimSpace(line)
		switch {
		case line == "":
			latestFilters = []Filter{}
		case line[0] == '#':
			filter := ParseFilter(line)
			if filter != nil {
				latestFilters = append(latestFilters, filter)
			}
		default:
			site := &Site{
				Name:    line,
				Filters: latestFilters,
			}
			sites = append(sites, site)
		}
	}
	return sites
}

const (
	keyringService = "kagi"
	keyringAccount = "master"
)

func loadMasterPassword() (string, error) {
	password, err := keyring.Get(keyringService, keyringAccount)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", fmt.Errorf("master password not found; run kagi -set-master-password: %w", err)
	}
	if err != nil {
		return "", fmt.Errorf("read master password from keychain: %w", err)
	}
	return strings.TrimSpace(password), nil
}

func setMasterPassword() error {
	readPassword := func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read password from terminal: %w", err)
		}
		return strings.TrimSpace(string(password)), nil
	}
	password, err := readPassword("Master password: ")
	if err != nil {
		return err
	}
	if password == "" {
		return errors.New("master password must not be empty")
	}
	confirmation, err := readPassword("Confirm master password: ")
	if err != nil {
		return err
	}
	if password != confirmation {
		return errors.New("master passwords do not match")
	}
	if err := keyring.Set(keyringService, keyringAccount, password); err != nil {
		return fmt.Errorf("store master password in keychain: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Master password stored in the keychain.")
	return nil
}

func run() error {
	setPassword := flag.Bool("set-master-password", false, "Store the master password in the OS keychain")
	flag.Usage = showUsage
	flag.Parse()

	if *setPassword {
		if flag.NArg() != 0 {
			flag.Usage()
			return errors.New("-set-master-password does not accept arguments")
		}
		return setMasterPassword()
	}
	if flag.NArg() != 1 {
		flag.Usage()
		return errors.New("expected a sites file")
	}

	sites := loadSites(flag.Arg(0))
	masterPassword, err := loadMasterPassword()
	if err != nil {
		return err
	}
	longestSiteLen := 0
	for _, site := range sites {
		siteLen := len(site.Name)
		if longestSiteLen < siteLen {
			longestSiteLen = siteLen
		}
	}
	for _, site := range sites {
		spaceNum := longestSiteLen - len(site.Name) + 1
		spaceStr := strings.Repeat(" ", spaceNum)
		fmt.Printf("%s:%s%s\n", site.Name, spaceStr,
			site.Password(masterPassword))
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kagi:", err)
		os.Exit(1)
	}
}
