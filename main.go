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
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
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
		str = strings.ReplaceAll(str, string('a'+i), string('0'+i%10))
		str = strings.ReplaceAll(str, string('A'+i), string('0'+i%10))
	}
	for i := 20; i < 26; i++ {
		str = strings.ReplaceAll(str, string('a'+i), "")
		str = strings.ReplaceAll(str, string('A'+i), "")
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
	fmt.Fprintf(os.Stderr, "Usage: %s SITES_FILE MASTER_PASS_FILE\n", os.Args[0])
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

func isAccessibleOnlyByOwner(filename string) bool {
	fileinfo, err := os.Stat(filename)
	if err != nil {
		panic(err)
	}
	mode := fileinfo.Mode()
	perm := mode.Perm()
	return (perm & 0077) == 0
}

func loadMasterPassword(filename string) string {
	if !isAccessibleOnlyByOwner(filename) {
		fmt.Fprintf(os.Stderr,
			"WARN: %s should be accessible only by the owner.\n",
			filename)
	}
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	fileContent, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(fileContent))
}

var sites []*Site
var masterPassword string

func init() {
	if len(os.Args) != 3 {
		showUsage()
		os.Exit(-1)
	}
	sites = loadSites(os.Args[1])
	masterPassword = loadMasterPassword(os.Args[2])
}

func main() {
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
}
