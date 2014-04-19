package main

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

type Filter interface {
	Apply(str string) string
}

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
		filter = &ReplaceFilter{
			From: args[0],
			To:   args[1],
		}
	case "skip":
		if len(args) != 1 {
			return nil
		}
		filter = &SkipFilter{
			Char: []rune(args[0])[0],
		}
	case "substring":
		if len(args) < 1 || 2 < len(args) {
			return nil
		}
		start := 0
		length := -1
		s, err := strconv.Atoi(args[0])
		if err == nil {
			start = s
		}
		if 2 <= len(args) {
			l, err := strconv.Atoi(args[1])
			if err == nil {
				length = l
			}
		}
		filter = &SubstringFilter{
			Start:  start,
			Length: length,
		}
	}
	return filter
}

type ReplaceFilter struct {
	From string
	To   string
}

func (f *ReplaceFilter) Apply(str string) string {
	return strings.Replace(str, f.From, f.To, -1)
}

type SkipFilter struct {
	Char rune
}

func (f *SkipFilter) Apply(str string) string {
	return strings.Replace(str, string(f.Char), "", -1)
}

type SubstringFilter struct {
	Start  int
	Length int
}

func (f *SubstringFilter) Apply(str string) string {
	if 0 <= f.Length {
		end := f.Length-f.Start
		if len(str) <= end {
			end = len(str)
		}
		return str[f.Start:end]
	} else {
		return str[f.Start:]
	}
}

type Site struct {
	Name    string
	Filters []Filter
}

func showUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s SITES_FILE MASTER_PASS_FILE\n", os.Args[0])
}

func trim(str string) string {
	return strings.Trim(str, " \t\r\n")
}

func (s *Site) Password(masterPass string) string {
	str := fmt.Sprintf("%s:%s", s.Name, masterPass)
	bytePass := sha512.Sum512([]byte(str))
	pass := base64.StdEncoding.EncodeToString(bytePass[:])[0:32]
	for _, filter := range s.Filters {
		pass = filter.Apply(pass)
	}
	return pass
}

func loadSites(filename string) []*Site {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(fileContent), "\n")
	sites := []*Site{}
	latestFilters := []Filter{}
	for _, line := range lines {
		line := trim(line)
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
	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}
	return trim(string(fileContent))
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
