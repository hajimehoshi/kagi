package main

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func showUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s SITES_FILE MASTER_PASS_FILE\n", os.Args[0])
}

func trim(str string) string {
	return strings.Trim(str, " \t\n")	
}

func createPassword(site, masterPass string) string {
	str := fmt.Sprintf("%s:%s", site, masterPass)
	bytePass := sha512.Sum512([]byte(str))
	return base64.StdEncoding.EncodeToString(bytePass[:])[0:32]
}

func loadSites(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}
	provisionalSites := strings.Split(string(fileContent), "\n")
	sites := []string{}
	for _, site := range provisionalSites {
		site := trim(site)
		if site != "" && site[0] != '#' {
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

var sites []string
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
		siteLen := len(site)
		if longestSiteLen < siteLen {
			longestSiteLen = siteLen
		}
	}
	for _, site := range sites {
		spaceNum := longestSiteLen - len(site) + 1
		spaceStr := strings.Repeat(" ", spaceNum)
		fmt.Printf("%s:%s%s\n", site, spaceStr,
			createPassword(site, masterPassword))
	}
}
