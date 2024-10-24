package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	ErrPasswordNotFound = errors.New("Password not found. Probably you are usiing invalid charset or length.")
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage:")
		fmt.Println("  go run main.go <md5_hash> <length>")
		fmt.Println("  md5_cracker <md5_hash> <length>")
		return
	}

	hash := os.Args[1]
	if len(hash) != 32 {
		fmt.Println("Invalid MD5 hash length")
		return
	}

	length, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println(err)
		return
	}

	if length < 1 || length > 10 {
		fmt.Println("Invalid password length")
		return
	}

	password, err := crackMD5(hash, length)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Password found: %s\n", password)
}

func generatePasswords(ctx context.Context, length int, charset string, passwordCh chan<- string) {
	defer close(passwordCh)

	if length < 1 || length > 10 {
		return
	}

	var generate func(context.Context, string, int)
	generate = func(ctx context.Context, prefix string, remaining int) {
		if ctx.Err() != nil {
			return
		}
		if remaining == 0 {
			passwordCh <- prefix
			return
		}
		for _, c := range charset {
			generate(ctx, prefix+string(c), remaining-1)
		}
	}
	generate(ctx, "", length)
}

func md5Hash(password string) string {
	hash := md5.Sum([]byte(password))
	return hex.EncodeToString(hash[:])
}

func worker(ctx context.Context, hash string, passwordCh chan string, resultCh chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	for password := range passwordCh {
		if ctx.Err() != nil {
			return
		}

		fmt.Printf("Trying: %s\r", password)

		if md5Hash(password) == hash {
			select {
			case resultCh <- password:
			default:
			}
			return
		}
	}
}

func crackMD5(hash string, length int) (string, error) {
	passwordCh := make(chan string)
	resultCh := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	workerCount := runtime.GOMAXPROCS(0) - 1
	var wg sync.WaitGroup

	go generatePasswords(ctx, length, charset, passwordCh)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(ctx, hash, passwordCh, resultCh, &wg)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	password := <-resultCh
	if password == "" {
		return "", ErrPasswordNotFound
	}

	return password, nil
}
