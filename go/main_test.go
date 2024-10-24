package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Для решения задачи буду использовать тупой брутфорс
// Алгоритм простейший: генерю в заданной длине все возможные пароли с заданным charset'ом
// Хэширую их в md5 и сравниваю с переданным хэшом
// При первом же совпадении хлопаю в ладоши и выдаю в стандартный вывод подобранный пароль
// Это хэппи путь. В остальных случаях (сырая строка содержит символы помимо определенных,
// или передан не md5 и т.д.) то просто говорю, что пароль не найден.

// Для начала нужен генератор паролей
// Это функция, которая принимает в себя длину пароля, charset,
// канал для передачи сгенерированных вариантов и генерит
// в этот канал все возможные варианты паролей с заданным charset'ом и длиной.
// Если длина > 10 || <= 0, то просто закрываю канал
func Test_generatePasswords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		length  int
		charset string
		expect  map[string]struct{}
	}{
		{
			name:    "length is too big",
			length:  11,
			charset: "ab",
			expect:  map[string]struct{}{},
		},
		{
			name:    "length is too small",
			length:  0,
			charset: "ab",
			expect:  map[string]struct{}{},
		},
		{
			name:    "empty charset",
			length:  2,
			charset: "",
			expect:  map[string]struct{}{},
		},
		{
			name:    "happy case",
			length:  2,
			charset: "ab",
			expect: map[string]struct{}{
				"aa": {},
				"bb": {},
				"ab": {},
				"ba": {},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			result := make(map[string]struct{})
			ch := make(chan string)

			// Запуск генератора паролей в отдельной горутине
			go generatePasswords(context.Background(), tt.length, tt.charset, ch)

			// Чтение результатов из канала
			for password := range ch {
				result[password] = struct{}{}
			}

			// Сравниваем ожидаемый результат с полученным
			assert.Equal(t, tt.expect, result)
		})
	}
}

// Нужен хэшировщик паролей. На вход принимает строку и возвращает хэш строку
func Test_md5Hash(t *testing.T) {
	t.Parallel()
	var length = 1

	tests := []struct {
		name    string
		charset string
		expect  string
	}{
		{
			name:    "happy case a",
			charset: "a",
			expect:  "0cc175b9c0f1b6a831c399e269772661",
		},
		{
			name:    "happy case b",
			charset: "b",
			expect:  "92eb5ffee6ae2fec3ad71c777531578f",
		},
		{
			name:    "empty charset",
			charset: "",
			expect:  "d41d8cd98f00b204e9800998ecf8427e",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resCh := make(chan string)

			go generatePasswords(context.Background(), length, tt.charset, resCh)

			password := <-resCh
			assert.Equal(t, tt.expect, md5Hash(password))
		})
	}
}

// Нужен переборщик паролей
func Test_crackMD5(t *testing.T) {

	tests := []struct {
		name   string
		hash   string
		length int
		expect string
		err    error
	}{
		{
			name:   "password length is 0",
			hash:   "d41d8cd98f00b204e9800998ecf8427e",
			length: 0,
			expect: "",
			// Здесь, конечно, лучше выдавать сигнальную ошибку о том, что длина 0,
			// но задача не вроде бы не про это
			err: ErrPasswordNotFound,
		},
		{
			name:   "password length is 1",
			hash:   "0cc175b9c0f1b6a831c399e269772661",
			length: 1,
			expect: "a",
		},
		{
			name:   "password length is 2",
			hash:   "cc8c0a97c2dfcd73caff160b65aa39e2",
			length: 2,
			expect: "az",
		},
		{
			name:   "password has not valid symbols",
			hash:   "d1457b72c3fb323a2671125aef3eab5d",
			length: 1,
			expect: "",
			err:    ErrPasswordNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.err != nil {
				_, err := crackMD5(tt.hash, tt.length)
				assert.Equal(t, tt.err, err)
				return
			}

			password, err := crackMD5(tt.hash, tt.length)
			assert.NoError(t, err)
			assert.Equal(t, tt.expect, password)
		})
	}

}
