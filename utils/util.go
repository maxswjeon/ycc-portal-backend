package utils

import (
	"strings"
)

type Signed interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

type Unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

type Integer interface {
	Signed | Unsigned
}

type Float interface {
	~float32 | ~float64
}

type Complex interface {
	~complex64 | ~complex128
}

type Ordered interface {
	Integer | Float | ~string
}

func Includes[T comparable](array []T, value T) bool {
	for _, v := range array {
		if v == value {
			return true
		}
	}
	return false
}

func IncludesCaseInsensitive(array []string, value string) bool {
	for _, v := range array {
		if strings.Compare(strings.TrimSpace(strings.ToLower(v)), strings.TrimSpace(strings.ToLower(value))) == 0 {
			return true
		}
	}
	return false
}

func Index[T comparable](array []T, value T) int {
	for i, v := range array {
		if v == value {
			return i
		}
	}
	return -1
}

func IndexCaseInsensitive(array []string, value string) int {
	for i, v := range array {
		if strings.Compare(strings.TrimSpace(strings.ToLower(v)), strings.TrimSpace(strings.ToLower(value))) == 0 {
			return i
		}
	}
	return -1
}

func Max[T Ordered](values ...T) T {
	max := values[0]
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	return max
}

func HeaderIndex(header []string, keys ...string) int {
	max := -1
	for _, k := range keys {
		index := IndexCaseInsensitive(header, k)
		if index > max {
			max = index
		}
	}
	return max
}
