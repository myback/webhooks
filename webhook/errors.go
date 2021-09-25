package webhook

import "errors"

var (
	ErrEventNotSpecifiedToParse = errors.New("no Event specified to parse")
	ErrInvalidHTTPMethod        = errors.New("invalid HTTP Method")
	ErrMissingEventKeyHeader    = errors.New("missing Event Header")
	ErrTokenEmpty               = errors.New("token is empty")
	ErrEventNotFound            = errors.New("event not defined to be parsed")
	ErrHMACVerificationFailed   = errors.New("HMAC verification failed")
	ErrUUIDVerificationFailed   = errors.New("UUID verification failed")
)
