package traffic

import (
	"context"
	"errors"
)

type UnavailableSampler struct {
	Message string
}

func (s UnavailableSampler) Sample(_ context.Context, _ int) (Counters, error) {
	message := s.Message
	if message == "" {
		message = "traffic monitor is unavailable"
	}
	return Counters{}, errors.New(message)
}
