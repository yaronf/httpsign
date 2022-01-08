package httpsign

import (
	"encoding/json"
	"log"
)

type Config struct {
	SignAlg     bool
	SignCreated bool
	FakeCreated int64
}

func NewConfig() Config {
	return Config{
		SignAlg:     true,
		SignCreated: true,
		FakeCreated: 0,
	}
}

func (c Config) SetSignAlg(b bool) Config {
	c.SignAlg = b
	return c
}

func (c Config) SetSignCreated(b bool) Config {
	c.SignCreated = b
	return c
}

func (c Config) SetFakeCreated(i int64) Config {
	c.FakeCreated = i
	return c
}

func (c Config) String() string {
	s, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		log.Fatal("Cannot marshal config")
	}
	return string(s)
}
