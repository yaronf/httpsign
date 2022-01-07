package main

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

func (c Config) String() string {
	s, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		log.Fatalln("Cannot marshal config")
	}
	return string(s)
}
