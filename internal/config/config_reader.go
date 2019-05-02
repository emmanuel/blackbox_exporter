package config

import (
	// "errors"
	"fmt"
	"io/ioutil"
	// "net/http"
	"sync/atomic"

	// "github.com/prometheus/client_golang/prometheus"
	// "github.com/emmanuel/blackbox-exporter/internal/logging"

	yaml "gopkg.in/yaml.v2"
)

// ConfigReader atomically loads probe configurations
type ConfigReader interface {
	Config() *Config
	ReloadConfig() error
	ReloadChannel() chan<- struct{}
}

// cfgReader implements the ConfigReader interface
type reader struct {
	path          string
	config        atomic.Value
	reloadChannel chan struct{}
}

// NewFilePathConfigReader() returns a new ConfigReader with the provided path
func NewFilePathConfigReader(path string) ConfigReader {
	cfgReader := &reader{
		path:          path,
		reloadChannel: make(chan struct{}),
	}
	return cfgReader
}

// loop() polls reloadChannel and reloads the config when something is on the channel
func (this *reader) loop(stop <-chan struct{}) {
	for {
		select {
		case <-this.reloadChannel:
			this.ReloadConfig()
		case <-stop:
			break
		}
	}
}

// ReloadChannel() returns the reload channel that can be `put` onto for config reloads
func (this *reader) ReloadChannel() chan<- struct{} {
	return this.reloadChannel
}

// Config() returns the last successfully-read Config
func (this *reader) Config() *Config {
	return this.config.Load().(*Config)
}

// ReloadConfig() attempts to read and unmarshal the config file.
//   upon success, it updates the current Config
func (this *reader) ReloadConfig() error {
	newConfig := &Config{}
	yamlBytes, err := ioutil.ReadFile(this.path)
	if err != nil {
		// TODO (emmanuel): better to return no error when an existing config is available?
		if this.Config() != nil {
			return nil
		} else {
			return fmt.Errorf("Error reading config file: %s", err)
		}
	}
	if err := yaml.UnmarshalStrict(yamlBytes, newConfig); err != nil {
		return fmt.Errorf("Error parsing config file: %s", err)
	}

	this.config.Store(newConfig)
	return nil
}
