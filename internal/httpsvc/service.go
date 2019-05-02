// Copyright © 2018 Heptio
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package httpsvc provides a HTTP/1.x Service
package httpsvc

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Service is a HTTP/1.x endpoint
type Service struct {
	addr string
	port int

	*zap.Logger
	http.ServeMux
}

// Start fulfills the g.Start contract.
// When stop is closed the http server will shutdown.
func New(addr string, port int, logger *zap.Logger) Service {
	return Service{
		addr:   addr,
		port:   port,
		Logger: logger,
	}
}

// Start fulfills the g.Start contract.
// When stop is closed the http server will shutdown.
func (this *Service) Start(stop <-chan struct{}) (err error) {
	defer func() {
		if err != nil {
			this.Logger.Error("terminated with error", zap.Error(err))
		} else {
			this.Logger.Info("stopped")
		}
	}()

	s := http.Server{
		Addr:           fmt.Sprintf("%s:%d", this.addr, this.port),
		Handler:        &this.ServeMux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   5 * time.Minute, // allow for long trace requests
		MaxHeaderBytes: 1 << 11,         // 8kb should be enough for anyone
	}

	go func() {
		// wait for stop signal from group.
		<-stop

		// shutdown the server with 5 seconds grace.
		ctx := context.Background()
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		s.Shutdown(ctx)
	}()

	this.Logger.Info("started", zap.String("address", s.Addr))
	return s.ListenAndServe()
}
