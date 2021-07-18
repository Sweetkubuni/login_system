package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/Sweetkubuni/session/authenticate"
	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
)

type server struct {
	cache  *redis.Client
	db     *sql.DB
	router *mux.Router
}

func newServer() *server {
	s := &server{
		cache:  authenticate.InitREDIS(),
		db:     authenticate.InitMYSQL(),
		router: mux.NewRouter(),
	}
	s.routes()
	return s
}

func (s server) welcome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome into the side!!!")
}

func main() {
	srv := newServer()
	http.ListenAndServe(":8080", srv.router)
}
