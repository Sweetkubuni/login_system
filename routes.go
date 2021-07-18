package main

import "github.com/Sweetkubuni/session/authenticate"

func (s *server) routes() {
	s.router.HandleFunc("/login", authenticate.Login(s.cache, s.db))
	s.router.HandleFunc("/signup", authenticate.Register(s.db))
	s.router.HandleFunc("/temp", authenticate.TempUser(s.cache))
	s.router.HandleFunc("/welcome", authenticate.AuthorizeWrapper(s.cache, s.welcome))
}
