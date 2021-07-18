package authenticate

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"os"
	"regexp"
	"time"

	"github.com/go-redis/redis"
	"github.com/twinj/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func comparePasswords(hashedPwd string, plainPwd []byte) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func hashAndSalt(pwd []byte) string {

	// Use GenerateFromPassword to hash & salt pwd.
	// MinCost is just an integer constant provided by the bcrypt
	// package along with DefaultCost & MaxCost.
	// The cost can be any value you want provided it isn't lower
	// than the MinCost (4)
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	// GenerateFromPassword returns a byte slice so we need to
	// convert the bytes to a string and return it
	return string(hash)
}

func InitMYSQL() *sql.DB {
	//Initializing mysql
	dsn := os.Getenv("MYSQL_DSN")
	if len(dsn) == 0 {
		dsn = "root:password1@tcp(127.0.0.1:3306)/test"
	}

	db, err := sql.Open("mysql", dsn)

	// if there is an error opening the connection, handle it
	if err != nil {
		panic(err.Error())
	}

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	return db
}

func InitREDIS() *redis.Client {
	//Initializing redis
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}

	db := redis.NewClient(&redis.Options{
		Addr:     dsn,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	_, err := db.Ping().Result()
	if err != nil {
		panic(err.Error())
	}

	return db
}

func verifyPassword(password []byte) bool {
	re1 := regexp.MustCompile(`.*[a-z]`)
	re2 := regexp.MustCompile(`.*[A-Z]`)
	re3 := regexp.MustCompile(`.*\d`)
	re4 := regexp.MustCompile(`.*[@$!%*?&]`)
	re5 := regexp.MustCompile(`[A-Za-z\d@$!%*?&]{8,}`)
	return re1.Match(password) && re2.Match(password) && re3.Match(password) && re4.Match(password) && re5.Match(password)
}

func verifyUsername(username []byte) bool {
	return len(username) > 0
}

func Register(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, err := mail.ParseAddress(r.PostFormValue("email"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		username := r.PostFormValue("username")
		if !verifyUsername([]byte(username)) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		password := r.PostFormValue("password")
		if !verifyPassword([]byte(password)) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		insertAction := `
		INSERT INTO Users (Username, Email, Password)
		VALUES (%s, %s, %s);`

		if _, err := db.Exec(fmt.Sprintf(insertAction, username, email, hashAndSalt([]byte(password)))); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, "/", http.StatusAccepted)
	}
}

func Login(cache *redis.Client, db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		username := r.PostFormValue("username")
		if len(username) == 0 {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}

		password := r.PostFormValue("password")
		if verifyPassword([]byte(password)) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}

		var hashPassword string
		var Id uint64

		if err := db.QueryRow("SELECT Password, Id  FROM Users WHERE Username=?;", username).Scan(&hashPassword, &Id); err == sql.ErrNoRows {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		//compare the user from the request, with the one we defined:
		if !comparePasswords(hashPassword, []byte(password)) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Create a new random session token
		sessionToken := uuid.NewV4().String()
		err := cache.Set(sessionToken, username, 120).Err()

		if err != nil {
			// If there is an error in setting the cache, return an internal server error
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Finally, we set the client cookie for "session_token" as the session token we just generated
		// we also set an expiry time of 120 seconds, the same as the cache
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: time.Now().Add(120 * time.Second),
		})

	}
}

func TempUser(cache *redis.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PostFormValue("username")
		if len(username) == 0 {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}

		// Create a new random session token
		sessionToken := uuid.NewV4().String()
		err := cache.Set(sessionToken, username, 120).Err()

		if err != nil {
			// If there is an error in setting the cache, return an internal server error
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Finally, we set the client cookie for "session_token" as the session token we just generated
		// we also set an expiry time of 120 seconds, the same as the cache
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: time.Now().Add(120 * time.Second),
		})
	}
}

func AuthorizeWrapper(cache *redis.Client, route func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// We can obtain the session token from the requests cookies, which come with every request
		c, err := r.Cookie("session_token")
		if err != nil {
			if err == http.ErrNoCookie {
				// If the cookie is not set, return an unauthorized status
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// For any other type of error, return a bad request status
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sessionToken := c.Value

		// We then get the name of the user from our cache, where we set the session token
		_, err = cache.Get(sessionToken).Result()

		if err == redis.Nil {
			// If the session token is not present in cache, return an unauthorized error
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else if err != nil {
			// If there is an error fetching from cache, return an internal server error status
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else {
			route(w, r)
		}
	}
}
