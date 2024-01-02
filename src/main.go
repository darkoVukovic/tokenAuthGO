package main

import (
	"encoding/json"
	f "fmt"
    "os"
	"io"
	"net/http"
    "github.com/rs/cors"
    _ "github.com/go-sql-driver/mysql"
    "database/sql"
    "golang.org/x/crypto/bcrypt"
    "github.com/dgrijalva/jwt-go"
	"time"
    "github.com/joho/godotenv"

)

type Tokens struct {
    Token string
    Username string
}

type DbUser struct {
    UserId uint
    Username string
    token string
}

type User struct {
    Username string
    Password string
    UserId uint
}

type Claims struct {
    UserId uint
    Role string
    jwt.StandardClaims
}

func generateToken(UserId uint, role string) (string, error) {
    claims := Claims{
        UserId: UserId,
        Role: role,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
            IssuedAt: time.Now().Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    secretKey := []byte("test")
    tokenString, err := token.SignedString(secretKey);
    if err != nil {
        f.Println(err);
    }

    return tokenString, nil
}

func ParseToken(tokenString string) (*Claims, error) {
	// Parse the token with the secret key
    secretK := os.Getenv("SECRET_KEY");
	secretKey := []byte(secretK) 
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	// Check for errors
	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, f.Errorf("invalid token")
}


func main() {

    // TODO read from env return if fails or make backup method
    err := godotenv.Load()
    if err != nil {
        f.Println("error loading .env file", err);
        return;
    }

    mux := http.NewServeMux();
    f.Println("server running");
    db, err := sql.Open("mysql", "root:redacar@tcp(127.0.0.1)/reactchat");
	if err != nil {
		panic(err.Error());
	}


    mux.HandleFunc("/", testme);
    mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
        registerUser(w, r, db);
    })
    mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        loginUser(w, r, db)
    });
    mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
        logoutUser(w, r, db)
    });

    mux.HandleFunc("/checkToken", func(w http.ResponseWriter, r *http.Request){
        authUser(w, r, db);
    })

    c := cors.New(cors.Options{
        AllowedOrigins: []string{"http://localhost:3000"},
        AllowCredentials: true,
        AllowedMethods: []string{"POST"},
        AllowedHeaders: []string{"content-type"},
    });

    handler := c.Handler(mux);
    
    http.ListenAndServe(":10000", handler);
    

}
//spageti for now
func authUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000");
    var message string;
    cookieToken, err := r.Cookie("token");
    if err == http.ErrNoCookie {
            message = "token cookie doesnt exist";
            w.WriteHeader(http.StatusUnauthorized)
            json.NewEncoder(w).Encode(map[string]string{
                "message": message,
                "result": "false",
            })
            return;
    } else if err != nil {
         message = "error during cookie logic dont send this";
    } else {
        cookieUser, err := r.Cookie("username");
        if err == http.ErrNoCookie{
            // same for user i guess until i find better way 
            message = "username cookie  doesnt exist";
            w.WriteHeader(http.StatusUnauthorized)
            json.NewEncoder(w).Encode(map[string]string{
                "message": message,
                "result": "false",
            })
        } else if err != nil {
            f.Println("error ", err);
        } else {
            tokens := Tokens{
                Token: cookieToken.Value,
                Username: cookieUser.Value,
            }
            stmt, err := db.Prepare("SELECT a.user, a.token, b.username FROM tokens as a INNER JOIN users as b ON user_id = user WHERE username= ?");
            if err != nil {
                f.Println(err);
            }
            var dbUser DbUser;
            err = stmt.QueryRow(tokens.Username).Scan(&dbUser.UserId, &dbUser.token, &dbUser.Username);
            if err != nil {
                if err == sql.ErrNoRows { 
                //    f.Println("User not found") error for me to test
                    w.WriteHeader(http.StatusUnauthorized)
                    json.NewEncoder(w).Encode(map[string]string{
                        "message": "auth checker",
                        "result": "false",
                    })
                    return ;

                } else {
                    f.Println("Error during query:", err)
                    w.WriteHeader(http.StatusUnauthorized)
                    json.NewEncoder(w).Encode(map[string]string{
                        "message": "auth checker",
                        "result": "false",
                    })
                    return ;
                }
            }
            
            w.WriteHeader(http.StatusAccepted)
            json.NewEncoder(w).Encode(map[string]string{
                "message": "auth checker",
                "result": "true",
            })
        }
    }


}   

// TODO proper response on errors 
func logoutUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000");

    var token Tokens;

    cookies := r.Cookies()

    for _, cookie := range cookies {
        switch cookie.Name {
        case "username":
            token.Username = cookie.Value
        case "token":
            token.Token = cookie.Value
        }
      
    }
    // maybe dd salt after insert in db now tokens are same in db and cookie 
    var tableU  string = os.Getenv("TABLEU");
    var tableT  string = os.Getenv("TABLET");
    stmt, err := db.Prepare("DELETE a FROM " + tableT + " AS  a  INNER JOIN " + tableU + " AS  b ON a.user = b.user_id WHERE b.username = ? AND a.token = ?");

    if err != nil {
        f.Println(err);
    }
    defer stmt.Close();

    results, err := stmt.Exec(token.Username, token.Token);
    if err != nil {
        f.Println("err", err);
    }
    rowsAffected , err := results.RowsAffected();
    if err != nil {
        http.Error(w, "err", http.StatusInternalServerError)
        f.Println("err", err);
    }
    
    if rowsAffected > 0 {
        cookieNames := []string{"token", "username"};


        for _, cookieName := range cookieNames {
            cookie := http.Cookie{
                Name:  cookieName,
                Value:   "",
                Expires: time.Unix(0, 0),
                MaxAge: -1,
                Path:    "/",
                HttpOnly: true,
            }
            http.SetCookie(w, &cookie)
        }


        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{
            "message": "user succesfully logout",
            "result": "true",
            "token": token.Token,
        })
    }
    
}


func loginUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
    }
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000");

    var reqeuestData map[string]interface{}

    body, err := io.ReadAll(r.Body);
    if err != nil {
        http.Error(w, "invalid body request", http.StatusInternalServerError)
        return;
    }

    err = json.Unmarshal(body, &reqeuestData);
    if err != nil {
        http.Error(w, "error reading request body", http.StatusInternalServerError)
        return;
    }


    stmt, err := db.Prepare("SELECT user_id, username, password FROM users WHERE username = ?");
    if err != nil {
        f.Println(err);
    }
    var user User;
    var message string;
    err = stmt.QueryRow(reqeuestData["username"].(string)).Scan(&user.UserId, &user.Username, &user.Password);
    if err != nil {
        if err == sql.ErrNoRows {
            // log wrong credentials
            message = "username or password incorrect";
        } else {
            // log error instead print
            message = "err";
        }
    }
    if !comparePasswords(reqeuestData["password"].(string),  user.Password) {
        // log incorect password ?
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{
            "message": message,
            "result": "false",
        })
      } else {
        token, err := generateToken(user.UserId, "guest");
        if err != nil {
          f.Println(err);
        }
  
        claims, err := ParseToken(token);
        if err != nil {
          f.Println(err);
        }

  

        stmt, err := db.Prepare("INSERT INTO tokens (user, token) VALUES (?, ?) ON DUPLICATE KEY UPDATE user = VALUES(user), token=VALUES(token) ");
        if err != nil {
            f.Println(err);
        }
        _, err = stmt.Exec(claims.UserId, token)
        if err != nil {
            f.Println(err);
        }
        
        cookie := &http.Cookie{
            Name:    "token",
            Value:   token,
            Expires: time.Now().Add(time.Hour),
            Path:    "/",
            HttpOnly: true,
        }
    
        http.SetCookie(w, cookie)

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)

   
        json.NewEncoder(w).Encode(map[string]string{
            "message": "user logged successfully",
            "result": "true",
            "role": claims.Role,
            "token": token,
        })
      }

}


//TODO change name to register or make read seperate then register/login use it 
func registerUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
    }
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000");

    var requestData map[string]interface{}

    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "error reading request body", http.StatusInternalServerError)
        return;
    }
    err = json.Unmarshal(body, &requestData);
    if err != nil {
        http.Error(w, "error decoding json" , http.StatusBadRequest);
        f.Println(err);
        return
    }

    var pw string = requestData["password"].(string);

    hashedPassword, err := hashPassword(pw);
    if err != nil {
        f.Println("error during hashing");  
    }
    stmt, err := db.Prepare("INSERT INTO users (email, username, password ) VALUES (?, ?, ?)");
        if err != nil {
            f.Println(err);
        }
        
        _, err = stmt.Exec(requestData["email"], requestData["username"], hashedPassword);
				
        if err != nil {
            f.Println("error", err);
        }


    w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
        "message": "user register successfully",
        "result": "true",
    })

}



func testme(w http.ResponseWriter, r *http.Request){

}

func hashPassword (password string) (string ,error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost);
	if err != nil {
		return "err", err;
	}
	return string(hash), nil;
}


func comparePasswords(password string, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password));
	return err == nil;
}