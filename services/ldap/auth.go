package ldap

// Authentication states
const (
	AuthAnonymous = iota
	AuthUser
	AuthAdmin
)

type Authenticator interface {
	Authenticate(user, passwd string)
	AuthState() int
}

type Auth struct {
	users     map[string]string
	authState int
}

func NewAuth(userpw [][]string) *Auth {
	a := &Auth{
		users:     make(map[string]string),
		authState: AuthAnonymous,
	}

	for _, u := range userpw {
		a.users[u[0]] = u[1]
	}

	return a
}

// Authenticate:
func (u *Auth) Authenticate(user, passwd string) {
	pw, ok := u.users[user]
	if !ok {
		u.authState = AuthAnonymous
		return
	}

	if pw == passwd {
		if user == "admin" || user == "root" {
			u.authState = AuthAdmin
		} else {
			u.authState = AuthUser
		}
	}
}

// AuthState: return the authstate
func (u *Auth) AuthState() int {
	return u.authState
}
