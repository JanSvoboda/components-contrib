package vault

type userPassAuthentication struct {
	loginPath string
	username  string
	password  string
}

type appRoleAuthentication struct {
	loginPath string
	roleId    string
	secretId  string
}

type certAuthentication struct {
	loginPath    string
	keystorePath string
}

type tokenAuthentication struct {
	loginPath string
	token     string
}
