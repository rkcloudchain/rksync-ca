package config

// ServerConfig is the courier-ca server's configuration
type ServerConfig struct {
	// Listening port for the server
	Port int
	// Bind address for the server
	Address string
	// Enables  debug logging
	Debug bool
	// Sets the logging level on the server
	LogLevel string
	// CACfg is the default CA's config
	CACfg CAConfig
	// TLS for the server's listening endpoint
	TLS ServerTLSConfig
}

// ServerTLSConfig defines key material for a TLS server
type ServerTLSConfig struct {
	Enabled    bool
	CertFile   string
	KeyFile    string
	ClientAuth ClientAuth
}

// ClientAuth defines the key material needed to verify client certificates
type ClientAuth struct {
	Type      string
	CertFiles []string
}

// CAConfig is the CA instance's configuration
type CAConfig struct {
}
