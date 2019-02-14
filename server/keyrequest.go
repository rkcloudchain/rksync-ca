package server

import (
	"github.com/rkcloudchain/courier-ca/api"
	"github.com/rkcloudchain/courier-ca/config"
)

// GetKeyRequest constructs and returns api.BasicKeyRequest object based on the bccsp
// configuration options
func GetKeyRequest(cfg *config.CAConfig) *api.BasicKeyRequest {
	if cfg.CSP.SwOpts != nil {
		return &api.BasicKeyRequest{Algo: "ecdsa", Size: cfg.CSP.SwOpts.SecLevel}
	}
	return api.NewBasicKeyRequest()
}
