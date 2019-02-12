package ca

import (
	"github.com/cloudflare/cfssl/signer"
	"github.com/rkcloudchain/courier-ca/attrmgr"
	"github.com/rkcloudchain/courier-ca/config"
)

// CA represents a certificate authority which signs, issues and revokes certificates
type CA struct {
	// The home directory for the CA
	HomeDir string
	// The CA's configuration
	Config *config.CAConfig
	// The signer used for enrollment
	enrollSigner signer.Signer
	// The attribute manager
	attrMgr *attrmgr.Mgr
}
