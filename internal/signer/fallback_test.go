package signer

import (
	"context"
	"testing"

	"github.com/caddyserver/certmagic"
)

func Test_loadOrGenerateAndStore(t *testing.T) {
	type args struct {
		ctx        context.Context
		storage    certmagic.Storage
		keyName    string
		generator  func() privateKey
		principals []string
	}

	tempDir := t.TempDir()
	signersBytes := [][]byte{}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "RSA",
			args: args{
				ctx: context.TODO(),
				storage: &certmagic.FileStorage{
					Path: tempDir,
				},
				keyName:   rsa_host_key,
				generator: generateRSA,
			},
			wantErr: false,
		},
		{
			name: "ed25519",
			args: args{
				ctx: context.TODO(),
				storage: &certmagic.FileStorage{
					Path: tempDir,
				},
				keyName:   ed25519_host_key,
				generator: generateEd25519,
			},
			wantErr: false,
		},
		{
			name: "RSA",
			args: args{
				ctx: context.TODO(),
				storage: &certmagic.FileStorage{
					Path: tempDir,
				},
				keyName:   rsa_host_key,
				generator: generateRSA,
			},
			wantErr: false,
		},
		{
			name: "ed25519",
			args: args{
				ctx: context.TODO(),
				storage: &certmagic.FileStorage{
					Path: tempDir,
				},
				keyName:   ed25519_host_key,
				generator: generateEd25519,
			},
			wantErr: false,
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := loadOrGenerateAndStore(tt.args.ctx, tt.args.storage, tt.args.keyName, tt.args.generator, &signersBytes, tt.args.principals); (err != nil) != tt.wantErr {
				t.Errorf("loadOrGenerateAndStore() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(signersBytes) != i+1 {
				t.Errorf("len(signersBytes) != i+1; len(signersBytes) = %d , i= %d", len(signersBytes), i)
			}
		})
	}
}
