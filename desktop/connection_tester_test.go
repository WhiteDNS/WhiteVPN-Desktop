package main

import (
	"testing"

	"whitevpn-desktop/internal/model"
)

func TestConnectionTestResolversFromStatePrefersActiveResolvers(t *testing.T) {
	state := model.ResolverRuntimeState{
		ResolverDetails: []model.ResolverRuntimeDetail{
			{Resolver: "1.1.1.1", Valid: true, UploadMTU: 100, DownloadMTU: 200},
			{Resolver: "9.9.9.9", Active: true, Valid: true, UploadMTU: 120, DownloadMTU: 240},
		},
	}

	resolvers := connectionTestResolversFromState(state)
	if len(resolvers) != 2 {
		t.Fatalf("expected two resolvers, got %#v", resolvers)
	}
	if resolvers[0].Endpoint != "9.9.9.9" {
		t.Fatalf("expected active resolver first, got %#v", resolvers)
	}
}

func TestConnectionTestResolversFromStateMergesMTUDetails(t *testing.T) {
	state := model.ResolverRuntimeState{
		ResolverDetails: []model.ResolverRuntimeDetail{
			{Resolver: "1.1.1.1", Active: true, Valid: true},
			{Resolver: "1.1.1.1", Active: true, Valid: true, UploadMTU: 100, DownloadMTU: 200, UploadMTUChars: 120},
		},
	}

	resolvers := connectionTestResolversFromState(state)
	if len(resolvers) != 1 {
		t.Fatalf("expected one resolver, got %#v", resolvers)
	}
	if resolvers[0].UploadMTU != 100 || resolvers[0].DownloadMTU != 200 || resolvers[0].UploadMTUChars != 120 {
		t.Fatalf("expected merged MTU details, got %#v", resolvers[0])
	}
}
