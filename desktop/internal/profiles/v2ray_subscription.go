package profiles

import (
	"fmt"
	"strings"

	"whitevpn-desktop/internal/model"
)

func ParseV2RaySubscriptionDocument(rawText string) ([]model.V2RayProfile, error) {
	if profiles, err := ParseV2RayProfileImports(rawText); err == nil {
		return profiles, nil
	}

	decoded, err := decodeV2RayBase64(compactBase64(rawText))
	if err != nil {
		return nil, fmt.Errorf("subscription must contain V2Ray links or base64 encoded V2Ray links")
	}
	profiles, err := ParseV2RayProfileImports(string(decoded))
	if err != nil {
		return nil, fmt.Errorf("decoded subscription: %w", err)
	}
	return profiles, nil
}

func compactBase64(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, r := range value {
		if r != ' ' && r != '\n' && r != '\r' && r != '\t' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}
