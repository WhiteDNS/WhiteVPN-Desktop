package resolver

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"whitevpn-desktop/internal/model"
)

const defaultResolverPort = 53

type FileSummary struct {
	Count        int
	InvalidCount int
	Preview      []string
}

func ValidateText(raw string) model.ResolverTextValidation {
	normalized := make([]string, 0)
	invalid := make([]string, 0)
	seen := map[string]struct{}{}
	seenInvalid := map[string]struct{}{}

	for _, token := range resolverTextTokens(raw) {
		entry, ok := normalizeEntry(token)
		if !ok {
			if _, exists := seenInvalid[token]; !exists {
				invalid = append(invalid, token)
				seenInvalid[token] = struct{}{}
			}
			continue
		}
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		normalized = append(normalized, entry)
	}

	text := strings.Join(normalized, "\n")
	return model.ResolverTextValidation{
		NormalizedResolvers: normalized,
		InvalidEntries:      invalid,
		NormalizedText:      text,
		IsValid:             len(normalized) > 0 && len(invalid) == 0,
	}
}

func NormalizeText(raw string) string {
	return ValidateText(raw).NormalizedText
}

func NormalizeReaderToWriter(reader io.Reader, writer io.Writer, previewLimit int) (FileSummary, error) {
	seen := map[string]struct{}{}
	summary := FileSummary{}

	scanner := newLineScanner(reader)
	for scanner.Scan() {
		for _, token := range resolverLineTokens(scanner.Text()) {
			entry, ok := normalizeEntry(token)
			if !ok {
				summary.InvalidCount++
				continue
			}
			if _, exists := seen[entry]; exists {
				continue
			}
			seen[entry] = struct{}{}
			if _, err := io.WriteString(writer, entry+"\n"); err != nil {
				return summary, err
			}
			summary.Count++
			if previewLimit > 0 && len(summary.Preview) < previewLimit {
				summary.Preview = append(summary.Preview, entry)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return summary, err
	}
	return summary, nil
}

func SummarizeNormalizedReader(reader io.Reader, previewLimit int) (FileSummary, error) {
	summary := FileSummary{}
	scanner := newLineScanner(reader)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		summary.Count++
		if previewLimit > 0 && len(summary.Preview) < previewLimit {
			summary.Preview = append(summary.Preview, value)
		}
	}
	return summary, scanner.Err()
}

func resolverTextTokens(raw string) []string {
	lines := strings.Split(strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", "\n"), "\r", "\n"), "\n")
	cleanLines := make([]string, 0, len(lines))
	hasDelimitedLine := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cleanLines = append(cleanLines, line)
		if strings.ContainsAny(line, ",;") {
			hasDelimitedLine = true
		}
	}

	tokens := make([]string, 0, len(cleanLines))
	for _, line := range cleanLines {
		parts := []string{line}
		if hasDelimitedLine {
			parts = strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' })
		}
		for _, part := range parts {
			token := cleanToken(part)
			if token != "" && !strings.HasPrefix(token, "#") {
				tokens = append(tokens, token)
			}
		}
	}
	return tokens
}

func newLineScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	return scanner
}

func resolverLineTokens(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	parts := []string{line}
	if strings.ContainsAny(line, ",;") {
		parts = strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' })
	}
	tokens := make([]string, 0, len(parts))
	for _, part := range parts {
		token := cleanToken(part)
		if token != "" && !strings.HasPrefix(token, "#") {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func cleanToken(token string) string {
	return strings.Trim(strings.TrimSpace(token), `"'`)
}

func normalizeEntry(entry string) (string, bool) {
	if target, ok := normalizeTarget(entry); ok {
		return target, true
	}

	host, portText, ok := splitHostPort(entry)
	if !ok {
		return "", false
	}
	target, ok := normalizeTarget(host)
	if !ok {
		return "", false
	}
	port, ok := parsePort(portText)
	if !ok {
		return "", false
	}
	if port == defaultResolverPort {
		return target, true
	}
	if resolverTargetNeedsBrackets(target) {
		return fmt.Sprintf("[%s]:%d", target, port), true
	}
	return fmt.Sprintf("%s:%d", target, port), true
}

func splitHostPort(entry string) (string, string, bool) {
	text := strings.TrimSpace(entry)
	if strings.HasPrefix(text, "[") {
		end := strings.Index(text, "]")
		if end <= 1 {
			return "", "", false
		}
		host := strings.TrimSpace(text[1:end])
		remainder := strings.TrimSpace(text[end+1:])
		if !strings.HasPrefix(remainder, ":") {
			return "", "", false
		}
		port := strings.TrimSpace(strings.TrimPrefix(remainder, ":"))
		return host, port, host != "" && port != ""
	}

	if strings.Count(text, ":") != 1 {
		return "", "", false
	}
	idx := strings.Index(text, ":")
	host := strings.TrimSpace(text[:idx])
	port := strings.TrimSpace(text[idx+1:])
	return host, port, host != "" && port != ""
}

func normalizeTarget(target string) (string, bool) {
	text := strings.TrimSpace(target)
	if text == "" {
		return "", false
	}

	if slash := strings.Index(text, "/"); slash >= 0 {
		if slash != strings.LastIndex(text, "/") {
			return "", false
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return "", false
		}
		prefix = prefix.Masked()
		addr := prefix.Addr().Unmap()
		maxBits := 32
		if addr.Is6() {
			maxBits = 128
		}
		if maxBits-prefix.Bits() > 16 {
			return "", false
		}
		return fmt.Sprintf("%s/%d", addr.String(), prefix.Bits()), true
	}

	addr, err := netip.ParseAddr(text)
	if err != nil {
		return "", false
	}
	return addr.Unmap().String(), true
}

func parsePort(raw string) (int, bool) {
	if raw == "" {
		return 0, false
	}
	port := 0
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, false
		}
		port = port*10 + int(r-'0')
	}
	return port, port >= 1 && port <= 65535
}

func resolverTargetNeedsBrackets(target string) bool {
	return strings.Contains(strings.Split(target, "/")[0], ":")
}
