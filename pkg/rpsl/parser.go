package rpsl

import (
	"bufio"
	"io"
	"strings"
)

// Object represents a parsed RPSL object
type Object struct {
	Type       string              // Object type (first attribute key)
	PrimaryKey string              // Value of primary attribute
	Attributes map[string][]string // All attributes (can be multi-value)
}

// Parser handles RPSL format parsing
type Parser struct {
	// Parser state
}

// NewParser creates a new RPSL parser
func NewParser() *Parser {
	return &Parser{}
}

// cleanUTF8 ensures a string contains only valid UTF-8 bytes
// Invalid bytes are replaced with the Unicode replacement character
func cleanUTF8(s string) string {
	// strings.ToValidUTF8 replaces invalid UTF-8 bytes with replacement rune
	// This handles mixed encodings (Latin-1, Windows-1252, etc) in WHOIS data
	return strings.ToValidUTF8(s, "�")
}

// ParseStream parses RPSL objects from a reader
// Objects are separated by blank lines
// Attributes are "key: value" format
// Continuation lines start with whitespace or '+'
func (p *Parser) ParseStream(reader io.Reader) (<-chan *Object, <-chan error) {
	objects := make(chan *Object, 1000)
	errors := make(chan error, 100)

	go func() {
		defer close(objects)
		defer close(errors)

		scanner := bufio.NewScanner(reader)
		// Increase buffer size to handle large RPSL objects (some RIPE objects > 64KB)
		const maxTokenSize = 1024 * 1024 // 1MB buffer
		buffer := make([]byte, 0, 64*1024)
		scanner.Buffer(buffer, maxTokenSize)

		currentLines := []string{}

		for scanner.Scan() {
			line := scanner.Text()

			// Blank line = end of object
			if len(strings.TrimSpace(line)) == 0 {
				if len(currentLines) > 0 {
					obj, err := p.parseObject(currentLines)
					if err != nil {
						errors <- err
					} else if obj != nil {
						objects <- obj
					}
					currentLines = []string{}
				}
				continue
			}

			// Skip comment lines
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "%") {
				continue
			}

			currentLines = append(currentLines, line)
		}

		// Handle last object if file doesn't end with blank line
		if len(currentLines) > 0 {
			obj, err := p.parseObject(currentLines)
			if err != nil {
				errors <- err
			} else if obj != nil {
				objects <- obj
			}
		}

		if err := scanner.Err(); err != nil {
			errors <- err
		}
	}()

	return objects, errors
}

func (p *Parser) parseObject(lines []string) (*Object, error) {
	if len(lines) == 0 {
		return nil, nil
	}

	obj := &Object{
		Attributes: make(map[string][]string),
	}

	var currentKey string
	var currentValue strings.Builder

	for _, line := range lines {
		// Continuation line (starts with whitespace or '+')
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t' || line[0] == '+') {
			if currentKey != "" {
				// Append to current value
				currentValue.WriteString(" ")
				currentValue.WriteString(strings.TrimSpace(line))
			}
			continue
		}

		// Save previous attribute
		if currentKey != "" {
			obj.Attributes[currentKey] = append(obj.Attributes[currentKey], cleanUTF8(currentValue.String()))
			currentValue.Reset()
		}

		// Parse new attribute
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			currentKey = strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				currentValue.WriteString(strings.TrimSpace(parts[1]))
			}

			// First attribute defines object type
			if obj.Type == "" {
				obj.Type = currentKey
				if len(parts) > 1 {
					obj.PrimaryKey = cleanUTF8(strings.TrimSpace(parts[1]))
				}
			}
		}
	}

	// Save last attribute
	if currentKey != "" {
		obj.Attributes[currentKey] = append(obj.Attributes[currentKey], cleanUTF8(currentValue.String()))
	}

	return obj, nil
}

// GetAttribute returns first value for an attribute
func (o *Object) GetAttribute(key string) string {
	if values, ok := o.Attributes[key]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

// GetAttributes returns all values for an attribute
func (o *Object) GetAttributes(key string) []string {
	if values, ok := o.Attributes[key]; ok {
		return values
	}
	return nil
}

// Has AttributeChecks if attribute exists
func (o *Object) HasAttribute(key string) bool {
	_, ok := o.Attributes[key]
	return ok
}
