package export

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/Lorikeet-Security/lory-cli/pkg/types"
)

// GeneratePDFEvidence produces a valid binary PDF 1.4 document containing
// compliance and vulnerability evidence for the given findings and organization.
func GeneratePDFEvidence(findings []types.VulnerabilityFinding, orgName string) []byte {
	text := GenerateSOC2Evidence(findings, orgName)
	return GeneratePDF(text)
}

// GeneratePDF produces a valid binary PDF 1.4 document from arbitrary text.
func GeneratePDF(text string) []byte {
	lines := wrapText(text, 80)
	pages := paginateLines(lines, 45)

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	numPages := len(pages)
	if numPages == 0 {
		numPages = 1
		pages = [][]string{{""}}
	}

	// Calculate object indices
	// 1: Catalog
	// 2: Pages
	// 3: Font F1 (Helvetica)
	// 4: Font F2 (Helvetica-Bold)
	// 5 + 2*i: Page i
	// 6 + 2*i: Content i
	totalObjects := 4 + 2*numPages
	offsets := make([]int, totalObjects+1)

	// Helper to write an object and record its offset
	writeObj := func(objNum int, content string) {
		offsets[objNum] = buf.Len()
		buf.WriteString(fmt.Sprintf("%d 0 obj\n%s\nendobj\n", objNum, content))
	}

	// Obj 1: Catalog
	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")

	// Obj 2: Pages
	var kids strings.Builder
	for i := 0; i < numPages; i++ {
		if i > 0 {
			kids.WriteString(" ")
		}
		kids.WriteString(fmt.Sprintf("%d 0 R", 5+2*i))
	}
	writeObj(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), numPages))

	// Obj 3: Font F1
	writeObj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")

	// Obj 4: Font F2
	writeObj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")

	// Pages and Content Streams
	for i, pageLines := range pages {
		pageObjNum := 5 + 2*i
		contentObjNum := 6 + 2*i

		// Page object
		pageDict := fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>", contentObjNum)
		writeObj(pageObjNum, pageDict)

		// Content stream
		var stream bytes.Buffer
		stream.WriteString("BT\n/F1 10 Tf\n14 TL\n50 742 Td\n")
		for _, line := range pageLines {
			escaped := escapePDFString(line)
			stream.WriteString(fmt.Sprintf("(%s) Tj T*\n", escaped))
		}
		stream.WriteString("ET\n")

		streamBytes := stream.Bytes()
		contentDictAndStream := fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(streamBytes), string(streamBytes))
		writeObj(contentObjNum, contentDictAndStream)
	}

	// Cross-reference table
	xrefOffset := buf.Len()
	buf.WriteString(fmt.Sprintf("xref\n0 %d\n", totalObjects+1))
	buf.WriteString("0000000000 65535 f \r\n")
	for i := 1; i <= totalObjects; i++ {
		buf.WriteString(fmt.Sprintf("%010d 00000 n \r\n", offsets[i]))
	}

	// Trailer
	buf.WriteString(fmt.Sprintf("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", totalObjects+1, xrefOffset))

	return buf.Bytes()
}

func escapePDFString(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch b {
		case '\\':
			sb.WriteString("\\\\")
		case '(':
			sb.WriteString("\\(")
		case ')':
			sb.WriteString("\\)")
		default:
			if b >= 32 && b <= 126 {
				sb.WriteByte(b)
			} else if b == '\t' {
				sb.WriteString("    ")
			} else {
				sb.WriteByte(' ')
			}
		}
	}
	return sb.String()
}

func wrapText(text string, maxCols int) []string {
	if maxCols <= 0 {
		maxCols = 80
	}
	rawLines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var result []string

	for _, line := range rawLines {
		line = strings.ReplaceAll(line, "\t", "    ")
		if len(line) <= maxCols {
			result = append(result, line)
			continue
		}

		words := strings.Fields(line)
		if len(words) == 0 {
			result = append(result, "")
			continue
		}

		var curLine strings.Builder
		for _, word := range words {
			for len(word) > maxCols {
				if curLine.Len() > 0 {
					result = append(result, curLine.String())
					curLine.Reset()
				}
				result = append(result, word[:maxCols])
				word = word[maxCols:]
			}

			if curLine.Len() == 0 {
				curLine.WriteString(word)
			} else if curLine.Len()+1+len(word) <= maxCols {
				curLine.WriteByte(' ')
				curLine.WriteString(word)
			} else {
				result = append(result, curLine.String())
				curLine.Reset()
				curLine.WriteString(word)
			}
		}
		if curLine.Len() > 0 {
			result = append(result, curLine.String())
		}
	}
	return result
}

func paginateLines(lines []string, linesPerPage int) [][]string {
	if linesPerPage <= 0 {
		linesPerPage = 45
	}
	if len(lines) == 0 {
		return [][]string{{""}}
	}

	var pages [][]string
	for i := 0; i < len(lines); i += linesPerPage {
		end := i + linesPerPage
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, lines[i:end])
	}
	return pages
}
