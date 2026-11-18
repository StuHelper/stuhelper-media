package media

import (
	"github.com/gabriel-vasile/mimetype"
	"mime"
	"net/http"
)

// These text formats have no distinguishing signature.
func noteFormat(typ string) bool {
	return typ == "text/markdown" || typ == "application/x-tex" || typ == "text/x-tex"
}

func supportedType(typ string) bool {
	return noteFormat(typ) || mimetype.Lookup(typ) != nil || typ == "application/vnd.rar" || typ == "application/x-gzip"
}

func matchesContentType(prefix []byte, typ string) bool {
	sniffed, _, _ := mime.ParseMediaType(http.DetectContentType(prefix))
	if sniffed == typ {
		return true
	}
	detected := mimetype.Detect(prefix)
	if noteFormat(typ) {
		return sniffed == "text/plain" && detected.Is("text/plain")
	}
	return detected.Is(typ)
}
