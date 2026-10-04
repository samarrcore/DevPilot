package report

import (
	"encoding/json"
	"io"

	"devpilot/internal/model"
)

// RenderJSON serializes the report to structured indented JSON.
func RenderJSON(w io.Writer, r *model.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(r)
}
