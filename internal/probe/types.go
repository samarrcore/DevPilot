package probe

// ToolResult represents the outcome of probing a CLI tool or runtime.
type ToolResult struct {
	Name      string `json:"name"`
	Found     bool   `json:"found"`
	Version   string `json:"version"`
	RawOutput string `json:"raw_output"`
	Path      string `json:"path"`
	Error     string `json:"error,omitempty"`
}
