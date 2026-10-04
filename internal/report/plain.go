package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"devpilot/internal/model"
)

// RenderPlain prints a clean, human-readable preflight report to w.
// Blockers (Grounded) are listed first, followed by Caution, then Clear.
func RenderPlain(w io.Writer, r *model.Report) error {
	fmt.Fprintln(w, "✈  DevPilot Preflight Inspection Report")
	fmt.Fprintf(w, "   Target: %s\n", r.TargetDir)
	fmt.Fprintf(w, "   Time:   %s\n", r.Timestamp.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintln(w, strings.Repeat("-", 60))

	// Sort findings: Grounded first, then Caution, then Clear
	sorted := make([]model.Finding, len(r.Findings))
	copy(sorted, r.Findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityWeight(sorted[i].Severity) < severityWeight(sorted[j].Severity)
	})

	for _, f := range sorted {
		badge := badgeFor(f.Severity)
		fmt.Fprintf(w, "\n[%s] %s (%s)\n", badge, f.Title, f.ID)

		if len(f.Evidence) > 0 {
			fmt.Fprintln(w, "  Evidence:")
			for _, ev := range f.Evidence {
				fmt.Fprintf(w, "    • %s: %s (source: %s)\n", ev.Key, ev.Value, ev.Source)
			}
		}

		if f.Fix != nil {
			fmt.Fprintf(w, "  Fix:       %s\n", f.Fix.Title)
			fmt.Fprintf(w, "    Action:  %s", f.Fix.ActionType)
			if len(f.Fix.Params) > 0 {
				var paramStrs []string
				for k, v := range f.Fix.Params {
					paramStrs = append(paramStrs, fmt.Sprintf("%s=%s", k, v))
				}
				sort.Strings(paramStrs)
				fmt.Fprintf(w, " [%s]", strings.Join(paramStrs, ", "))
			}
			fmt.Fprintln(w)
			if f.Fix.Explanation != "" {
				fmt.Fprintf(w, "    Note:    %s\n", f.Fix.Explanation)
			}
		}

		if f.Risk != "" {
			fmt.Fprintf(w, "  Risk:      %s\n", strings.ToUpper(string(f.Risk)))
		}

		if f.Verify != "" {
			fmt.Fprintf(w, "  Verify:    %s\n", f.Verify)
		}
	}

	fmt.Fprintln(w, "\n"+strings.Repeat("-", 60))
	statusSummary := "FLIGHT READY"
	if r.Summary.Grounded > 0 {
		statusSummary = "GROUNDED - Blockers detected"
	} else if r.Summary.Caution > 0 {
		statusSummary = "CAUTION - Advisory warnings detected"
	}

	fmt.Fprintf(w, "Status: %s\n", statusSummary)
	fmt.Fprintf(w, "Summary: %d Total | %d Grounded | %d Caution | %d Clear\n",
		r.Summary.Total, r.Summary.Grounded, r.Summary.Caution, r.Summary.Clear)

	return nil
}

func severityWeight(s model.Severity) int {
	switch s {
	case model.SeverityGrounded:
		return 0 // highest priority
	case model.SeverityCaution:
		return 1
	case model.SeverityClear:
		return 2
	default:
		return 3
	}
}

func badgeFor(s model.Severity) string {
	switch s {
	case model.SeverityGrounded:
		return "GROUNDED"
	case model.SeverityCaution:
		return "CAUTION"
	case model.SeverityClear:
		return "CLEAR"
	default:
		return string(s)
	}
}
