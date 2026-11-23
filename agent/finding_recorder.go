package agent

import (
	"context"

	"github.com/Autumn-27/artex/db"
)

// FindingRecorder is injected by the host; agents never synthesize or copy
// evidence bodies themselves. Its implementation owns the atomic write.
type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

// Tool-use guidance is appended without replacing the user's editable prompt.
// It does not require capture or claim that unavailable traffic tools exist.
const findingTrafficGuidance = "\n\n**Vulnerability Traffic Evidence (Optional)**: When calling report_finding to report a vulnerability, if you have inspected and confirmed HTTP request/response records that support the finding, you may bind their real IDs via traffic_refs in reproduction order; domain and timestamp are only for candidate filtering, not presumed correlation. For non-HTTP vulnerabilities (such as TCP), uncaptured traffic, or when there is no exact match, omit traffic_refs or pass [], keep verifiable evidence (command output, logs, etc.) in evidence, and note why traffic was not bound. Never guess IDs, and do not re-probe solely to capture packets."

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }
