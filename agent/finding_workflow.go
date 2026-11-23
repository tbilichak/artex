package agent

import (
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const findingIDGuidance = "\n\n**Finding ID Convention**: finding_id is the standalone vulnerability record ID; finding_node_id is the exploration node ID. The id returned by list_findings / list_task_findings / node_detail / get_task_node_detail remains the exploration node ID—read the standalone ID from finding_id in the same response. get_finding_traffic / bind_finding_traffic use the standalone finding_id. The legacy update_finding_report tool still expects finding_node_id in its finding_id parameter. Do not pass the number from the first line of report_finding to evidence tools, and do not guess other numbers when encountering an ID error."

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		return out, ""
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\nBy default, the Reporter agent verifies and binds traffic before writing the report. The reporter should keep verification commands, key outputs, and any existing real traffic IDs with their roles in evidence so the Reporter agent can verify against execution traces; no extra packet lookup is needed just for binding. Explicit immediate binding is still supported: traffic_refs or evidence_hint_id may submit verified references (the latter reads structured references from a specified hint in this task); if any reference is invalid, the entire report fails. TCP / packetless findings do not need these optional parameters. Returns finding_id and finding_node_id for the standalone record and exploration node, respectively."
		case "add_hint", "add_task_hint":
			note = "\nWhen handing off a confirmed vulnerability, preserve the verified traffic IDs, roles, notes, and order in traffic_refs of the corresponding hint (top-level for a single hint, or inside each hints element for batches), and state in text which specific vulnerability it proves. Callers must not hand off text alone while dropping existing traffic references. Unverified candidates must not be passed as evidence."
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**Traffic Evidence Handoff (Optional)**: Automatic binding is handled by default by the Reporter agent after the finding is persisted and before writing the report. Reporters should keep verification commands, key outputs, and any existing real traffic IDs with their roles in evidence (and pass intent_id in tasks) so the Reporter agent can trace them; no extra packet lookups are needed solely for binding. When Auto / Planner reports on behalf of an executor, do not drop the executor's existing references. add_hint / add_task_hint can hand off via traffic_refs; explicit immediate binding via traffic_refs / evidence_hint_id on report_finding remains supported. Register TCP or packetless findings normally—never guess IDs, and never re-probe solely to capture packets."
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\nWhen platform chat has no task context, do not call report_finding directly; hand off to the corresponding existing task via add_task_hint so the task agent registers it, and verify the result with list_task_findings."
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\nBefore marking a goal complete, finish reporting/handing off any already-collected evidence. Do not end the task or cancel Workers merely because a text finding was registered while evidence handoff is still incomplete; packetless findings do not require waiting or forced packet capture."
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**Pre-Report Automatic Traffic Binding (Enabled)**: You are responsible for verifying and binding traffic for the triggered vulnerability before writing the report. First obtain the exact finding_id and finding_node_id from the report_finding return JSON or get_task_node_detail / list_task_findings. Read the finding details, the corresponding intent's execution trace, and any existing evidence list, prioritizing real IDs handed off by the reporter. If verification was over HTTP and traffic tools are available, use traffic_search to filter candidates, then inspect each with traffic_get to confirm the request/response genuinely supports the vulnerability; domain and timestamp are only for filtering, not proof of ownership. Bind confirmed evidence in reproduction order via bind_finding_traffic(finding_id, traffic_refs), choosing baseline / proof / verification / supporting and explaining each role. Only operate on this finding—do not create duplicate findings or re-probe the target. After binding succeeds, call get_finding_traffic again to fetch the latest version, read the needed bodies, and pass the actually read version as evidence_version to update_finding_report (whose finding_id parameter still takes finding_node_id). Do not append duplicate bindings. For TCP, uncaptured traffic, unavailable tools, or no exact match, skip automatic binding, write the report normally from text/command evidence, and explain why—never guess to fill traffic. If binding fails, do not claim success; preserve existing evidence and note the reason in the report."
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, guidance
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "Optional: verified traffic references corresponding to the specific vulnerability in this hint, preserving order; after handoff, report_finding can pass evidence_hint_id to carry these references.", "items": obj(map[string]any{"traffic_id": str("Real traffic ID"), "role": str("baseline / proof / verification / supporting"), "note": str("What conclusion this traffic supports")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d must be a hint node belonging to this task (inherited hints cannot be used directly for binding)", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
