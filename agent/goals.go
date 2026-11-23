package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// goalsDefaultTmpl is the built-in EDITABLE body (段 [A]) of the goals-decomposer
// prompt, seeded into agent_prompts. No template vars are used today.
const goalsDefaultTmpl = `You are a penetration testing goal decomposer. Your responsibility is to identify the **final outcomes to achieve** from the user's input, rather than planning attack steps.

**Step 1 (do this before decomposing goals): Extract Operational Constraints**
Identify explicit operator rules from "Task Goal / Task Description" about [what operations are allowed or prohibited], and register each one via set_constraints (if neither the description nor the goal mentions operational constraints, you may skip extracting constraints):
- type=deny: prohibited operations (e.g., "do not scan ports", "do not perform write/delete operations on production", "no brute-forcing", "do not touch a specific subdomain").
- type=allow: explicitly allowed/restricted operational scope (e.g., "passive reconnaissance only", "target only a specific domain").
- Constraints != goals, and != attack steps: they define boundaries on operational behavior.
- **Constraints must be [self-contained and hardcode concrete targets]**: replace **deictic references** like "current target / current port / current IP / current domain / this site" with the **concrete values** from the task goal/description. Constraints are injected standalone into execution-phase prompts where deictic references cannot be resolved without context.
  Example: if the target is https://abc.example.net -> write "Only test abc.example.net" instead of "Only test the current target"; "Only test target port 443, do not scan other ports" instead of "Only test the current port". If the original text says "current target" while the target address is explicitly given, fill in the address.
- **Only register constraints [explicitly stated or emphasized] in the goal/description; strictly avoid fabricating any**; when unsure of the type, use deny (more conservative).
- If the goal/description truly contains no operational constraints, **do not** call set_constraints.
After registering constraints (if any), proceed to goal decomposition below.

**Goal = final deliverable / verifiable outcome**

**NOT goals (do NOT list as sub-goals)**:
- Information gathering, reconnaissance, endpoint scanning
- Vulnerability analysis and verification processes
- Attack steps, exploitation techniques
- Result verification steps

**Decomposition principles**:
- If the user describes only one final goal -> output one
- If there are multiple **mutually independent** final deliverables -> list them separately
- Annotate vulnclass when a clear vulnerability class applies; leave empty for information gathering / business logic goals
- Strictly avoid inventing goals not mentioned by the user

Call set_goals to submit the results.`

// goalsScopeTail is the code-owned tail appended after the editable goals body
// WHEN an asset store + task context are available. It teaches the decomposer to
// also lift the explicit asset scope out of the goal/description and register it
// via add_task_scope. Kept in code (not the DB-editable body) so it always applies
// on released DBs and can't be edited away — same pattern as the trafficTool tail.
const goalsScopeTail = `

**Additional Responsibility: Register Testing Asset Scope**
In addition to decomposing goals, identify the **explicitly specified testing asset scope** from "Task Goal / Task Description" and register it via add_task_scope (this task's authorization boundary, and the denominator for asset testing coverage). **Principle of minimal scope: only register the exact target the user explicitly named; never expand it on your own.**
- Target is a URL or address with a hostname (e.g., https://xxx.example.com/path, app.example.com) -> extract the **full hostname**, kind=subdomain, value=full hostname.
  Example: target https://a1b2c3.lab.example.net/path -> kind=subdomain, value=a1b2c3.lab.example.net (**NOT** example.net).
  **Strictly forbidden** to trim a hostname with subdomains down to its root domain—registering all of example.com when given xxx.example.com expands scope beyond the user's target and violates the principle of minimal scope.
- Only when the user gives a **bare root domain with no subdomain** (e.g., directly writes example.com), or explicitly says "entire site / all subdomains / whole domain" -> use kind=root_domain, value=example.com.
- Plain IP or CIDR block -> kind=ip / cidr, value=IP or CIDR.
- **Do not** register company scope (company)—when a task is first created, the company usually does not exist in the asset system yet and cannot be registered; company-level scope is handled in the subsequent plan phase.
Other rules:
- Only register scope **explicitly stated in the goal/description**; strictly avoid fabricating or inferring unmentioned domains/IPs.
- Briefly note in reason which sentence it came from for auditing.
- If the goal/description contains no explicit asset scope, **do not** call add_task_scope.
First register the scope via add_task_scope (if any), then call set_goals to submit the goals.`

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoals asks the LLM to break a pentest task goal into discrete,
// independently-verifiable objectives (each becomes a goal node). Returns nil if
// no provider is configured or the call yields nothing — the caller then falls
// back to a rule-based split so goal nodes always exist.
//
// prov is supplied by the caller (rather than built here from a Config) so goal
// decomposition rides the SAME provider instance as the rest of the engine — it
// shares the rate limiter, gets recorded by llmrec, and participates in LLM
// failover instead of quietly bypassing all three.
//
// desc is the task's free-text description (背景：靶标范围/flag 数量/交战说明等).
// It is fed alongside the goal so the decomposer no longer splits blind — the
// prompt still forbids inventing anything the two texts don't state.
//
// emit, when non-nil, receives every LLM step (thinking/tool_use/result) with
// Worker="planner" so the round-0 goal-decomposition activity is visible in the UI.
//
// as + taskID, when non-nil/positive, wire the add_task_scope tool so the
// decomposer can register the explicit asset scope it extracts from the goal.
//
// ts is the task's exploration store: set_goals writes the decomposed goal nodes
// straight into it (the same managed tool the main agent uses to add goals at
// runtime). The returned specs are read back from the store so callers can emit
// per-goal activity and detect the "LLM produced nothing" case for their fallback.
func DecomposeGoals(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	return DecomposeGoalsWithProvider(ctx, prov, dataDir, goalText, desc, as, ts, taskID, false, 0, emit)
}

// DecomposeGoalsWithProvider is the task-runtime variant used when a task has an
// ordered provider chain. It preserves the same tools and write behavior while
// letting the caller own provider selection/failover. maxTokens is the profile's
// per-reply output cap (0 = send none).
func DecomposeGoalsWithProvider(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, nonStreaming bool, maxTokens int, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	// 目标拆解是一次性调用：不挂 transcript store，所以 agentcore 不会往 ctx 上挂
	// session id（它只在有 writer 时才挂，见 agentcore.Prompt）。而按 session-id 头
	// 做提示缓存/粘性路由的网关（opencode zen 缺 x-opencode-session 直接 400
	// MissingSessionID）读的就是 ctx 上这个值——不补就是「对话正常、拆解 400」。
	// 显式挂一个稳定 id：同一探索的拆解请求共享它（利于命中缓存），且命名与
	// planner/worker 不冲突，能被 llmrec.parseSession 正确归因。
	if ts != nil {
		ctx = transcript.WithSessionID(ctx, fmt.Sprintf("exp%d-goals", ts.ID()))
	}
	// worker="goals" tags the goal nodes' provenance; ts/taskID let set_goals link
	// each goal under the task root. This is the catalog's real set_goals tool, so a
	// web-edited description/schema on it applies here too.
	tsx := &ToolSet{as: as, ts: ts, taskID: taskID, worker: "goals"}
	// Description rides in the user message (same channel as the goal), NOT via the
	// {{.EngagementDescription}} template var — else a prompt that references the var
	// would inject the description twice. System prompt stays pure static instructions.
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{DataDir: dataDir, Now: nowStr()})
	// set_constraints 始终可用(不依赖 asset store):正文已含「先抽操作约束再拆目标」这步
	// (可在 agent 编辑页改措辞),这里只需接上工具。
	tools := []actool.CoreTool{tsx.setGoals(), tsx.setConstraints()}
	// Wire add_task_scope only when we have a real asset store + task to write to.
	// The scope-extraction tail is appended in lockstep so the prompt never asks for
	// a tool that isn't present.
	if as != nil && taskID > 0 {
		tools = append(tools, tsx.addTaskScope())
		sys += goalsScopeTail
	}
	userMsg := "Task goal:\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\nTask description (background context, may include target scope / flag count / rules of engagement; for reference only, do not invent anything not mentioned here):\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  tools,
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		// 3 步(抽约束 → 登记范围 → 拆目标)各需一次工具调用,给足回合避免收尾前漏调 set_goals。
		MaxTurns:     8,
		NonStreaming: nonStreaming, // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:    maxTokens,    // 0 = 不发上限,由服务端默认值决定
	}, userMsg, captureEmit)
	// set_goals persisted the goals directly; read them back so the caller sees what
	// was written (empty slice ⇒ the LLM produced nothing ⇒ caller falls back).
	if ts == nil {
		return nil
	}
	nodes, _ := ts.ListByKind(db.KindGoal, 10000)
	var out []GoalSpec
	for _, n := range nodes {
		var p struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if strings.TrimSpace(p.Text) != "" {
			out = append(out, GoalSpec{Text: p.Text, VulnClass: p.VulnClass})
		}
	}
	return out
}
