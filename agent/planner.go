package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	findingRecorder   FindingRecorder
	prov              llm.Provider
	model             string
	tx                *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window            int                                    // context window in tokens (for compaction)
	windowFn          func() int                             // optional dynamic task-chain minimum
	maxTurns          int                                    // max agent turns per run (0 = unlimited)
	killWork          func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork         func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr         string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert       string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch         WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir           string                                 // shared work dir (surfaced in prompt as artifact-output target)
	injectConstraints func() bool                            // resolver: inject task operation constraints into system prompt? (nil = yes)
	nonStreamingFn    func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn      func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn       func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
	compactor         *Compactor                             // cold-node compaction (§7); nil = disabled

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

func (p *Planner) SetCompactionWindowResolver(fn func() int) { p.windowFn = fn }

// SetCompactor wires the cold-node compactor (cold-digest §7). Called each
// planner wake-up to advance the round counter, maintain cold stamps, and
// (off the hot path) fold cold nodes into digests. nil = feature disabled.
func (p *Planner) SetCompactor(c *Compactor) { p.compactor = c }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (p *Planner) SetNonStreaming(fn func() bool) { p.nonStreamingFn = fn }

func (p *Planner) nonStreaming() bool { return p.nonStreamingFn != nil && p.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (p *Planner) SetNoaEnabled(fn func() bool) { p.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (p *Planner) SetMaxTokens(fn func() int) { p.maxTokensFn = fn }

func (p *Planner) maxTokens() int {
	if p.maxTokensFn == nil {
		return 0
	}
	return p.maxTokensFn()
}

func (p *Planner) compactionWindow() int {
	if p.windowFn != nil {
		return p.windowFn()
	}
	return p.window
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the planner system prompt. Read per round so the
// settings toggle takes effect without rebuilding the agent. nil = inject (default).
func (p *Planner) SetConstraintInject(fn func() bool) { p.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (p *Planner) wantConstraints() bool { return p.injectConstraints == nil || p.injectConstraints() }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your Planning Todos (persisted across wake-ups, written in your previous round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Advance based on this list: only dispatch intents for next steps whose [prerequisites are complete / dependent facts already exist]; update the list with TodoWrite (mark steps satisfied by facts as completed). Do not re-dispatch steps already pending/in_progress in the list.")
	return b.String()
}

// TriggerEvent describes what concretely caused this planning round to fire, so
// the planner looks first at the actual change instead of re-scanning the whole
// overview. Kind:
//
//	"done"    — a worker finished intent IntentID (its output conclusion is fetched).
//	"finding" — a worker reported a finding on intent IntentID (Detail = 摘要).
//	"goal"    — the human (via 主 agent 的 set_goals) added one OR MORE goals in a
//	            single call (Goals = 本次新增的目标文本，1+ 条；set_goals 支持批量).
//	"goal_deleted" — the human deleted a goal from 总览的目标管理 (Detail = 被删目标文本).
//	"goal_edited"  — the human edited a goal from 总览的目标管理 (OldGoal→NewGoal 文本).
//	"cancelled" — the human deleted intent IntentID (Detail = 删除原因). The intent is
//	            stopped (not deleted) and the reason is attached to it as a fact.
type TriggerEvent struct {
	Kind     string
	IntentID int64
	Detail   string
	Summary  string   // Kind=="cancelled" 专用：删除前捕获的意图摘要（真删除后节点已不存在，无法再查）
	Goals    []string // Kind=="goal" 专用：本次 set_goals 新增的目标文本（1 条或多条）
	OldGoal  string   // Kind=="goal_edited" 专用：修改前的目标文本
	NewGoal  string   // Kind=="goal_edited" 专用：修改后的目标文本
	Hints    []string // Kind=="hint" 专用：本次 add_hint 新增的提示文本（1 条或多条）
}

// renderTriggers spells out the change(s) that fired this round: for a finished
// worker — which intent + its output conclusion; for a finding — which intent +
// what was found. Empty for time/heartbeat wakes. Reads the store (best-effort;
// a blank field never blocks the round).
func renderTriggers(ts *db.ExplorationStore, evs []TriggerEvent) string {
	if len(evs) == 0 || ts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Concrete Changes That Triggered This Round (read this first before deciding whether to add directions)]:")
	for _, ev := range evs {
		switch ev.Kind {
		case "goal":
			if len(ev.Goals) == 1 {
				b.WriteString(fmt.Sprintf("\n- Human (Main Agent) added a goal: %s — new pending goal; add exploration directions accordingly (if no corresponding intent exists yet).", ev.Goals[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- Human (Main Agent) added %d goals: %s — all new pending goals; add exploration directions for each that has no corresponding intent yet.", len(ev.Goals), strings.Join(ev.Goals, "; ")))
			}
		case "hint":
			if len(ev.Hints) == 1 {
				b.WriteString(fmt.Sprintf("\n- Human (Main Agent) added a strategic hint: %s — attached to the exploration graph; adjust/add exploration directions accordingly (if no corresponding intent exists yet).", ev.Hints[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- Human (Main Agent) added %d strategic hints: %s — all attached to the exploration graph; adjust/add exploration directions accordingly.", len(ev.Hints), strings.Join(ev.Hints, "; ")))
			}
		case "goal_deleted":
			b.WriteString(fmt.Sprintf("\n- Human deleted a goal: %s — this goal has been removed; re-evaluate remaining goals/directions accordingly (no need to dispatch intents for it).", ev.Detail))
		case "goal_edited":
			b.WriteString(fmt.Sprintf("\n- Human edited a goal from \"%s\" to \"%s\" — adjust exploration directions to match the new goal (stop dispatching obsolete directions).", ev.OldGoal, ev.NewGoal))
		case "finding":
			b.WriteString(fmt.Sprintf("\n- Worker for intent #%d (%s) reported a finding: %s", ev.IntentID, intentSummary(ts, ev.IntentID), ev.Detail))
		case "cancelled":
			// 意图内容优先用删除时捕获的 Summary（真删除后节点已不存在，intentSummary 查不到）。
			sm := ev.Summary
			if sm == "" {
				sm = intentSummary(ts, ev.IntentID)
			}
			b.WriteString(fmt.Sprintf("\n- Intent #%d was deleted by the user (content: %s; reason: %s). This intent has been deleted and will no longer execute; replan accordingly.", ev.IntentID, sm, ev.Detail))
		default: // "done"
			b.WriteString(fmt.Sprintf("\n- Worker for intent #%d (%s) finished with conclusion: %s", ev.IntentID, intentSummary(ts, ev.IntentID), workerOutput(ts, ev.IntentID)))
			if fids := factIDsYielded(ts, ev.IntentID); fids != "" {
				b.WriteString(fmt.Sprintf("; new fact IDs yielded by this intent: %s ", fids))
			}
		}
	}
	b.WriteString("\n(For full details, inspect with node_detail / get_worker_output / list_findings.)")
	return b.String()
}

// factIDsYielded lists the fact ids an intent produced this run as "#12、#15", so the
// planner can jump straight to the round's incremental facts. Empty (best-effort) when
// the intent yielded no facts or the lookup fails.
func factIDsYielded(ts *db.ExplorationStore, id int64) string {
	ids, err := ts.FactsYielded(id)
	if err != nil || len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, fid := range ids {
		parts[i] = fmt.Sprintf("#%d", fid)
	}
	return strings.Join(parts, ", ")
}

// intentSummary reads an intent node's one-line summary (best-effort, "?" on miss).
func intentSummary(ts *db.ExplorationStore, id int64) string {
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		return "?"
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

// workerOutput returns the finished worker's conclusion for an intent — the last
// 'result' (else 'text') activity's full detail, truncated. Same source get_worker_output uses.
func workerOutput(ts *db.ExplorationStore, id int64) string {
	acts, _, err := ts.ActivityList(&id, 0, 1000)
	if err != nil {
		return "(failed to fetch output)"
	}
	var pick *db.Activity
	for i := range acts {
		if acts[i].Kind == "result" {
			pick = &acts[i]
		} else if acts[i].Kind == "text" && pick == nil {
			pick = &acts[i]
		}
	}
	if pick == nil {
		return "(no output recorded for this work yet)"
	}
	out, _ := ts.ActivityDetail(pick.ID)
	if out == "" {
		out = pick.Summary
	}
	return truncOutput(out, 800)
}

// truncOutput caps a worker-output blob so the trigger context doesn't bloat the
// system prompt every round; full text is one get_worker_output call away.
func truncOutput(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + " ... (truncated, see get_worker_output for full text)"
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[Current Round Posture (prefetched graph_overview, identical to calling that tool; call node_detail/list_facts etc. on demand for deeper details)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the 中间产物输出规约
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "Planner" of an authorized cybersecurity penetration testing system, woken frequently (whenever the graph changes). Responsibility: read posture -> evaluate goals -> **add exploration intents only when there are genuinely uncovered new directions**. You are a planner, not an executor: all outputs of this round must only be [generating/specifying intents] or [evaluating goals]—never do the execution work yourself during planning.

Task goal: {{.Goal}}

**How many intents to produce this round (think this through first)**:
- **Hard floor (highest priority)**: Whenever [goals are not yet met] AND [there are currently no open or running intents] (frontier_open=0 and running_intents is empty), this round [MUST] produce at least one intent advancing toward the goal—with no running work to wait for and no queued directions, producing 0 intents stalls the task; even if known directions only appear in recent_done, open a new branch or resume one according to the done/exhausted/blocked rules below.
- Outside the hard floor, **producing 0 intents is a normal outcome, provided there is a valid reason** (not a default of "dispatching fewer is safer"): (1) **Already covered**—every direction you thought of is already being handled by an open/running intent (re-generating an existing intent with different wording is a serious mistake); (2) **Waiting on dependencies**—the next step depends on output from a currently running work that has not finished yet (dispatching prematurely causes the downstream worker to spin without prerequisites; wait for the next wakeup after the graph updates).
- Conversely: whenever there is a genuinely [uncovered direction that does not depend on running work], or goals remain unmet with untested surfaces in scope, dispatch it—do not treat 0 intents as a lazy default.

**Decision workflow on every wakeup**:

1. **Full posture is attached below this prompt** (the exact output of graph_overview, so no need to call it again): task (original title + goal/root node), asset counts, goals + status, open/running/recent_done intents, sites_without_endpoints (sites without endpoints, hinting at possible areas to probe), facts (exploration fact count, distinct from findings), recent_facts ({id, summary, confidence?}).
   - **Scope**: Exploration nodes (goals/intents/facts/findings) belong only to this task; **the asset graph is globally shared** (shared across tasks; asset counts reflect global in-scope assets, not exclusive to this task)—ignore assets unrelated to this task.
   - **Lineage**: Each intent carries parents (upstream: which facts/intents it was derived from) and yields (downstream: which facts/findings it produced), and each entry in recent_facts carries from_intent; use this to understand "which facts came from which direction and whether they synthesize into a new direction."
   - **Negative / uncertain observations** ("port closed / not injectable" in recent_facts) are worker observations, not final truth: before accepting them, call node_detail(id) to inspect evidence—only treat a direction as tentatively closed when evidence is solid, confidence=observed, and techniques were exhausted; if evidence is missing, it only "looks like / tried once", or confidence=inferred, treat it as [not yet established], and if it is in scope and uncovered by other intents, default to dispatching one verification intent to confirm or refute (**verify any negative direction at most once**; if still negative with reasonable evidence after verification, respect that conclusion and stop dispatching).
   - **Fetch deeper details only on demand**: list_facts (paginated, newest first, default 20, supports q filter and before pagination, includes total/has_more), list_findings (all findings), node_detail(id) (full evidence/detail; lists and recent_facts only show summaries), list_assets (pull: q search, type/company_id/task_id filters, pagination, or direct id/ids lookup), asset_neighbors. Assets are globally shared—do not pull everything by default.

2. **Evaluate goals (core responsibility)**: The goals field lists each goal and its status; for any unmet goal already proven by a finding/fact, call prove_goal(goal_id, evidence_id, reason) to mark it met. **When you mark the very last unmet goal, the system automatically marks the entire task complete**—completion is driven solely by proving goals one by one; there is no other "complete task" shortcut.
   - **Quantitative acceptance check (strictly no premature sign-off)**: When a goal includes quantitative criteria (reach X% coverage, capture N flags, obtain specific privileges), you [MUST] verify the actual numbers in graph_overview above (coverage.pct, findings_total, etc.) before calling prove_goal: if not yet met, [DO NOT] call prove_goal—dispatch intents to close the gap instead; never mark met early on the grounds of "mostly done / core achieved." Example: goal requires 100% coverage while actual coverage.pct=40% -> not met; continue dispatching gap-filling intents.

3. **(Optional, opening round only, ultra-lightweight) Exploratory understanding**: Only when the graph has almost no facts yet (recent_facts is basically empty, task just started) and the posture alone is insufficient to make initial intents concrete may you run minimal, read-only probes with Bash etc. (e.g., 1-2 curls to check homepage/fingerprint). **The ONLY valid output is a more precise intent description**—never vulnerability discovery/verification/exploitation, nor endpoint/directory/parameter enumeration (that is the worker's job; turn it into an intent and dispatch it). Three hard boundaries:
   - Once the graph already has worker-produced facts (facts>0 / recent_facts non-empty) -> [FORBIDDEN] to probe yourself; base all decisions on existing facts, and this round's output can only be "dispatch new intents" or "finish"; to dig deeper into a lead -> dispatch an intent for a worker, do not curl it yourself.
   - Even at the start, stop after <=3 probes purely to clarify initial intents; the moment you notice yourself "investigating deeply" instead of "quickly setting direction" (enumerating endpoints/directories, testing IDs one by one, decoding chains, repeatedly probing one endpoint, testing/verifying any injection/IDOR/vulnerability—all heavy worker tasks), stop immediately and write it as an intent.
   - If you can decide from existing facts/posture, do not probe at all.

4. **Decide which new directions to add**: **"Restraint" here means only [do not duplicate existing intents], NOT "dispatch as few as possible"**—while goals remain unmet, the default question is "to get closer to the goal, what deeper, sharper, uncovered attack paths remain?", not "can we wrap up?". Intents are [open-ended exploration directions] (not a fixed menu/taxonomy); judge directions from known facts, assets, and goals, comparing each against open + running + recent_done:
   - Already covered by open/running -> do not generate (already in progress).
   - Appeared in recent_done -> **check the intent's state (present on every entry) to see how it stopped before deciding**:
     - **done (finished normally)**: already covered -> do not re-dispatch as-is; judge whether it is a dead end from the fact conclusions it yielded, not from state; re-dispatch only when a [materially new mechanism] emerges (new fact/asset/parameter/substantially different approach), and clearly state in summary how it differs from the previous run; rephrasing or "maybe trying again will work" does not count—no retries.
     - **exhausted (budget ran out mid-way, only partial write-back) / blocked (model or network failure, barely explored)**: both ended prematurely with incomplete info—first inspect get_worker_trace / get_worker_output to see how far it actually got and where it got stuck, then choose: close to breakthrough when cut by budget -> dispatch "continue from previous progress"; pure external failure (common for blocked) -> re-dispatch the same direction directly; repeatedly stuck at the same spot -> switch approach/direction. Always base the decision on actual progress in the trace, never on state alone.
   - Brand-new direction uncovered by any intent -> generate.
   - All known directions are already covered by open/running intents -> do not generate and finish directly (active/queued workers are advancing them); however, if coverage exists only in recent_done with no open/running intents left while goals remain unmet -> by the hard floor above, you must open a new direction or resume one.
   - **Depth over coverage**: coverage is a floor/acceptance metric, not the exploration goal itself; once a high-value entry point (potentially leading to RCE / privilege escalation / data exfiltration) is found, prioritize dispatching intents to [drive that path all the way through], rather than spreading shallowly across every asset just to even out coverage.
   - **Maintain route diversity; avoid premature convergence**: while goals are unmet, if existing intents all cluster on one route/entry point while a [fundamentally different] uncovered direction exists (another entry surface / asset class / exploit chain), prioritize adding that divergent direction rather than adding synonymous intents on the same line (judge by substantive difference, not wording); if that divergent direction is already covered, still do not generate. Ideally 2-3 mechanically distinct routes run concurrently (e.g., "via upload chain" and "via auth bypass"), concentrating resources once one yields evidence [approaching the goal]. **Diversity always yields to [Operational Constraints] at the top**: never generate intents for entry surfaces, ports, hosts, or operations excluded by constraints, even if fundamentally different.

   **Serial exploitation chains: dispatch step by step, never split into parallel.** For strongly dependent serial chains (1 -> 2 -> 3, where each step depends on the actual output of the previous step): do not dispatch them all in parallel at once (downstream workers lacking non-existent prerequisites will only duplicate work or spin); record the whole chain as todos via TodoWrite (one item per step), dispatch only the step whose prerequisites are met (usually step 1), and on subsequent wakeups (which include your todo list) after it yields facts, dispatch the next step and mark satisfied steps completed. Do not split "the same thing" into two intents ("confirm trigger" and "trigger it" are one step); use parallel intents only for [independent, non-overlapping] dimensions (e.g., enumerating unrelated endpoints).

5. **Submit**: Submit the selected new directions in [ONE] batch add_intent call (intents array, at most 4 highest-value items; do not call repeatedly one by one):
   - **summary**: a single natural-language sentence describing the direction (full target address + what to do + why), without rigid categories; deduplication relies primarily on comparing this against existing intents.
   - **asset_ids**: target asset IDs this direction will test/attack (pass whenever possible, 0/1/many, from list_assets)—always pass whenever the direction targets specific assets (site/endpoint/parameter/host) for coverage deduplication and asset lineage linking; pass all relevant IDs if spanning multiple assets; leave empty only for pure global recon with no specific asset.
   - **parent_ids**: upstream node IDs from which this direction was synthesized (optional, 0/1/many)—pass all when combining multiple facts into one intent, or pass an upstream intent/finding ID when deriving from it; leave empty for a fresh top-level direction.

No duplicates, no filler; when goals are unmet and deeper uncovered approaches exist, dispatch decisively. Be concise, focused, and effective.`

func plannerSystem(goal, dataDir, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir)
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// triggers carries the concrete change(s) that fired this round — worker(s) done
// and/or finding(s) reported (may be several — the engine debounces a burst; empty
// for time/heartbeat wakes). They are spelled out at the top of the prompt so the
// planner looks first at the actual change (which intent, its output/finding).
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, triggers []TriggerEvent, emit func(db.Activity)) (met bool, reason string, err error) {
	// cold-digest §2.3/§7: advance this task's planner-round counter, maintain the
	// cold_since_round stamps, and (if a threshold is hit) kick off background
	// compaction. Synchronous part is cheap (a few queries); the LLM compaction
	// runs in a detached goroutine so it never adds latency to this round.
	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetFindingRecorder(p.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// 领域工具 + 基础默认工具集（Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash）
	// 资产覆盖度功能关闭时剔除 add_task_scope/list_untested_assets（不入 prompt）。
	base := append(tsx.DropCoverageTools(tsx.PlannerTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// 关键态势（刚完成的意图 + 预取的完整图）改放【本轮 user 输入】(见下方 input)，system
	// 只留静态规划正文。move-out 让 system 每轮稳定、更利于缓存；代价是若单轮变长，态势可能
	// 被 compaction 压缩（planner 单轮通常短，风险低）。situational 会拼进下方 input。
	situational := renderTriggers(ts, triggers) + renderGraphOverview(tsx.graphOverviewData())
	// 任务级 deadline / 终局模式(经 ctx 注入,见 taskclock.go)。终局那一轮把任务超时
	// planner 收尾词作为【本轮操作指令】拼进本轮 user 输入(随 situational),让它只做最后
	// 目标判定、不产新意图。
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Task Final Wrap-Up (special instruction for this round, overriding the regular planning workflow above)]: " + resolveTaskTimeoutWrapup("planner")
	}
	// 本任务的工作目录 <workDir>/tasks/<taskID>，先建好。
	taskDir := ensureRunDir(p.workDir, taskID, 0)
	ctx = intercept.WithReviewContext(ctx, taskDir, intercept.ReviewBackground{})
	sysBody := plannerSystem(goal, p.workDir, taskDir)
	if p.wantConstraints() {
		sysBody += constraintBlock(ts) // 操作约束(若有)注入系统提示,框定探索边界
	}
	system, boundary := deferredSystem(sysBody, def)
	// planner 无自身墙钟预算;有 deadline 时把 MaxDuration 夹逼到剩余,让在跑的规划轮在
	// 任务到点时进收尾(因超时→任务超时词,因步数→per-run 词)。
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:       p.webSearch.Enabled,
		WebSearchBackend:      p.webSearch.Backend,
		BraveSearchAPIKey:     p.webSearch.BraveKey,
		TavilySearchAPIKey:    p.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: p.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  p.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   p.webSearch.DeepSeekModel,
		WebSearchProxy:        p.webSearch.Proxy,
		BashEnv:               proxyEnv(p.proxyAddr, p.proxyCACert), // Bash 子命令默认走代理+信任 CA
		WorkingDir:            taskDir,                              // 本任务工作目录 <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(taskDir),
		MaxTurns:              p.maxTurns, // 0 = unlimited (configurable in agent management)
		MaxDuration:           maxDur,     // 0=不限;有 deadline 时=距 deadline 剩余
		Compaction:            compactionConfig(p.compactionWindow()),
		// 跨唤醒共享的规划待办：让串行链在多轮之间保留（session 是新的，store 不是）。
		Todos: p.todoFor(ts.ID()),
		// 命中【本轮】步数预算→ SDK 跑收尾:把本轮已想清楚的结论落地(该派的 add_intent、
		// 能证的 prove_goal、串行链记 TodoWrite),而非停止规划——planner 之后仍会被反复唤醒。
		// clamped(被任务 deadline 夹逼)时改用 PromptByReason(见 wrapupSettlementForTask)。
		Settlement:   settle,
		NonStreaming: p.nonStreaming(), // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:    p.maxTokens(),    // 0 = 不发上限,由服务端默认值决定
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// 实验功能:开启后由 noa 接管上下文压缩(归档集中在 <workDir>/noa/<SessionID> 下,持久)。
	noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
	enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, noaWarn(noaSession))
	// 态势（刚完成的意图 + 完整图）现在拼进本轮 user 输入（见下方 input）。user 里还有
	// 指令 + 跨唤醒待办（todo 是模型自己的规划便签，可再生，放 user 即可）。
	// 开场白按「本轮有无具体变动」分两种：有变动 → 指向下方【实际变动】块；无变动
	// (心跳定时巡检 / hint / 恢复等) → 别谎称"图发生了变化",转而提示顺带复查在跑意图。
	lead := "Concrete changes just occurred (see [Concrete Changes That Triggered This Round] below); plan the next steps accordingly:"
	if len(triggers) == 0 {
		lead = "This round is a **periodic check-in (heartbeat) / no-specific-change** wakeup—the graph may not have changed. Also review running intents: use steer_work to course-correct any that are stalled or drifting, and kill_work to stop any going in the wrong direction; then evaluate goals and decide whether to add directions:"
		// 心跳/无变动唤醒时,若全图已无任何 open 或 running 意图 → 探索已停摆(没 worker 在跑、
		// 也没排队方向)。明确告知 planner 并强制其本轮补出新方向,别只复查在跑意图后空转一轮。
		if active, err := ts.HasActiveIntent(); err == nil && !active {
			lead = "This round is a **periodic check-in (heartbeat)** wakeup, and there are currently **no open or running intents**—no workers are running and no directions are queued; exploration has stalled. You **MUST** produce one or more new intents this round that advance toward the goal and **do not duplicate** existing intents in the graph (producing 0 intents is not allowed); first check from the posture below whether goals are already met, and if not, add directions immediately:"
		}
	}
	input := lead + situational + "\n\nBased on the posture above, evaluate the goals. When a goal is [genuinely met] (target deliverable obtained / target vulnerability confirmed), mark it with prove_goal one by one. **Hard floor: whenever goals remain unmet and there are currently no open or running intents (frontier_open=0 and running_intents is empty), this round MUST produce at least one intent advancing toward the goal—with no running work to wait for and no queued directions, producing 0 intents stalls the task. You may skip producing new intents this round ONLY when open/running intents are already advancing or all goals are met.**" +
		renderPlannerTodos(opts.Todos.List())
	// MaxDuration 现在会在墙钟到点打断在跑工具并就地进收尾(在活 ctx 上),单轮卡死不再
	// 绕过收尾,无需外部硬 ctx 兜底。ctx 只承载 pause / kill / shutdown。
	_, _, err = captureRun(ctx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
