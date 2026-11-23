package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedByUser = cause("paused_by_user", "User paused the task",
		"User paused the task via the task control API (POST /api/tasks/{id}/control, action=pause). This Planner/Worker run was proactively cancelled; in-flight intents return to frontier (open) and will be re-claimed and executed from scratch after resuming")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "Orchestrator agent paused the task",
		"The orchestrator agent called pause_task to pause this task. This Planner/Worker run was proactively cancelled; in-flight intents return to frontier (open) and will re-execute after resuming")
	AbortTaskDeleted = cause("task_deleted", "Task was deleted",
		"The task is being deleted (DELETE /api/tasks/{id}); the deletion barrier cancelled the running Planner, Workers, and Main Agent for this task; results from this run will no longer be used")
	AbortPausedOnReload = cause("paused_on_reload", "Backend restored the task's paused state",
		"On startup, the backend restored the task's paused state from persisted database state. This run was cancelled; normally no agents are running during recovery")
	AbortGoalMet = cause("goal_met", "Planner determined task goals are met",
		"The planner determined that task goals are met and marked the task done, then cancelled still-running Workers; those intents are marked stopped rather than failed")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "Task timeout wrap-up drain window expired",
		"After the task reached its timeout, the system waited for running Workers to wrap up gracefully, but the 90-second drain grace period was exceeded and a hard cancel was issued; intents are marked exhausted, and facts/assets already written during wrap-up are preserved")

	// Per-work context.
	AbortKilledByPlanner = cause("killed_by_planner", "Planner terminated this intent",
		"The planner called kill_work to proactively terminate this intent, typically because it drifted off track or no longer has value; the intent is marked stopped and will not be automatically re-claimed")
	AbortWorkPausedByUser = cause("work_paused_by_user", "User paused this Worker intent",
		"The user paused a running Worker. This run was cancelled and the intent moved to paused; all already-recorded intents, facts, findings, and activity logs are preserved, and it will execute from scratch when resumed")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "User deleted this Worker intent",
		"The user deleted a running Worker. This run was cancelled; once the Worker exits the write section, the server handles the intent according to the chosen deletion mode—soft delete marks it deleted while keeping all outputs, while hard delete cascades to remove the intent and downstream nodes supported only by it")
	AbortWorkFinished = cause("work_finished", "Worker finished normally and released context",
		"The Worker finished normally and the engine released its context in detachWork. This is not an interruption; if it appears in an abort message, a race occurred between cancellation and teardown")
	AbortPausedRaceGuard = cause("paused_race_guard", "Refused to start new run while task is paused",
		"While the task is paused, the engine refuses to issue new execution contexts to prevent a claim/pause race from launching a Worker; the claimed intent returns to frontier")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "User stopped this chat turn",
		"The user clicked Stop to proactively abort this Main Agent or chat agent turn. Activity records already produced are preserved, and the user can send a follow-up message")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "Task pause aborted Main Agent chat",
		"When the user paused the task, the running Main Agent chat turn was cancelled as well. Activity records already produced are preserved; resuming the task will not automatically replay this turn")
	AbortChatTurnFinished = cause("chat_turn_finished", "Chat turn finished normally and released context",
		"This chat turn finished normally and the server is releasing its context. This is not an interruption; if it appears in an abort message, a race occurred between cancellation and teardown")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "Backend process is shutting down",
		"The backend process received SIGINT or SIGTERM and is restarting, updating, or shutting down. All running agents are cancelled; leftover running intents are reset to open and re-executed after restart")
	AbortRunHardTimeout = cause("run_hard_timeout", "Per-run hard timeout backstop triggered",
		"This run exceeded both its soft wall-clock budget and extra grace period, indicating a model request or tool did not return for an extended time and prevented normal turn-boundary wrap-up. Inspect the last unreturned tool call before the abort")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "Upstream context reached deadline",
			"Upstream context reached its deadline, but the caller did not attach a named cause via WithTimeoutCause: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "Canceller did not attach a named cause",
			"Upstream context was cancelled, but the canceller did not attach a named cause via context.WithCancelCause; register a cause in agent/cancelcause.go and wire it at that cancellation site", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}
