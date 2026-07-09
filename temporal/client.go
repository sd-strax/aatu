package temporal

import (
	"context"
	"fmt"

	"go.temporal.io/sdk/client"

	"github.com/sd-strax/reckon/internal/branding"
)

// Client is a thin dispatch wrapper over the Temporal SDK client, scoped to
// reckon's task queue and namespace. It is the command-path entry point for
// starting workflows; Phase C extends it with real Start* methods
// (StartActionLifecycle, …). At A.7 it carries only Ping — the wireup prover.
type Client struct {
	c         client.Client
	taskQueue string
}

// ClientConfig configures a dispatch Client.
type ClientConfig struct {
	// HostPort is the Temporal frontend gRPC address, e.g. "localhost:7233".
	HostPort string

	// Namespace is the Temporal namespace. Default "default".
	Namespace string

	// TaskQueue is the queue workflows are dispatched onto. Default
	// branding.CLI — must match the Worker's task queue for work to be picked
	// up.
	TaskQueue string
}

// NewClient dials the Temporal frontend and returns a dispatch Client. The
// caller owns the returned Client and must Close it.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}
	if cfg.TaskQueue == "" {
		cfg.TaskQueue = branding.CLI
	}
	c, err := client.Dial(client.Options{HostPort: cfg.HostPort, Namespace: cfg.Namespace})
	if err != nil {
		return nil, fmt.Errorf("dial temporal %s: %w", cfg.HostPort, err)
	}
	return &Client{c: c, taskQueue: cfg.TaskQueue}, nil
}

// Close releases the underlying Temporal client.
func (c *Client) Close() { c.c.Close() }

// Ping executes the Ping workflow and returns its result, proving the round
// trip command → Temporal → worker → result. Blocks until the workflow
// completes.
func (c *Client) Ping(ctx context.Context, msg string) (string, error) {
	run, err := c.c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		TaskQueue: c.taskQueue,
	}, WorkflowPing, msg)
	if err != nil {
		return "", fmt.Errorf("start Ping workflow: %w", err)
	}
	var out string
	if err := run.Get(ctx, &out); err != nil {
		return "", fmt.Errorf("Ping workflow result: %w", err)
	}
	return out, nil
}
