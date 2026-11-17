package cdap

import (
	"context"
	"fmt"
	"time"
)

// SendCommandAndWait sends a command and waits for its correlated response.
// It is intended for fixed management operations whose acknowledgement is
// required before committing server-side state. Callers must not put secrets
// in the response; responses are published on the normal CDAP event bus.
func (g *Gateway) SendCommandAndWait(ctx context.Context, deviceID string, cmd *CommandMessage) (*CommandResponsePayload, error) {
	dc := g.GetDeviceConn(deviceID)
	if dc == nil {
		return nil, fmt.Errorf("device %s not connected", deviceID)
	}
	if cmd == nil || cmd.ID == "" {
		return nil, fmt.Errorf("command ID is required")
	}
	pending := &PendingCommand{
		CommandID: cmd.ID,
		DeviceID:  deviceID,
		SentAt:    time.Now(),
		ResultCh:  make(chan *CommandResponsePayload, 1),
	}
	g.pendingCommands.Store(cmd.ID, pending)
	defer g.pendingCommands.Delete(cmd.ID)

	dc.CommandCount.Add(1)
	if err := dc.WriteMessage(ctx, &Message{
		Type: "command", ID: cmd.ID,
		Timestamp: time.Now().UTC().Format(time.RFC3339), Payload: cmd.Payload,
	}); err != nil {
		return nil, err
	}
	select {
	case response := <-pending.ResultCh:
		if response == nil {
			return nil, fmt.Errorf("empty command response")
		}
		return response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
