package session

// Handler is an interface for an Actor to implement
type Handler interface {
	Handle(Session) error
}
