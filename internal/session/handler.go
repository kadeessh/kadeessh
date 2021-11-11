package session

type Handler interface {
	Handle(Session) error
}
