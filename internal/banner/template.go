package banner

import (
	"bytes"
	"strings"
	"sync"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/caddyserver/caddy/v2"
	internalcaddyssh "github.com/kadeessh/kadeessh/internal"
	"github.com/kadeessh/kadeessh/internal/session"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

func init() {
	caddy.RegisterModule(Template{})
}

// Template is a module that allows you to render a custom banner using the connection
// metadata (i.e. User, SessionID, ClientVersion, ServerVersion, RemoteAddr, LocalAddr).
// The template is rendered using the [text/template package](https://pkg.go.dev/text/template)
// and the [sprig template functions](https://masterminds.github.io/sprig/).
type Template struct {
	// The template content
	Body string `json:"body"`

	tpl    *template.Template
	logger *zap.Logger
}

// CaddyModule implements caddy.Module.
func (t Template) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.banner.template",
		New: func() caddy.Module {
			return new(Template)
		},
	}
}

// Provision implements caddy.Provisioner.
func (t *Template) Provision(ctx caddy.Context) error {
	t.logger = ctx.Logger()
	t.tpl = template.New("banner").Funcs(sprig.TxtFuncMap())
	if _, err := t.tpl.Parse(t.Body); err != nil {
		return err
	}
	return nil
}

func (t *Template) RenderingCallback(ctx session.Context) session.BannerCallback {
	return func(conn gossh.ConnMetadata) string {
		buffer := bufPool.Get().(*bytes.Buffer)
		defer buffer.Reset()
		defer bufPool.Put(buffer)
		if err := t.tpl.ExecuteTemplate(buffer, "banner", conn); err != nil {
			t.logger.Error(
				"failed to render banner template",
				zap.Error(err),
				zap.String("session_id", string(conn.SessionID())),
				zap.String("user", conn.User()),
				zap.String("server_version", string(conn.ServerVersion())),
				zap.String("remote_addr", conn.RemoteAddr().String()),
				zap.String("local_addr", conn.LocalAddr().String()),
			)
			return ""
		}
		str := buffer.String()
		if !strings.HasSuffix(str, "\n") {
			str += "\n"
		}
		return str
	}
}

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

var (
	_ caddy.Module                     = (*Template)(nil)
	_ caddy.Provisioner                = (*Template)(nil)
	_ internalcaddyssh.BannerGenerator = (*Template)(nil)
)
