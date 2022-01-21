package restserver

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/restic/rest-server/quota"

	"gopkg.in/jcmturner/goidentity.v3"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
)

func (s *Server) debugHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s %s", r.Method, r.URL)
			next.ServeHTTP(w, r)
		})
}

func (s *Server) logHandler(next http.Handler) http.Handler {
	accessLog, err := os.OpenFile(s.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	return handlers.CombinedLoggingHandler(accessLog, next)
}

func (s *Server) checkAuth(r *http.Request) (username string, ok bool) {
	username = ""
	ok = false

	if len(s.KeyTabFile) > 0 { // SPNEGO auth provider
		ctx := r.Context()
		creds := ctx.Value(spnego.CTXKeyCredentials).(goidentity.Identity)
		if creds.Authenticated() {
			username = creds.UserName() + "@" + creds.Domain()
			ok = true
		}
	} else if !s.NoBasicAuth { // HTTP basic auth provider
		var basic_username string
		var basic_password string
		var basic_ok bool
		basic_username, basic_password, basic_ok = r.BasicAuth()
		if basic_ok && s.htpasswdFile.Validate(basic_username, basic_password) {
			username = basic_username
			ok = basic_ok
		}
	} else {
		username = ""
		ok = true
	}

	return username, ok
}

func (s *Server) wrapMetricsAuth(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, ok := s.checkAuth(r)
		if !ok {
			httpDefaultError(w, http.StatusUnauthorized)
			return
		}
		if s.PrivateRepos && username != "metrics" {
			httpDefaultError(w, http.StatusUnauthorized)
			return
		}
		f(w, r)
	}
}

// NewHandler returns the master HTTP multiplexer/router.
func NewHandler(server *Server) (http.Handler, error) {
	if !server.NoBasicAuth {
		var err error
		server.htpasswdFile, err = NewHtpasswdFromFile(filepath.Join(server.Path, ".htpasswd"))
		if err != nil {
			return nil, fmt.Errorf("cannot load .htpasswd (use --no-auth to disable): %v", err)
		}
	}

	const GiB = 1024 * 1024 * 1024

	if server.MaxRepoSize > 0 {
		log.Printf("Initializing quota (can take a while)...")
		qm, err := quota.New(server.Path, server.MaxRepoSize)
		if err != nil {
			return nil, err
		}
		server.quotaManager = qm
		log.Printf("Quota initialized, currently using %.2f GiB", float64(qm.SpaceUsed())/GiB)
	}

	mux := http.NewServeMux()
	if server.Prometheus {
		if server.PrometheusNoAuth {
			mux.Handle("/metrics", promhttp.Handler())
		} else {
			mux.HandleFunc("/metrics", server.wrapMetricsAuth(promhttp.Handler().ServeHTTP))
		}
	}

	if len(server.KeyTabFile) > 0 {
		// Try to load the service keytab
		kt, err := keytab.Load(server.KeyTabFile)
		if err != nil {
			return nil, fmt.Errorf("cannot load given keytab file: %v", err)
		}

		mux.Handle("/", spnego.SPNEGOKRB5Authenticate(server, kt))
	} else {
		mux.Handle("/", server)
	}

	var handler http.Handler = mux
	if server.Debug {
		handler = server.debugHandler(handler)
	}
	if server.Log != "" {
		handler = server.logHandler(handler)
	}
	return handler, nil
}
