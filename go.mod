module github.com/rikatz/ingress-security-agent

go 1.15

require (
	github.com/criteo/haproxy-spoe-go v1.0.1
	github.com/rikatz/go-modsecurity v0.0.0-20201120175059-e357e488078d
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1 // indirect
	golang.org/x/sys v0.0.0-20201119102817-f84b799fce68 // indirect
)

replace github.com/rikatz/go-modsecurity => /home/rkatz/git/go-modsecurity
