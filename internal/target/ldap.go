package target

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"rdpshot/internal/model"
)

// LDAPOptions configures Active Directory domain target discovery.
type LDAPOptions struct {
	Server   string        // Host or Host:Port of the domain controller
	Domain   string        // DNS domain name, e.g. "corp.example.com"
	Username string        // User for simple bind (e.g. "user" or "user@corp.example.com")
	Password string        // Password for bind
	BaseDN   string        // Base DN; auto-generated from Domain if empty
	Filter   string        // Custom LDAP search filter (optional)
	Port     uint16        // Default RDP port to assign to discovered hosts (default 3389)
	Timeout  time.Duration // Connection timeout (default 10s)
	UseSSL   bool          // Use LDAPS (port 636)
}

// DefaultLDAPFilter searches for computer accounts with Terminal Services SPNs or Server OS.
const DefaultLDAPFilter = "(|(servicePrincipalName=TERMSRV/*)(&(objectCategory=computer)(operatingSystem=*Server*)))"

// DomainToBaseDN converts a DNS domain name (e.g. "corp.example.com") into
// an Active Directory Base DN (e.g. "DC=corp,DC=example,DC=com").
func DomainToBaseDN(domain string) string {
	domain = strings.Trim(domain, ".")
	if domain == "" {
		return ""
	}
	parts := strings.Split(domain, ".")
	var dcParts []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			dcParts = append(dcParts, "DC="+p)
		}
	}
	return strings.Join(dcParts, ",")
}

// DiscoverLDAP connects to an Active Directory domain controller and queries
// computer objects registered with RDP SPNs (TERMSRV/*) or Windows Server OS.
func DiscoverLDAP(opts LDAPOptions) ([]model.Endpoint, error) {
	server := strings.TrimSpace(opts.Server)
	if server == "" {
		if opts.Domain != "" {
			server = opts.Domain
		} else {
			return nil, fmt.Errorf("ldap: server or domain must be specified")
		}
	}

	port := 389
	if opts.UseSSL {
		port = 636
	}

	host := server
	if h, pStr, err := net.SplitHostPort(server); err == nil {
		host = h
		if pNum, err := strconv.Atoi(pStr); err == nil && pNum > 0 {
			port = pNum
		}
	}

	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var conn *ldap.Conn
	var err error

	if opts.UseSSL {
		tlsConf := &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			ServerName:         host,
		}
		conn, err = ldap.DialURL(fmt.Sprintf("ldaps://%s", targetAddr),
			ldap.DialWithTLSConfig(tlsConf),
			ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	} else {
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s", targetAddr),
			ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	}

	if err != nil {
		return nil, fmt.Errorf("ldap: dial %s: %w", targetAddr, err)
	}
	defer conn.Close()

	// Authentication (Bind)
	username := strings.TrimSpace(opts.Username)
	if username != "" {
		bindUser := username
		if opts.Domain != "" && !strings.Contains(username, "@") && !strings.Contains(username, "\\") {
			bindUser = username + "@" + opts.Domain
		}
		if err := conn.Bind(bindUser, opts.Password); err != nil {
			return nil, fmt.Errorf("ldap: bind as %q: %w", bindUser, err)
		}
	} else {
		// Unauthenticated bind
		if err := conn.UnauthenticatedBind(""); err != nil {
			// Some AD environments disallow unauthenticated binds
			return nil, fmt.Errorf("ldap: unauthenticated bind failed: %w", err)
		}
	}

	baseDN := strings.TrimSpace(opts.BaseDN)
	if baseDN == "" && opts.Domain != "" {
		baseDN = DomainToBaseDN(opts.Domain)
	}
	if baseDN == "" {
		// Try to query rootDSE to find defaultNamingContext
		rootReq := ldap.NewSearchRequest(
			"",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{"defaultNamingContext"},
			nil,
		)
		if sr, err := conn.Search(rootReq); err == nil && len(sr.Entries) > 0 {
			baseDN = sr.Entries[0].GetAttributeValue("defaultNamingContext")
		}
	}
	if baseDN == "" {
		return nil, fmt.Errorf("ldap: could not determine base DN; specify domain or baseDN")
	}

	filter := strings.TrimSpace(opts.Filter)
	if filter == "" {
		filter = DefaultLDAPFilter
	}

	rdpPort := opts.Port
	if rdpPort == 0 {
		rdpPort = 3389
	}

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,   // no size limit
		120, // 2 minutes time limit
		false,
		filter,
		[]string{"dNSHostName", "name", "sAMAccountName", "operatingSystem", "servicePrincipalName"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap: search failed: %w", err)
	}

	seen := make(map[string]bool)
	var endpoints []model.Endpoint

	for _, entry := range sr.Entries {
		dnsHost := strings.TrimSpace(entry.GetAttributeValue("dNSHostName"))
		name := strings.TrimSpace(entry.GetAttributeValue("name"))

		targetHost := dnsHost
		if targetHost == "" {
			if name != "" && opts.Domain != "" {
				targetHost = name + "." + opts.Domain
			} else {
				targetHost = name
			}
		}

		if targetHost == "" {
			continue
		}

		key := strings.ToLower(targetHost) + ":" + strconv.Itoa(int(rdpPort))
		if seen[key] {
			continue
		}
		seen[key] = true

		endpoints = append(endpoints, model.Endpoint{
			Address: targetHost,
			Port:    rdpPort,
		})
	}

	return endpoints, nil
}
