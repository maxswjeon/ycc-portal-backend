package utils

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func LDAPConnectAndBind(dn string, pw string) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(os.Getenv("LDAP_DOMAIN"))
	if err != nil {
		return nil, err
	}

	conn.Bind(dn, pw)

	return conn, nil
}

func LDAPGeneratePassword() (string, string) {
	rawPass := make([]byte, 24)
	rand.Read(rawPass)

	password := base64.StdEncoding.EncodeToString(rawPass)
	
	encoder := SSHAEncoder{}
	hash := encoder.Encode([]byte(password))
	
	return password, hash
}

func LDAPAddUser(conn *ldap.Conn, uid string, sn string, gn string, uidNumber string, telephoneNumber string, mail string, birthday string, gender string, colleage string, majors string, enrolled bool, graduated bool, password string, hash string) (error) {
	// sambaSID Length 64 -> 48bit to base64
	sambaSIDBytes := make([]byte, 48)
	rand.Read(sambaSIDBytes)
	sambaSID := base64.StdEncoding.EncodeToString(sambaSIDBytes)
	
	addRequest := ldap.NewAddRequest("uid="+uid+",ou=people,"+os.Getenv("LDAP_BASE_DN"), nil)
	addRequest.Attribute("objectClass", []string{"inetOrgPerson", "organizationalPerson", "person", "student", "PostfixBookMailAccount", "sambaSamAccount"})
	addRequest.Attribute("cn", []string{sn + gn})
	addRequest.Attribute("sn", []string{sn})
	addRequest.Attribute("givenName", []string{gn})
	addRequest.Attribute("uid", []string{uid})
	addRequest.Attribute("mail", []string{uid + "@" + os.Getenv("DOMAIN")})
	addRequest.Attribute("uidNumber", []string{uidNumber})
	addRequest.Attribute("telephoneNumber", []string{telephoneNumber})
	addRequest.Attribute("studentBirthday", []string{birthday})
	addRequest.Attribute("studentColleage", []string{colleage})
	addRequest.Attribute("studentFirstMajor", []string{strings.Split(majors, ",")[0]})
	addRequest.Attribute("studentMajor", strings.Split(majors, ","))
	addRequest.Attribute("studentEmail", strings.Split(mail, " "))
	addRequest.Attribute("studentGender", []string{gender})
	addRequest.Attribute("studentEnrolled", []string{strings.ToUpper(strconv.FormatBool(enrolled))})
	addRequest.Attribute("studentGraduated", []string{strings.ToUpper(strconv.FormatBool(graduated))})
	addRequest.Attribute("userPassword", []string{hash})
	addRequest.Attribute("sambaSID", []string{sambaSID})
	addRequest.Attribute("sambaNTPassword", []string{"{nt}" + NTLMHash(password)})
	

	if err := conn.Add(addRequest); err != nil {
		return err
	}

	return nil
}

func LDAPCheckUser(conn *ldap.Conn, uid string) (*ldap.SearchResult, error) {
	searchRequest := ldap.NewSearchRequest(
		os.Getenv("LDAP_BASE_DN"),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,     // SizeLimit
		30,    // TimeLimit
		false, // TypesOnly
		"(&(objectClass=student)(uid="+uid+"))", // Filter
		[]string{"dn", "cn", "uid", "studentEmail", "uidNumber"},
		nil, // Controls
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func LDAPGetGroups(conn *ldap.Conn) (*ldap.SearchResult, error) {
	searchRequest := ldap.NewSearchRequest(
		os.Getenv("LDAP_BASE_DN"),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,     // SizeLimit
		30,    // TimeLimit
		false, // TypesOnly
		"(&(objectClass=groupOfNames))", // Filter
		[]string{"cn", "member", "description"},
		nil, // Controls
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	return result, nil
}
