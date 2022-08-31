package handlers

import (
	"encoding/csv"
	"fmt"
	"io"
	"lmm_backend/utils"
	"mime/multipart"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func CSV(conn *ldap.Conn, r *multipart.File) (bool, []utils.Message) {
	logData := []utils.Message{}
	// Handle CSV
	logData = append(logData, utils.Message{
		Message: "CSV File Detected",
		Type: utils.INFO,
	})

	reader := csv.NewReader(*r)

	header, err := reader.Read();
	if err != nil {
		logData = append(logData, utils.Message{
			Message: "Error while reading header",
			Type: utils.ERROR,
		})

		return false, logData
	}

	if strings.HasPrefix(header[0], string([]byte{0xEF, 0xBB, 0xBF})) {
		header[0] = header[0][3:]
	}
	
	index := map[string]int {
		"uid": utils.HeaderIndex(header, "uid", "username", "아아디"),
		"sn": utils.HeaderIndex(header, "sn", "surname", "lastname", "familyName", "family name", "last name", "성"),
		"gn": utils.HeaderIndex(header, "gn", "givenName", "given name", "firstname", "first name", "이름"),
		"uidNumber": utils.HeaderIndex(header, "uidNumber", "uid number", "student number", "학번"),
		"telephoneNumber": utils.HeaderIndex(header, "telephoneNumber", "telephone number", "phone number", "phone", "전화번호"),
		"mail": utils.HeaderIndex(header, "mail", "email", "studentMail", "studentEmail", "이메일"),
		"birthday": utils.HeaderIndex(header, "birthday", "studentBirthday",  "생일"),
		"gender": utils.HeaderIndex(header, "gender", "studentGender", "성별"),
		"colleage": utils.HeaderIndex(header, "colleage", "studentColleage", "단과대", "소속 단과대"),
		"majors": utils.HeaderIndex(header, "major", "majors", "studentMajor","studentMajors","전공", "제1전공", "제 1전공", "제 1 전공", "주전공"),
		"enrolled": utils.HeaderIndex(header, "enrolled", "studentEnrolled", "재학여부"),
		"graduated": utils.HeaderIndex(header, "graduated", "studentGraduated", "졸업여부"),
	}

	for k, v := range index {
		if v == -1 {
			logData = append(logData, utils.Message{
				Message: "Column " + k + " not found",
				Type: utils.ERROR,
			})
		}
	}

	for _, v := range index {
		if v == -1 {
			return false, logData
		}
	}
		
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			logData = append(logData, utils.Message{
				Message: "Error while reading record",
				Type: utils.ERROR,
			})

			return false, logData
		}

		data := map[string]string{
			"uid": record[index["uid"]],
			"sn": record[index["sn"]],
			"gn": record[index["gn"]],
			"uidNumber": record[index["uidNumber"]],
			"telephoneNumber": record[index["telephoneNumber"]],
			"mail": record[index["mail"]],
			"birthday": record[index["birthday"]],
			"gender": record[index["gender"]],
			"colleage": record[index["colleage"]],
			"majors": record[index["majors"]],
			"enrolled": record[index["enrolled"]],
			"graduated": record[index["graduated"]],
		}

		isDirty := false
		for k, v := range data {
			if v == "" {
				logData = append(logData, utils.Message{
					Message: fmt.Sprintf("Column %s is empty for %s, skipping", k, data["uidNumber"]),
					Type: utils.WARN,
				})
				isDirty = true
				break
			}
		}

		if isDirty {
			continue
		}

		result, err := utils.LDAPCheckUser(conn, record[index["uid"]])
		if err != nil {
			logData = append(logData, utils.Message{
				Message: fmt.Sprintf("Error while checking user %s", record[index["uid"]]),
				Type: utils.ERROR,
			})
			continue
		}

		if len(result.Entries) > 0 {
			logData = append(logData, utils.Message{
				Message: fmt.Sprintf("User %s already exists", record[index["uid"]]),
				Type: utils.WARN,
			})
			continue
		}

		password, hash := utils.LDAPGeneratePassword()

		enrolled, err := strconv.ParseBool(record[index["enrolled"]])
		if err != nil {
			logData = append(logData, utils.Message{
				Message: fmt.Sprintf("Error while parsing enrolled value %s", record[index["enrolled"]]),
				Type: utils.ERROR,
			})
			continue
		}

		graduated, err := strconv.ParseBool(record[index["graduated"]])
		if err != nil {
			logData = append(logData, utils.Message{
				Message: fmt.Sprintf("Error while parsing graduated value %s", record[index["graduated"]]),
				Type: utils.ERROR,
			})
			continue
		}
		
		err = utils.LDAPAddUser(conn,
			record[index["uid"]],
			record[index["sn"]],
			record[index["gn"]],
			record[index["uidNumber"]],
			record[index["telephoneNumber"]],
			record[index["mail"]],
			record[index["birthday"]],
			record[index["gender"]],
			record[index["colleage"]],
			record[index["majors"]],
			enrolled,
			graduated,
			password,
			hash,
		)
		if err != nil {
			logData = append(logData, utils.Message{
				Message: fmt.Sprintf("Error while adding user %s", record[index["uid"]]),
				Type: utils.ERROR,
			})
			continue
		}

		err = utils.SendInitialPasswordMail(strings.Split(record[index["mail"]], ",")[0], record[index["uid"]], password)
		if err != nil {
			logData = append(logData, utils.Message{
				Message: fmt.Sprintf("Error while sending initial password mail to %s", record[index["mail"]]),
				Type: utils.ERROR,
			})
			continue
		}
	}

	return true, logData
}
