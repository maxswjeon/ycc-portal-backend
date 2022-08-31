package utils

type User struct {
	DN string
  Uid string
  Cn string
  Sn string
  Gn string
  Mail string
  UidNumber int
  StudentGender string
  StudentBirthday string
  TelephoneNumber string
  StudentColleage string
  StudentFirstMajor string
  StudentMajor string
  StudentEnrolled bool
  StudentGraduated bool
}

type UserSlim struct {
	DN string
	Uid string
	Cn string
	Mail string
	UidNumber int
}
