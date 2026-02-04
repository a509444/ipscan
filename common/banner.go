package common

import "fmt"

const LOGO = `
  _       _____                      
 (_)___  / ___/_________ _____  _____
/ / __ \/ __ \/ ___/ __ / __ \/ ___/
/ / /_/ / /_/ (__  ) /_/ / / / / /__  
/_/ .___/ .___/____/\__,_/_/ /_/\___/  
  /_/   /_/                             
`

func GetBanner() string {
	banner := fmt.Sprintf("%s%s\n\n", LOGO, GetVersion())
	return banner
}
