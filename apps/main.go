package main

import (
	"fmt"

	confidential "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

func main() {
	cred, err := confidential.NewCredFromSecret("client_secret")
	if err != nil {
		return nil, fmt.Errorf("could not create a cred from a secret: %w", err)
	}

	confidentialClientApp, err := confidential.New("client_id", cred, confidential.WithAuthority("https://login.microsoft.com/Enter_The_Tenant_Name_Here"))

}
