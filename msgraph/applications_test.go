package msgraph_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/manicminer/hamilton/auth"
	"github.com/manicminer/hamilton/internal/test"
	"github.com/manicminer/hamilton/internal/utils"
	"github.com/manicminer/hamilton/msgraph"
)

type ApplicationsClientTest struct {
	connection   *test.Connection
	client       *msgraph.ApplicationsClient
	randomString string
}

const certificateData string = `-----BEGIN CERTIFICATE-----
MIIDCjCCAfICCQCJOOUlBxUxWDANBgkqhkiG9w0BAQsFADBHMQswCQYDVQQGEwJH
QjEWMBQGA1UECgwNV2lkZ2V0cywgSW5jLjEgMB4GA1UEAwwXd2lkZ2V0cy1hcHAt
Y2VydGlmaWNhdGUwHhcNMjEwNTE3MDkwMDA3WhcNMzEwNTE1MDkwMDA3WjBHMQsw
CQYDVQQGEwJHQjEWMBQGA1UECgwNV2lkZ2V0cywgSW5jLjEgMB4GA1UEAwwXd2lk
Z2V0cy1hcHAtY2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCsjxFwrV0MO5fUA/eeVSXc1h5uG7rAG5ClYYruWtE/W3mZLhGYVr4wK7d3
UrDFp4kh5V0avoBw9h7eOH39Ycx74Xfqz+5aBHcI55RK3Lf7NcmVu0yUiuUxx9Z7
B7IvKSOYoETxvLL31FYeRmpu01cWuzwioBfJotO2+eLe6h6nXzfkAg7/l1uMnAB4
wvcIIJSuh1Qp4LNfz0twxA7QDL1fhQGV+SDy0uMIj6+IzXI85MdZfZvOpCEffJjv
NVvyk3CtIDrCF+lXhHy2k7fp+Tvv2q5q4kWQGpNJlnOYB9TQ2AgQBQArvm+AjRiL
vMxiR8FD45npSCSgR2yLd9mVlxFzAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGeH
OWC2Z7V+fitTIQA5JgUsX6xs1hpGFkNZX0btRALSY1RMx50Nx+cImt0wNNh9+Tv7
16htG3TofNdC4P9dRK8SyivgaDtwgKWAHMzGlO891iahU/f9XEYH5ozczN8bcOPf
RIzgwf264lj6jmmSLAxTaMMBDGvKsas4A59iCUSBKk4r0pDal+tAYKZjHzEGGeWI
ImyRqWTm6sPrfeUB6PViReSibXJM5tUgUAE8YH7DmMadTrfLDB7hFV3vbNm2JkQw
ekf0R5MshXOcXl7dC9UcGyfLWk9prNJEKu3ZOM1S3y2xQLqEI2/c3ySlv1cw5vQq
svkIO1MgRxraNnGpybQ=
-----END CERTIFICATE-----`

func TestApplicationsClient(t *testing.T) {
	c := ApplicationsClientTest{
		connection:   test.NewConnection(auth.MsGraph, auth.TokenVersion2),
		randomString: test.RandomString(),
	}
	c.client = msgraph.NewApplicationsClient(c.connection.AuthConfig.TenantID)
	c.client.BaseClient.Authorizer = c.connection.Authorizer

	app := testApplicationsClient_Create(t, c, msgraph.Application{
		DisplayName: utils.StringPtr(fmt.Sprintf("test-application-%s", c.randomString)),
	})
	testApplicationsClient_Get(t, c, *app.ID)
	app.DisplayName = utils.StringPtr(fmt.Sprintf("test-app-updated-%s", c.randomString))
	testApplicationsClient_Update(t, c, *app)
	owners := testApplicationsClient_ListOwners(t, c, *app.ID)
	testApplicationsClient_GetOwner(t, c, *app.ID, (*owners)[0])
	testApplicationsClient_RemoveOwners(t, c, *app.ID, owners)
	app.AppendOwner(c.client.BaseClient.Endpoint, c.client.BaseClient.ApiVersion, (*owners)[0])
	testApplicationsClient_AddOwners(t, c, app)
	testApplicationsClient_AddKey(t, c, app)
	pwd := testApplicationsClient_AddPassword(t, c, app)
	testApplicationsClient_RemovePassword(t, c, app, pwd)
	testApplicationsClient_List(t, c)
	testApplicationsClient_Delete(t, c, *app.ID)
}

func TestApplicationsClient_groupMembershipClaims(t *testing.T) {
	c := ApplicationsClientTest{
		connection:   test.NewConnection(auth.MsGraph, auth.TokenVersion2),
		randomString: test.RandomString(),
	}
	c.client = msgraph.NewApplicationsClient(c.connection.AuthConfig.TenantID)
	c.client.BaseClient.Authorizer = c.connection.Authorizer

	app := testApplicationsClient_Create(t, c, msgraph.Application{
		DisplayName:           utils.StringPtr(fmt.Sprintf("test-application-%s", c.randomString)),
		GroupMembershipClaims: &[]msgraph.GroupMembershipClaim{"SecurityGroup", "ApplicationGroup"},
	})
	testApplicationsClient_Delete(t, c, *app.ID)
}

func testApplicationsClient_Create(t *testing.T, c ApplicationsClientTest, a msgraph.Application) (application *msgraph.Application) {
	application, status, err := c.client.Create(c.connection.Context, a)
	if err != nil {
		t.Fatalf("ApplicationsClient.Create(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ApplicationsClient.Create(): invalid status: %d", status)
	}
	if application == nil {
		t.Fatal("ApplicationsClient.Create(): application was nil")
	}
	if application.ID == nil {
		t.Fatal("ApplicationsClient.Create(): application.ID was nil")
	}
	return
}

func testApplicationsClient_Update(t *testing.T, c ApplicationsClientTest, a msgraph.Application) {
	status, err := c.client.Update(c.connection.Context, a)
	if err != nil {
		t.Fatalf("ApplicationsClient.Update(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ApplicationsClient.Update(): invalid status: %d", status)
	}
}

func testApplicationsClient_List(t *testing.T, c ApplicationsClientTest) (applications *[]msgraph.Application) {
	applications, _, err := c.client.List(c.connection.Context, "")
	if err != nil {
		t.Fatalf("ApplicationsClient.List(): %v", err)
	}
	if applications == nil {
		t.Fatal("ApplicationsClient.List(): applications was nil")
	}
	return
}

func testApplicationsClient_Get(t *testing.T, c ApplicationsClientTest, id string) (application *msgraph.Application) {
	application, status, err := c.client.Get(c.connection.Context, id)
	if err != nil {
		t.Fatalf("ApplicationsClient.Get(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ApplicationsClient.Get(): invalid status: %d", status)
	}
	if application == nil {
		t.Fatal("ApplicationsClient.Get(): application was nil")
	}
	return
}

func testApplicationsClient_Delete(t *testing.T, c ApplicationsClientTest, id string) {
	status, err := c.client.Delete(c.connection.Context, id)
	if err != nil {
		t.Fatalf("ApplicationsClient.Delete(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ApplicationsClient.Delete(): invalid status: %d", status)
	}
}

func testApplicationsClient_ListOwners(t *testing.T, c ApplicationsClientTest, id string) (owners *[]string) {
	owners, status, err := c.client.ListOwners(c.connection.Context, id)
	if err != nil {
		t.Fatalf("ApplicationsClient.ListOwners(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ApplicationsClient.ListOwners(): invalid status: %d", status)
	}
	if owners == nil {
		t.Fatal("ApplicationsClient.ListOwners(): owners was nil")
	}
	if len(*owners) == 0 {
		t.Fatal("ApplicationsClient.ListOwners(): owners was empty")
	}
	return
}

func testApplicationsClient_GetOwner(t *testing.T, c ApplicationsClientTest, appId string, ownerId string) (owner *string) {
	owner, status, err := c.client.GetOwner(c.connection.Context, appId, ownerId)
	if err != nil {
		t.Fatalf("ApplicationsClient.GetOwner(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ApplicationsClient.GetOwner(): invalid status: %d", status)
	}
	if owner == nil {
		t.Fatal("ApplicationsClient.GetOwner(): owner was nil")
	}
	return
}

func testApplicationsClient_AddOwners(t *testing.T, c ApplicationsClientTest, a *msgraph.Application) {
	status, err := c.client.AddOwners(c.connection.Context, a)
	if err != nil {
		t.Fatalf("ApplicationsClient.AddOwners(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ApplicationsClient.AddOwners(): invalid status: %d", status)
	}
}

func testApplicationsClient_RemoveOwners(t *testing.T, c ApplicationsClientTest, appId string, ownerIds *[]string) {
	status, err := c.client.RemoveOwners(c.connection.Context, appId, ownerIds)
	if err != nil {
		t.Fatalf("ApplicationsClient.RemoveOwners(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ApplicationsClient.RemoveOwners(): invalid status: %d", status)
	}
}

func testApplicationsClient_AddKey(t *testing.T, c ApplicationsClientTest, a *msgraph.Application) {
	key := msgraph.KeyCredential{
		DisplayName: utils.StringPtr("test certificate"),
		Key:         utils.StringPtr(base64.StdEncoding.EncodeToString([]byte(certificateData))),
		Type:        msgraph.KeyCredentialTypeAsymmetricX509Cert,
		Usage:       msgraph.KeyCredentialUsageVerify,
	}
	status, err := c.client.AddKey(c.connection.Context, *a.ID, key)
	if err != nil {
		t.Fatalf("ApplicationsClient.AddKey(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ApplicationsClient.AddKey(): invalid status: %d", status)
	}
}

func testApplicationsClient_AddPassword(t *testing.T, c ApplicationsClientTest, a *msgraph.Application) *msgraph.PasswordCredential {
	pwd := msgraph.PasswordCredential{
		DisplayName: utils.StringPtr("test password"),
	}
	newPwd, status, err := c.client.AddPassword(c.connection.Context, *a.ID, pwd)
	if err != nil {
		t.Fatalf("ApplicationsClient.AddPassword(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ApplicationsClient.AddPassword(): invalid status: %d", status)
	}
	if newPwd.SecretText == nil || len(*newPwd.SecretText) == 0 {
		t.Fatalf("ApplicationsClient.AddPassword(): nil or empty secretText returned by API")
	}
	return newPwd
}

func testApplicationsClient_RemovePassword(t *testing.T, c ApplicationsClientTest, a *msgraph.Application, p *msgraph.PasswordCredential) {
	status, err := c.client.RemovePassword(c.connection.Context, *a.ID, *p.KeyId)
	if err != nil {
		t.Fatalf("ApplicationsClient.RemovePassword(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ApplicationsClient.RemovePassword(): invalid status: %d", status)
	}
}
