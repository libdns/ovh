package ovh_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/ovh"
)

var (
	endPoint          = ""
	applicationKey    = ""
	applicationSecret = ""
	consumerKey       = ""
	zone              = ""
)

func TestMain(m *testing.M) {
	endPoint = os.Getenv("LIBDNS_OVH_TEST_ENDPOINT")
	applicationKey = os.Getenv("LIBDNS_OVH_TEST_APPLICATION_KEY")
	applicationSecret = os.Getenv("LIBDNS_OVH_TEST_APPLICATION_SECRET")
	consumerKey = os.Getenv("LIBDNS_OVH_TEST_CONSUMER_KEY")
	zone = os.Getenv("LIBDNS_OVH_TEST_ZONE")
	if len(endPoint) == 0 || len(applicationKey) == 0 || len(applicationSecret) == 0 || len(consumerKey) == 0 || len(zone) == 0 {
		fmt.Println(`Please notice that this test runs agains the public OVH DNS API, so you should NEVER run the test with a zone used in production.`)
		fmt.Println(`To run this test, you have to specify the environment variables specified in provider_test.go`)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestGetRecords(t *testing.T) {
	provider := &ovh.Provider{
		Endpoint:          endPoint,
		ApplicationKey:    applicationKey,
		ApplicationSecret: applicationSecret,
		ConsumerKey:       consumerKey,
	}

	records, err := provider.GetRecords(context.TODO(), zone)
	if err != nil {
		t.Fatal(err)
	}

	for _, rec := range records {
		t.Logf("%#v", rec)
	}
}

var appendRecords []libdns.Record = []libdns.Record{
	libdns.Address{Name: "ttl0", TTL: 0 * time.Second, IP: netip.MustParseAddr("1.2.3.4")},
	libdns.CNAME{Name: "redirect", TTL: 3 * time.Minute, Target: "example.com."},
	libdns.TXT{Name: "_escaped_text", TTL: 3 * time.Minute, Text: `quotes " backslashes \000 del: \x7F`},
}

func TestAppendRecords(t *testing.T) {
	provider := &ovh.Provider{
		Endpoint:          endPoint,
		ApplicationKey:    applicationKey,
		ApplicationSecret: applicationSecret,
		ConsumerKey:       consumerKey,
	}

	appended, err := provider.AppendRecords(context.TODO(), zone, appendRecords)
	if err != nil {
		t.Fatal(err)
	}

	if len(appended) != len(appendRecords) {
		t.Fatalf("len(appended) < len(appendRecords) => %d < %d", len(appended), len(appendRecords))
	}

	for _, rec := range appended {
		t.Logf("%#v", rec)
	}

	if _, err := provider.AppendRecords(context.TODO(), zone, []libdns.Record{libdns.RR{Name: "empty"}}); err == nil {
		t.Fatal("expecting append failing if record type wasn't set")
	}
}

func TestDeleteRecords(t *testing.T) {
	provider := &ovh.Provider{
		Endpoint:          endPoint,
		ApplicationKey:    applicationKey,
		ApplicationSecret: applicationSecret,
		ConsumerKey:       consumerKey,
	}

	deleted, err := provider.DeleteRecords(context.TODO(), zone, appendRecords)
	if err != nil {
		t.Fatal(err)
	}

	for _, rec := range deleted {
		t.Logf("%#v", rec)
	}
}

func TestSetRecordsExample1(t *testing.T) {
	provider := &ovh.Provider{
		Endpoint:          endPoint,
		ApplicationKey:    applicationKey,
		ApplicationSecret: applicationSecret,
		ConsumerKey:       consumerKey,
	}

	origRecords := []libdns.Record{
		libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.1")},
		libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.2")},
		libdns.TXT{Name: "@", Text: "hello world"},
	}

	_, err := provider.SetRecords(context.TODO(), zone, origRecords)
	if err != nil {
		t.Fatal(err)
	}

	inputRecords := []libdns.Record{
		libdns.Address{Name: "@", IP: netip.MustParseAddr("192.0.2.3")},
	}

	setted, err := provider.SetRecords(context.TODO(), zone, inputRecords)
	if err != nil {
		t.Fatal(err)
	}

	for _, rec := range setted {
		t.Logf("%#v", rec)
	}

	if len(setted) != 1 {
		t.Fatalf("expecting 1 modified record in the zone, not %d", len(setted))
	}

	provider.DeleteRecords(context.TODO(), zone, origRecords)
	provider.DeleteRecords(context.TODO(), zone, inputRecords)
}

func TestSetRecordsExample2(t *testing.T) {
	provider := &ovh.Provider{
		Endpoint:          endPoint,
		ApplicationKey:    applicationKey,
		ApplicationSecret: applicationSecret,
		ConsumerKey:       consumerKey,
	}

	origRecords := []libdns.Record{
		libdns.Address{Name: "a", IP: netip.MustParseAddr("2001:db8::1")},
		libdns.Address{Name: "a", IP: netip.MustParseAddr("2001:db8::2")},
		libdns.Address{Name: "b", IP: netip.MustParseAddr("2001:db8::3")},
		libdns.Address{Name: "b", IP: netip.MustParseAddr("2001:db8::4")},
	}

	_, err := provider.SetRecords(context.TODO(), zone, origRecords)
	if err != nil {
		t.Fatal(err)
	}

	inputRecords := []libdns.Record{
		libdns.Address{Name: "a", IP: netip.MustParseAddr("2001:db8::1")},
		libdns.Address{Name: "a", IP: netip.MustParseAddr("2001:db8::2")},
		libdns.Address{Name: "a", IP: netip.MustParseAddr("2001:db8::5")},
	}

	setted, err := provider.SetRecords(context.TODO(), zone, inputRecords)
	if err != nil {
		t.Fatal(err)
	}

	for _, rec := range setted {
		t.Logf("%#v", rec)
	}

	if len(setted) != 1 {
		t.Fatalf("expecting 1 modified record in the zone, not %d", len(setted))
	}

	provider.DeleteRecords(context.TODO(), zone, origRecords)
	provider.DeleteRecords(context.TODO(), zone, inputRecords)
}

func TestGetRecordsFinal(t *testing.T) {
	provider := &ovh.Provider{
		Endpoint:          endPoint,
		ApplicationKey:    applicationKey,
		ApplicationSecret: applicationSecret,
		ConsumerKey:       consumerKey,
	}

	records, err := provider.GetRecords(context.TODO(), zone)
	if err != nil {
		t.Fatal(err)
	}

	for _, rec := range records {
		t.Logf("%#v", rec)
	}
}
