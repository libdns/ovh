package ovh

import (
	"context"

	"github.com/libdns/libdns"
)

// Provider implements the libdns interfaces for OVH.
type Provider struct {
	Endpoint          string `json:"endpoint,omitempty"`
	ApplicationKey    string `json:"application_key,omitempty"`
	ApplicationSecret string `json:"application_secret,omitempty"`
	ConsumerKey       string `json:"consumer_key,omitempty"`
	client            Client
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	records, err := p.getRecords(ctx, unFQDN(zone))
	if err != nil {
		return nil, err
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var appended []libdns.Record

	zone = unFQDN(zone)
	for _, record := range records {
		rec, err := p.addRecord(ctx, zone, record)
		if err != nil {
			return nil, err
		}
		appended = append(appended, rec)
	}

	if len(appended) > 0 {
		if err := p.refreshZone(ctx, zone); err != nil {
			return nil, err
		}
	}

	return appended, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the setted records, if not existing in the zone.
// This implementation isn't atomic, mostly due how ovh api handle records
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zone = unFQDN(zone)

	setted, err := p.setRecords(ctx, zone, records)
	if err != nil {
		return nil, err
	}

	if len(setted) > 0 {
		if err := p.refreshZone(ctx, zone); err != nil {
			return nil, err
		}
	}

	return setted, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record

	zone = unFQDN(zone)
	for _, record := range records {
		recs, err := p.deleteRecords(ctx, zone, record)
		if err != nil {
			return nil, err
		}
		deleted = append(deleted, recs...)
	}

	if len(deleted) > 0 {
		if err := p.refreshZone(ctx, zone); err != nil {
			return nil, err
		}
	}

	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
