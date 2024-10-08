package ovh

import (
	"context"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with OVH.
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
	var createdRecords []libdns.Record

	for _, record := range records {
		createdRecord, err := p.createRecord(ctx, unFQDN(zone), record)
		if err != nil {
			return nil, err
		}
		createdRecords = append(createdRecords, createdRecord)
	}

	if len(createdRecords) > 0 {
		if err := p.refresh(ctx, unFQDN(zone)); err != nil {
			return nil, err
		}
	}

	return createdRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var updatedRecords []libdns.Record

	for _, record := range records {
		updatedRecord, err := p.createOrUpdateRecord(ctx, unFQDN(zone), record)
		if err != nil {
			return nil, err
		}
		updatedRecords = append(updatedRecords, updatedRecord)
	}

	if len(updatedRecords) > 0 {
		if err := p.refresh(ctx, unFQDN(zone)); err != nil {
			return nil, err
		}
	}

	return updatedRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deletedRecords []libdns.Record

	for _, record := range records {
		deletedRecord, err := p.deleteRecord(ctx, unFQDN(zone), record)
		if err != nil {
			return nil, err
		}
		deletedRecords = append(deletedRecords, deletedRecord)
	}

	if len(deletedRecords) > 0 {
		if err := p.refresh(ctx, unFQDN(zone)); err != nil {
			return nil, err
		}
	}

	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
