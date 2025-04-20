package ovh

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/libdns/libdns"
	"github.com/ovh/go-ovh/ovh"
)

type Client struct {
	ovh   *ovh.Client
	mutex sync.Mutex
}

func (p *Provider) setupClient() error {
	if p.client.ovh == nil {
		client, err := ovh.NewClient(p.Endpoint, p.ApplicationKey, p.ApplicationSecret, p.ConsumerKey)
		if err != nil {
			return err
		}

		p.client.ovh = client
	}

	return nil
}

func (p *Provider) getRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	ids, err := p.getAllRecordsIDs(ctx, zone)
	if err != nil {
		return nil, err
	}

	var records []libdns.Record
	for _, id := range ids {
		rec, err := p.getRecordByID(ctx, zone, id)
		if err != nil {
			return nil, err
		}

		records = append(records, rec)
	}

	return records, nil
}

func (p *Provider) getAllRecordsIDs(ctx context.Context, zone string) ([]int64, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return nil, err
	}

	var ids []int64
	if err := p.client.ovh.GetWithContext(ctx, fmt.Sprintf("/domain/zone/%s/record", zone), &ids); err != nil {
		return nil, err
	}

	return ids, nil
}

func (p *Provider) getRecordByID(ctx context.Context, zone string, id int64) (libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return nil, err
	}

	var ovhRec ovhRecord
	if err := p.client.ovh.GetWithContext(ctx, fmt.Sprintf("/domain/zone/%s/record/%d", zone, id), &ovhRec); err != nil {
		return nil, err
	}

	return ovhRec.libdnsRecord()
}

func (p *Provider) addRecord(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return nil, err
	}

	ovhRec, err := toOvhRecord(record)
	if err != nil {
		return nil, err
	}

	if ovhRec.FieldType == "" {
		return nil, fmt.Errorf("type of record not specified")
	}

	var ovhRecAdded ovhRecord
	if err := p.client.ovh.PostWithContext(ctx, fmt.Sprintf("/domain/zone/%s/record", zone), ovhRec, &ovhRecAdded); err != nil {
		return nil, err
	}

	return ovhRecAdded.libdnsRecord()
}

func (p *Provider) setRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	setted := []libdns.Record{}
	recList := map[string][]libdns.Record{}

	for _, rec := range records {
		mRec := rec.RR()
		pair := fmt.Sprintf("%s/%s", mRec.Name, mRec.Type)

		if _, ok := recList[pair]; !ok {
			mRec.Data = ""
			founded, err := p.findRecords(ctx, zone, mRec)
			if err != nil {
				return nil, err
			}

			recList[pair] = []libdns.Record{}

			for idf, recf := range founded {
				exists := false
				for _, recs := range records {
					if libdnsRecordEqual(recf, recs) {
						exists = true
						break
					}
				}
				if !exists {
					if err := p.deleteRecordByID(ctx, zone, idf); err != nil {
						return nil, err
					}
				} else {
					recList[pair] = append(recList[pair], recf)
				}
			}
		}

		exists := false
		for _, recs := range recList[pair] {
			if libdnsRecordEqual(rec, recs) {
				exists = true
				break
			}
		}
		if !exists {
			reca, err := p.addRecord(ctx, zone, rec)
			if err != nil {
				return nil, err
			}
			setted = append(setted, reca)
		}

	}

	return setted, nil
}

func (p *Provider) deleteRecords(ctx context.Context, zone string, record libdns.Record) ([]libdns.Record, error) {
	founded, err := p.findRecords(ctx, zone, record)
	if err != nil {
		return nil, err
	}

	deleted := []libdns.Record{}
	for id, rec := range founded {
		if err := p.deleteRecordByID(ctx, zone, id); err != nil {
			return nil, err
		}
		deleted = append(deleted, rec)
	}

	return deleted, nil
}

func (p *Provider) deleteRecordByID(ctx context.Context, zone string, id int64) error {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return err
	}

	return p.client.ovh.DeleteWithContext(ctx, fmt.Sprintf("/domain/zone/%s/record/%d", zone, id), nil)
}

func (p *Provider) findRecords(ctx context.Context, zone string, record libdns.Record) (map[int64]libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return nil, err
	}

	ovhMatchRec, err := toOvhRecord(record)
	if err != nil {
		return nil, err
	}

	founded := map[int64]libdns.Record{}

	var ids []int64
	if err := p.client.ovh.GetWithContext(ctx, fmt.Sprintf("/domain/zone/%s/record?fieldType=%s&subDomain=%s", zone, ovhMatchRec.FieldType, ovhMatchRec.SubDomain), &ids); err != nil {
		return nil, err
	}

	for _, id := range ids {
		var ovhCurrentRec ovhRecord
		if err := p.client.ovh.GetWithContext(ctx, fmt.Sprintf("/domain/zone/%s/record/%d", zone, id), &ovhCurrentRec); err != nil {
			return nil, err
		}

		currentRec, err := ovhCurrentRec.libdnsRecord()
		if err != nil {
			return nil, err
		}

		if libdnsRecordMatch(record, currentRec) {
			founded[ovhCurrentRec.ID] = currentRec
		}
	}

	return founded, nil
}

func (p *Provider) refreshZone(ctx context.Context, zone string) error {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return err
	}

	if err := p.client.ovh.PostWithContext(ctx, fmt.Sprintf("/domain/zone/%s/refresh", zone), nil, nil); err != nil {
		return err
	}

	return nil
}

func unFQDN(fqdn string) string {
	return strings.TrimSuffix(fqdn, ".")
}
