package qualys

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/antchfx/xmlquery"
)

type QualysClient struct {
	ApiUrl     string
	Username   string
	Password   string
	HttpClient *http.Client
}

func (q *QualysClient) prepareRequest(req *http.Request) *http.Request {
	req.SetBasicAuth(q.Username, q.Password)
	req.Header.Add("X-Requested-With", "golang/net/http")
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	return req
}

func (q *QualysClient) ReportsList() ([]Report, error) {
	form := url.Values{}
	form.Add("action", "list")

	req, err := http.NewRequest("POST", q.ApiUrl+"/api/2.0/fo/report/", strings.NewReader(form.Encode()))

	req = q.prepareRequest(req)
	res, err := q.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	doc, err := xmlquery.Parse(strings.NewReader(string(resBody)))
	return ParseReportList(doc), err
}

func (q *QualysClient) ReportById(id string) (*bytes.Reader, error) {
	form := url.Values{}
	form.Add("action", "fetch")
	form.Add("id", id)

	req, err := http.NewRequest("POST", q.ApiUrl+"/api/2.0/fo/report/", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req = q.prepareRequest(req)
	res, err := q.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(resBody), nil
}

type Pager struct {
	Url            url.URL
	Form           url.Values
	NextPage       func(req *http.Request)
	HandleResponse func(res *http.Response)
}

type HostsQuery struct{}

func (q *QualysClient) HostsList() ([]Host, error) {
	limit := 100
	form := url.Values{}
	form.Add("action", "list")
	form.Add("truncation_limit", strconv.Itoa(limit))
	form.Add("id_min", "0")
	form.Add("details", "All/AGs")

	allHosts := []Host{}
	for {
		req, err := http.NewRequest("POST", q.ApiUrl+"/api/2.0/fo/asset/host/", strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req = q.prepareRequest(req)

		res, err := q.HttpClient.Do(req)
		if err != nil {
			return nil, err
		}

		defer res.Body.Close()

		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		doc, err := xmlquery.Parse(strings.NewReader(string(resBody)))
		if err != nil {
			return nil, err
		}

		hosts := ParseHosts(doc)
		allHosts = append(allHosts, hosts...)

		if len(hosts) != limit {
			break
		}

		lastHostId, _ := strconv.Atoi(hosts[len(hosts)-1].HostId)
		form.Set("id_min", strconv.Itoa(lastHostId+1))
	}

	return allHosts, nil
}
