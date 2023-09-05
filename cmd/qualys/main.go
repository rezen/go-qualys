package main

import (
	"encoding/json"
	"fmt"

	"github.com/antchfx/xmlquery"
	retryablehttp "github.com/hashicorp/go-retryablehttp"
	q "github.com/rezen/go-qualys"
)

func main() {

	// httpClient :=  &http.Client{Timeout: 20 * time.Second},
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	httpClient := retryClient.StandardClient()

	qualys := &q.QualysClient{
		ApiUrl:     "",
		Username:   "",
		Password:   ``,
		HttpClient: httpClient,
	}

	var downloadReport q.Report
	reports, _ := qualys.ReportsList()

	for _, report := range reports {
		if report.Title == "Report Name" {
			downloadReport = report
			break
		}
	}
	reportData, _ := qualys.ReportById(downloadReport.ID)

	doc, err := xmlquery.Parse(reportData)

	if err != nil {
		panic(err)
	}

	hosts := q.ParseHosts(doc)
	vulnDetails := q.ParseVulnDetailsReport(doc)
	vulns := q.CoalesceHostVulnerabilities(hosts, vulnDetails)

	data, _ := json.MarshalIndent(vulns, "", "    ")

	fmt.Println(string(data))

	/*
		hosts, err := qualys.HostsList()
		fmt.Println(err)
		data, _ := json.MarshalIndent(hosts, "", "    ")
		fmt.Println(string(data))
	*/

}
