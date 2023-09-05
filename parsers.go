package qualys

import (
	"github.com/antchfx/xmlquery"
	"strconv"
	"strings"
	"time"
)

func parseCves(n *xmlquery.Node) []IdUrl {
	results := []IdUrl{}
	for _, c := range xmlquery.Find(n, "CVE_ID_LIST/CVE_ID") {
		results = append(results, IdUrl{
			ID:  xmlquery.FindOne(c, "ID").InnerText(),
			Url: xmlquery.FindOne(c, "URL").InnerText(),
		})
	}
	return results
}

func parseVendors(n *xmlquery.Node) []IdUrl {
	results := []IdUrl{}
	for _, c := range xmlquery.Find(n, "VENDOR_REFERENCE_LIST/VENDOR_REFERENCE") {
		results = append(results, IdUrl{
			ID:  xmlquery.FindOne(c, "ID").InnerText(),
			Url: xmlquery.FindOne(c, "URL").InnerText(),
		})
	}
	return results
}

func ParseVulnDetailsReport(doc *xmlquery.Node) map[string]VulnDetails {
	vulnDetails := map[string]VulnDetails{}

	list, _ := xmlquery.QueryAll(doc, "//GLOSSARY/VULN_DETAILS_LIST/VULN_DETAILS")
	for _, n := range list {

		var lastUpdate time.Time
		lastUpdate, _ = time.Parse(time.RFC3339, xmlquery.FindOne(n, "LAST_UPDATE").InnerText())

		var severity int
		severity, _ = strconv.Atoi(xmlquery.FindOne(n, "SEVERITY").InnerText())

		details := VulnDetails{
			QID:              xmlquery.FindOne(n, "QID").InnerText(),
			Category:         xmlquery.FindOne(n, "CATEGORY").InnerText(),
			Title:            xmlquery.FindOne(n, "TITLE").InnerText(),
			Threat:           xmlquery.FindOne(n, "THREAT").InnerText(),
			Impact:           xmlquery.FindOne(n, "IMPACT").InnerText(),
			Solution:         xmlquery.FindOne(n, "SOLUTION").InnerText(),
			Severity:         severity,
			PciFlag:          xmlquery.FindOne(n, "PCI_FLAG").InnerText() == "1",
			CveIds:           parseCves(n),
			VendorReferences: parseVendors(n),
			LastUpdate:       lastUpdate,
		}
		vulnDetails[details.QID] = details

	}

	return vulnDetails

}

func parseHostVulns(n *xmlquery.Node) []VulnInfo {
	vulnerabilities := []VulnInfo{}
	for _, vuln := range xmlquery.Find(n, "VULN_INFO_LIST/VULN_INFO") {

		timesFound, _ := strconv.Atoi(xmlquery.FindOne(vuln, "TIMES_FOUND").InnerText())

		var lastFound time.Time
		lastFound, _ = time.Parse(time.RFC3339, xmlquery.FindOne(vuln, "LAST_FOUND").InnerText())

		vulnerabilities = append(vulnerabilities, VulnInfo{
			QID:        xmlquery.FindOne(vuln, "QID").InnerText(),
			Type:       xmlquery.FindOne(vuln, "TYPE").InnerText(),
			Result:     xmlquery.FindOne(vuln, "RESULT").InnerText(),
			VulnStatus: xmlquery.FindOne(vuln, "VULN_STATUS").InnerText(),
			TimesFound: timesFound,
			LastFound:  lastFound,
		})
	}
	return vulnerabilities
}

func parseBasicList(n *xmlquery.Node, xpath string) []string {
	items := []string{}
	for _, item := range xmlquery.Find(n, xpath) {
		items = append(items, item.InnerText())
	}
	return items
}

func ParseHosts(doc *xmlquery.Node) []Host {
	hosts := []Host{}
	list, _ := xmlquery.QueryAll(doc, "//HOST_LIST/HOST")
	resolvers := map[string]func(node *xmlquery.Node, h *Host){}

	resolvers["HOST_ID"] =  func(node *xmlquery.Node, h *Host) {
		h.HostId = node.InnerText()
	}

	resolvers["CLOUD_PROVIDER"] =  func(node *xmlquery.Node, h *Host) {
		h.CloudProvider = node.InnerText()
	}

	resolvers["CLOUD_SERVICE"] =  func(node *xmlquery.Node, h *Host) {
		h.CloudService = node.InnerText()
	}

	resolvers["CLOUD_RESOURCE_ID"] =  func(node *xmlquery.Node, h *Host) {
		h.CloudResourceId = node.InnerText()
	}

	resolvers["ID"] =  func(node *xmlquery.Node, h *Host) {
		h.HostId = node.InnerText()
	}
	resolvers["IP"] = func(node *xmlquery.Node, h *Host) {
	 	h.IP = node.InnerText()
	}

	resolvers["DNS"] = func(node *xmlquery.Node, h *Host) {
		h.DNS = node.InnerText()
	}

	resolvers["OPERATING_SYSTEM"] = func(node *xmlquery.Node, h *Host) {
		h.OperatingSystem = node.InnerText()
	}

	resolvers["OWNER"] = func(node *xmlquery.Node, h *Host) {
		h.Owner = node.InnerText()
	}

	resolvers["ASSET_GROUP_IDS"] = func(node *xmlquery.Node, h *Host) {
		h.AssetGroupIds = []int{}

		csv := strings.Split(node.InnerText(), ",")
		for _, val := range csv {
			id, err := strconv.Atoi(val)
			if err == nil {
				h.AssetGroupIds = append(h.AssetGroupIds, id)
			}
		}
	}

	for _, n := range list {
		host := Host{
			TrackingMethod:  xmlquery.FindOne(n, "TRACKING_METHOD").InnerText(),
			AssetGroups:     parseBasicList(n, "ASSET_GROUPS/ASSET_GROUP_TITLE"),
			AssetTags:       parseBasicList(n, "ASSET_TAGS/ASSET_TAG"),
			Vulnerabilities: parseHostVulns(n),
		}

		for query, resolver := range resolvers {
			node, _ := xmlquery.Query(n, query)
			if node != nil {
				resolver(node, &host)
			}
		}

		hosts = append(hosts, host)

	}
	return hosts
}

func CoalesceHostVulnerabilities(hosts []Host, vulnDetails map[string]VulnDetails) []HostVulnerabilty {
	vulnerabilities := []HostVulnerabilty{}

	for _, host := range hosts {
		for _, vuln := range host.Vulnerabilities {

			if details, ok := vulnDetails[vuln.QID]; ok {
				vulnerabilities = append(vulnerabilities, HostVulnerabilty{
					IP:              host.IP,
					HostId:          host.HostId,
					DNS:             host.DNS,
					TrackingMethod:  host.TrackingMethod,
					AssetTags:       host.AssetTags,
					AssetGroups:     host.AssetGroups,
					OperatingSystem: host.OperatingSystem,

					// Fields from VulnDetails
					QID:              details.QID,
					Title:            details.Title,
					Category:         details.Category,
					Severity:         details.Severity,
					Threat:           details.Threat,
					Impact:           details.Impact,
					Solution:         details.Solution,
					PciFlag:          details.PciFlag,
					CveIds:           details.CveIds,
					VendorReferences: details.VendorReferences,
					LastFound:        vuln.LastFound,
				})
			}
		}
	}

	return vulnerabilities

}



func ParseReportList(doc *xmlquery.Node) []Report {
	list, _ := xmlquery.QueryAll(doc, "//REPORT_LIST/REPORT")

	reports := []Report{}
	for _, n := range list {
		var launchedAt time.Time
		launchedAt, _ = time.Parse(time.RFC3339, xmlquery.FindOne(n, "LAUNCH_DATETIME").InnerText())

		var expiresAt time.Time
		expiresAt, _ = time.Parse(time.RFC3339, xmlquery.FindOne(n, "EXPIRATION_DATETIME").InnerText())

		reports = append(reports, Report{
			ID:                 xmlquery.FindOne(n, "ID").InnerText(),
			Title:              xmlquery.FindOne(n, "TITLE").InnerText(),
			Type:               xmlquery.FindOne(n, "TYPE").InnerText(),
			OutputFormat:       xmlquery.FindOne(n, "OUTPUT_FORMAT").InnerText(),
			Size:               xmlquery.FindOne(n, "SIZE").InnerText(),
			UserLogin:          xmlquery.FindOne(n, "USER_LOGIN").InnerText(),
			LaunchDatetime:     launchedAt,
			ExpirationDatetime: expiresAt,
		})
	}

	return reports
}
