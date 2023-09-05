package qualys

import (
	"time"
)

type IdUrl struct {
	ID  string
	Url string
}

type VulnDetails struct {
	QID              string
	Title            string
	Category         string
	Severity         int
	Threat           string
	Impact           string
	Solution         string
	PciFlag          bool
	CveIds           []IdUrl
	VendorReferences []IdUrl
	LastUpdate       time.Time
}

type VulnInfo struct {
	QID        string
	Type       string
	SSL        bool
	Result     string
	TimesFound int
	VulnStatus string
	Qds        int
	LastFound  time.Time
}

type Host struct {
	IP                         string
	HostId                     string
	DNS                        string
	TrackingMethod             string
	AssetTags                  []string
	AssetGroups                []string

	CloudProvider string
	CloudService string
	CloudResourceId string

	OperatingSystem            string
	Vulnerabilities            []VulnInfo
	Owner                      string
	Comments                   string
	LastVulnScanDatetime       time.Time
	LastVmScannedDate          time.Time
	LastVmScannedDuration      int
	LastVmAuthScannedDate      time.Time
	LastComplianceScanDatetime time.Time
	LastVmAuthSscannedDuration int
	AssetGroupIds              []int
}

type HostVulnerabilty struct {
	// Fields from Host
	QID             string
	IP              string
	HostId          string
	DNS             string
	TrackingMethod  string
	AssetTags       []string
	AssetGroups     []string
	OperatingSystem string

	// Fields from VulnDetails
	Title            string
	Category         string
	Severity         int
	Threat           string
	Impact           string
	Solution         string
	PciFlag          bool
	CveIds           []IdUrl
	VendorReferences []IdUrl
	LastFound        time.Time
}

type Report struct {
	ID                 string
	Title              string
	Type               string
	UserLogin          string
	OutputFormat       string
	LaunchDatetime     time.Time
	ExpirationDatetime time.Time
	Size               string
}
