package forwardsc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type AnalysisRequest struct {
	Query      Query  `json:"query"`
	SourceType string `json:"sourceType"`
	Type       string `json:"type"`
}

type Query struct {
	Type        string   `json:"type"`
	Tool        string   `json:"tool"`
	StartOffset int      `json:"startOffset"`
	EndOffset   int      `json:"endOffset"`
	Filters     []Filter `json:"filters"`
}

type Filter struct {
	FilterName string `json:"filterName"`
	Operator   string `json:"operator"`
	Value      string `json:"value"`
}

type AnalysisEnvelope struct {
	Type      string           `json:"type"`
	Response  AnalysisResponse `json:"response"`
	ErrorCode int              `json:"error_code"`
	ErrorMsg  string           `json:"error_msg"`
}

type AnalysisResponse struct {
	TotalRecords    int         `json:"totalRecords"`
	ReturnedRecords int         `json:"returnedRecords"`
	StartOffset     int         `json:"startOffset"`
	EndOffset       int         `json:"endOffset"`
	Results         []SumipHost `json:"results"`
}

type SumipHost struct {
	IP               string `json:"ip,omitempty"`
	DNSName          string `json:"dnsName,omitempty"`
	MACAddress       string `json:"macAddress,omitempty"`
	Score            string `json:"score,omitempty"`
	SeverityMedium   string `json:"severityMedium,omitempty"`
	SeverityHigh     string `json:"severityHigh,omitempty"`
	SeverityCritical string `json:"severityCritical,omitempty"`
}

func (r AnalysisRequest) Validate() error {
	if r.Query.Tool != "sumip" {
		return fmt.Errorf("unsupported query.tool %q", r.Query.Tool)
	}
	if r.Query.Type != "vuln" || r.Type != "vuln" {
		return errors.New("query.type and type must both be 'vuln'")
	}
	if r.Query.EndOffset < r.Query.StartOffset || r.Query.StartOffset < 0 {
		return errors.New("invalid offsets")
	}
	return nil
}

func (r AnalysisRequest) DaysAgo() (int, error) {
	for _, filter := range r.Query.Filters {
		if strings.EqualFold(filter.FilterName, "lastSeen") {
			parts := strings.Split(filter.Value, ":")
			if len(parts) != 2 {
				return 0, fmt.Errorf("invalid lastSeen format %q", filter.Value)
			}
			daysAgo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return 0, fmt.Errorf("invalid daysAgo in lastSeen %q: %w", filter.Value, err)
			}
			return daysAgo, nil
		}
	}
	return 0, errors.New("lastSeen filter is required")
}

func EmptyEnvelope(startOffset, endOffset int) AnalysisEnvelope {
	return AnalysisEnvelope{
		Type:      "regular",
		ErrorCode: 0,
		ErrorMsg:  "",
		Response: AnalysisResponse{
			TotalRecords:    0,
			ReturnedRecords: 0,
			StartOffset:     startOffset,
			EndOffset:       endOffset,
			Results:         []SumipHost{},
		},
	}
}
