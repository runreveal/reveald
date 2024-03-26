package nginx_syslog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseNginxLog(t *testing.T) {
	// Define test cases
	var tests = []struct {
		name    string
		logLine string
		want    *nginxLogEntry
		wantErr bool
	}{
		{
			name:    "StandardLogEntry",
			logLine: `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"`,
			want: &nginxLogEntry{
				RemoteAddr:    "127.0.0.1",
				RemoteUser:    "frank",
				TimeLocal:     "10/Oct/2000:13:55:36 -0700",
				Request:       "GET /apache_pb.gif HTTP/1.0",
				Status:        "200",
				BodyBytesSent: "2326",
				HttpReferer:   "http://www.example.com/start.html",
				HttpUserAgent: "Mozilla/4.08 [en] (Win98; I ;Nav)",
			},
			wantErr: false,
		},
		{
			name:    "MissingFields",
			logLine: `- - - [-] "-" - - "-" "-"`,
			want: &nginxLogEntry{
				RemoteAddr:    "-",
				RemoteUser:    "-",
				TimeLocal:     "-",
				Request:       "-",
				Status:        "-",
				BodyBytesSent: "-",
				HttpReferer:   "-",
				HttpUserAgent: "-",
			},
			wantErr: false,
		},
		{
			name:    "MalformedEntry",
			logLine: `This is not a valid log line`,
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNginxLog(tt.logLine)

			if tt.wantErr {
				assert.Error(t, err, "Expected an error for test case: %v", tt.name)
			} else {
				assert.NoError(t, err, "Did not expect an error for test case: %v", tt.name)
			}
			assert.Equal(t, tt.want, got, "log should parse as anticipated")
		})
	}

}
