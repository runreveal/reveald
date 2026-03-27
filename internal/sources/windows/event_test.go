package windows

import (
	"encoding/xml"
	"testing"
)

func TestParseKeyValuePairs(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   map[string]string
		wantNi bool // want nil
	}{
		{
			name:  "powershell classic format",
			input: "\tDetailSequence=1\r\n\tDetailTotal=1\r\n\r\n\tSequenceNumber=543\r\n\r\n\tUserId=WORKGROUP\\SYSTEM\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.17763.6414\r\n",
			want: map[string]string{
				"DetailSequence": "1",
				"DetailTotal":    "1",
				"SequenceNumber": "543",
				"UserId":         "WORKGROUP\\SYSTEM",
				"HostName":       "ConsoleHost",
				"HostVersion":    "5.1.17763.6414",
			},
		},
		{
			name:   "plain text no pairs",
			input:  "Write-Output \"hello world\"\n",
			wantNi: true,
		},
		{
			name:   "single pair below threshold",
			input:  "\tKey=Value\r\n",
			wantNi: true,
		},
		{
			name:   "empty string",
			input:  "",
			wantNi: true,
		},
		{
			name:  "value containing equals sign",
			input: "\tCommandLine=powershell -c \"1+1=2\"\r\n\tUser=SYSTEM\r\n",
			want: map[string]string{
				"CommandLine": "powershell -c \"1+1=2\"",
				"User":        "SYSTEM",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseKeyValuePairs(tt.input)
			if tt.wantNi {
				if got != nil {
					t.Errorf("parseKeyValuePairs() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("parseKeyValuePairs() = nil, want non-nil")
			}
			if len(got) != len(tt.want) {
				t.Errorf("parseKeyValuePairs() returned %d pairs, want %d", len(got), len(tt.want))
			}
			for k, wantV := range tt.want {
				if gotV, ok := got[k]; !ok {
					t.Errorf("missing key %q", k)
				} else if gotV != wantV {
					t.Errorf("key %q = %q, want %q", k, gotV, wantV)
				}
			}
		})
	}
}

func TestToJSONEvent_NamedData(t *testing.T) {
	// Sysmon-style XML with named Data elements
	input := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
		<System>
			<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
			<EventID>1</EventID>
			<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
			<Computer>WORKSTATION</Computer>
			<TimeCreated SystemTime="2026-03-27T21:00:00.000Z"/>
			<Security UserID="S-1-5-18"/>
		</System>
		<EventData>
			<Data Name="Image">C:\Windows\System32\cmd.exe</Data>
			<Data Name="CommandLine">cmd.exe /c dir</Data>
			<Data Name="User">SYSTEM</Data>
		</EventData>
	</Event>`

	var xe xmlEvent
	if err := xml.Unmarshal([]byte(input), &xe); err != nil {
		t.Fatal(err)
	}

	event := xe.ToJSONEvent()

	if len(event.EventData) != 0 {
		t.Errorf("EventData should be empty, got %v", event.EventData)
	}
	if got := event.EventDataMap["Image"]; got != `C:\Windows\System32\cmd.exe` {
		t.Errorf("EventDataMap[Image] = %q", got)
	}
	if got := event.EventDataMap["CommandLine"]; got != "cmd.exe /c dir" {
		t.Errorf("EventDataMap[CommandLine] = %q", got)
	}
}

func TestToJSONEvent_UnnamedKeyValueData(t *testing.T) {
	// PowerShell classic style — unnamed Data with key=value content
	input := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
		<System>
			<Provider Name="PowerShell" Guid=""/>
			<EventID>800</EventID>
			<Channel>Windows PowerShell</Channel>
			<Computer>WORKSTATION</Computer>
			<TimeCreated SystemTime="2026-03-27T21:00:00.000Z"/>
			<Security UserID=""/>
		</System>
		<EventData>
			<Data>some script text</Data>
			<Data>	DetailSequence=1
	DetailTotal=1

	SequenceNumber=543

	UserId=WORKGROUP\SYSTEM
	HostName=ConsoleHost
	HostVersion=5.1.17763.6414
</Data>
		</EventData>
	</Event>`

	var xe xmlEvent
	if err := xml.Unmarshal([]byte(input), &xe); err != nil {
		t.Fatal(err)
	}

	event := xe.ToJSONEvent()

	// The first Data element is plain text (no key=value pairs), should stay in EventData
	if len(event.EventData) != 1 {
		t.Errorf("EventData length = %d, want 1", len(event.EventData))
	}
	if len(event.EventData) > 0 && event.EventData[0] != "some script text" {
		t.Errorf("EventData[0] = %q, want %q", event.EventData[0], "some script text")
	}

	// The second Data element has key=value pairs, should be parsed into EventDataMap
	if got := event.EventDataMap["HostName"]; got != "ConsoleHost" {
		t.Errorf("EventDataMap[HostName] = %q, want %q", got, "ConsoleHost")
	}
	if got := event.EventDataMap["UserId"]; got != `WORKGROUP\SYSTEM` {
		t.Errorf("EventDataMap[UserId] = %q, want %q", got, `WORKGROUP\SYSTEM`)
	}
	if got := event.EventDataMap["DetailSequence"]; got != "1" {
		t.Errorf("EventDataMap[DetailSequence] = %q, want %q", got, "1")
	}
}

func TestToJSONEvent_UnnamedPlainTextOnly(t *testing.T) {
	// Data elements that are plain text should remain in EventData
	input := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
		<System>
			<Provider Name="TestProvider" Guid=""/>
			<EventID>1000</EventID>
			<Channel>Application</Channel>
			<Computer>WORKSTATION</Computer>
			<TimeCreated SystemTime="2026-03-27T21:00:00.000Z"/>
			<Security UserID=""/>
		</System>
		<EventData>
			<Data>Hello, World!</Data>
			<Data>Another message</Data>
		</EventData>
	</Event>`

	var xe xmlEvent
	if err := xml.Unmarshal([]byte(input), &xe); err != nil {
		t.Fatal(err)
	}

	event := xe.ToJSONEvent()

	if len(event.EventData) != 2 {
		t.Errorf("EventData length = %d, want 2", len(event.EventData))
	}
	if len(event.EventDataMap) != 0 {
		t.Errorf("EventDataMap should be empty, got %v", event.EventDataMap)
	}
}
