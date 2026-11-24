package main

import "testing"

func TestDiscordUpdateURL(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
		fail bool
	}{
		{
			name: "delta",
			body: `{"deltas":[{"url":""},{"url":"https://stable.dl2.discordapp.net/delta"}],"full":{"url":"https://stable.dl2.discordapp.net/full"}}`,
			want: "https://stable.dl2.discordapp.net/delta",
		},
		{
			name: "full when deltas are empty",
			body: `{"deltas":[],"full":{"url":"https://stable.dl2.discordapp.net/full"}}`,
			want: "https://stable.dl2.discordapp.net/full",
		},
		{
			name: "invalid JSON",
			body: `{"full":`,
			fail: true,
		},
		{
			name: "no URLs",
			body: `{"deltas":[{"url":""}],"full":{"url":""}}`,
			fail: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := discordUpdateURL([]byte(test.body))
			if test.fail {
				if err == nil {
					t.Fatalf("discordUpdateURL(%q) succeeded with %q", test.body, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("discordUpdateURL() = %q, want %q", got, test.want)
			}
		})
	}
}
