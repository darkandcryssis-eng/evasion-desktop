package ruguard

import "testing"

func TestIsRussian(t *testing.T) {
	for _, domain := range []string{
		"gosuslugi.ru", "*.sberbank.ru", "online.sberbank.ru.", "VK.com",
		"st.vk.com", "yandex.net", "кто.рф", "xn--80aswg.xn--p1ai",
		"mail.ru", "example.su", "userapi.com",
	} {
		if !IsRussian(domain) {
			t.Errorf("%q should be considered Russian", domain)
		}
	}
	for _, domain := range []string{
		"discord.com", "googlevideo.com", "youtube.com", "truvk.com",
		"ru.example.com", "rutracker.org", "", "notvk.com.example", "cyandex.com",
	} {
		if IsRussian(domain) {
			t.Errorf("%q should not be considered Russian", domain)
		}
	}
}
