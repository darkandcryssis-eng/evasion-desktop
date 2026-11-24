package ruguard

import (
	"strings"
)

var ruZones = []string{".ru", ".su", ".xn--p1ai", ".рф", ".xn--80adxhks", ".москва", ".xn--p1acf", ".рус", ".moscow", ".tatar"}

var ruServices = []string{
	"vk.com", "vk.me", "vk.cc", "vkuser.net", "vkuservideo.net", "vk-cdn.net", "userapi.com", "vkvideo.com", "okcdn.com",
	"yandex.com", "yandex.net", "yandex.cloud", "yandex.kz", "yandex.by", "yastatic.net", "yandexcloud.net", "ya.cc", "dzeninfra.net",
	"mycdn.me", "imgsmail.com", "sberbank.com", "sber.me", "sbrf.com", "tbank-online.com", "tinkoff.com", "tochka.com",
	"ozone.com", "ozonusercontent.com", "wbstatic.net", "wbbasket.com", "avito.st", "2gis.com", "kaspersky.com", "rt.com", "mts.com",
}

// IsRussian сообщает, относится ли домен к российским зонам или сервисам.
func IsRussian(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(d, "*")
	d = strings.Trim(d, ".")
	if d == "" {
		return false
	}
	for _, zone := range ruZones {
		if strings.HasSuffix(d, zone) || d == strings.TrimPrefix(zone, ".") {
			return true
		}
	}
	for _, service := range ruServices {
		if d == service || strings.HasSuffix(d, "."+service) {
			return true
		}
	}
	return false
}
