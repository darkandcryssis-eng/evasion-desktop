package interception

import (
	"runtime"
	"strings"
	"testing"
)

// TestResultDistinguishesCleanFromUnchecked — «не нашли» и «не искали» обязаны
// различаться.
//
// Это то же правило, на котором проект стоит с самого начала, и здесь оно
// опаснее обычного: выдав отсутствие проверки за чистую обстановку, doctor
// сообщил бы «конфликтов нет» там, где конфликтов не искали, а прогон объявил
// бы измерение чистым, не имея на то оснований. Пустой срез сам по себе
// ответить на этот вопрос не может.
func TestResultDistinguishesCleanFromUnchecked(t *testing.T) {
	cases := []struct {
		name  string
		res   Result
		clean bool
		found bool
	}{
		{
			name:  "искали и ничего не нашли",
			res:   Result{Supported: true},
			clean: true,
		},
		{
			name:  "не искали вовсе",
			res:   Result{Supported: false},
			clean: false,
		},
		{
			name:  "искали, но не до конца",
			res:   Result{Supported: true, Partial: true},
			clean: false,
		},
		{
			name:  "нашли",
			res:   Result{Supported: true, Tools: []Tool{{Kind: KindProcess, Name: "winws.exe"}}},
			clean: false,
			found: true,
		},
		{
			name:  "нашли, и поиск был неполным",
			res:   Result{Supported: true, Partial: true, Tools: []Tool{{Name: "zapret"}}},
			clean: false,
			found: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.res.Clean(); got != c.clean {
				t.Fatalf("Clean = %v, ожидалось %v", got, c.clean)
			}
			if got := c.res.Found(); got != c.found {
				t.Fatalf("Found = %v, ожидалось %v", got, c.found)
			}
		})
	}
}

// TestFindIsHonestAboutPlatform — поиск сообщает, применим ли он здесь.
//
// На не-Windows результат обязан быть неприменимым, а не чистым: движок и
// средства перехвата windows-only (3.1), и отсутствие находок в песочнице
// разработки измерением не является.
func TestFindIsHonestAboutPlatform(t *testing.T) {
	res := Find()
	if runtime.GOOS == "windows" {
		if !res.Supported {
			t.Fatal("на Windows поиск обязан быть применим")
		}
		return
	}
	if res.Supported {
		t.Fatal("вне Windows поиск неприменим и обязан это сообщать")
	}
	if res.Clean() {
		t.Fatal("неприменимый поиск не вправе объявлять обстановку чистой")
	}
	if len(res.Notes) == 0 {
		t.Fatal("неприменимость обязана быть объяснена: иначе пустой ответ необъясним")
	}
}

// TestDriverTellsItselfApart — драйвер отличается от средства обхода.
//
// Потребители относятся к ним по-разному: прогон не останавливает измерение
// из-за загруженного драйвера без процесса, а doctor на этапе 0 сообщает о нём
// как о сведении, а не как о конфликте. Спутав их, прогон падал бы на машине,
// где перехватчик был выключен, но драйвер остался загруженным.
func TestDriverTellsItselfApart(t *testing.T) {
	cases := []struct {
		tool   Tool
		driver bool
	}{
		{Tool{Kind: KindService, Name: "WinDivert"}, true},
		{Tool{Kind: KindService, Name: "WinDivert14"}, true},
		{Tool{Kind: KindService, Name: "windivert"}, true},
		{Tool{Kind: KindService, Name: "zapret"}, false},
		{Tool{Kind: KindProcess, Name: "winws.exe"}, false},
		// Имя процесса, начинающееся на windivert, драйвером не является:
		// драйвер — это служба.
		{Tool{Kind: KindProcess, Name: "windivert.exe"}, false},
	}
	for _, c := range cases {
		if got := c.tool.IsDriver(); got != c.driver {
			t.Fatalf("%+v: IsDriver = %v, ожидалось %v", c.tool, got, c.driver)
		}
	}
}

// TestKnownListsAreUsableAndIsolated — список имён отдаётся копией и пригоден
// к показу.
//
// Копия обязательна: список — единственный источник правил обнаружения, и
// потребитель, случайно изменивший его, поменял бы поведение и doctor, и
// прогонов сразу.
func TestKnownListsAreUsableAndIsolated(t *testing.T) {
	for _, get := range []func() []string{KnownProcesses, KnownServices} {
		list := get()
		if len(list) == 0 {
			t.Fatal("список известных средств пуст: обнаружению нечего искать")
		}
		list[0] = "подменено"
		if again := get(); again[0] == "подменено" {
			t.Fatal("список отдаётся не копией: потребитель может изменить правила обнаружения")
		}
	}

	// Имена процессов обязаны быть с расширением, службы — без: по этому
	// признаку их различают системные команды, и перепутанное имя молча
	// никогда не совпадёт.
	for _, name := range KnownProcesses() {
		if !strings.HasSuffix(name, ".exe") {
			t.Fatalf("имя процесса %q без расширения .exe: tasklist его не найдёт", name)
		}
	}
	for _, name := range KnownServices() {
		if strings.HasSuffix(name, ".exe") {
			t.Fatalf("имя службы %q с расширением .exe: sc query его не найдёт", name)
		}
	}
}

// TestOEMDecoding — вывод системных команд Windows переводится в читаемый вид.
//
// Проверяется на любой платформе намеренно: сама неполадка возможна только на
// русской Windows, но логика перевода чистая, и держать её непроверенной
// незачем. Именно эта нечитаемость («�� 㤠���� ����� 䠩�») встретила
// владельца, когда возврат zapret не сработал.
func TestOEMDecoding(t *testing.T) {
	t.Run("cp866 переводится", func(t *testing.T) {
		// «Отказано в доступе» в кодовой странице 866.
		raw := []byte{0x8E, 0xE2, 0xAA, 0xA0, 0xA7, 0xA0, 0xAD, 0xAE, 0x20, 0xA2, 0x20, 0xA4, 0xAE, 0xE1, 0xE2, 0xE3, 0xAF, 0xA5}
		got := oemToUTF8(raw)
		if got != "Отказано в доступе" {
			t.Fatalf("перевод дал %q", got)
		}
	})

	t.Run("готовый UTF-8 не портится", func(t *testing.T) {
		// Если кодовая страница консоли переключена, вывод приходит уже в
		// UTF-8, и повторный перевод превратил бы его в мусор.
		const want = "служба не установлена"
		if got := oemToUTF8([]byte(want)); got != want {
			t.Fatalf("годный UTF-8 испорчен: %q", got)
		}
	})

	t.Run("ASCII не меняется", func(t *testing.T) {
		const want = "STATE : 4 RUNNING"
		if got := oemToUTF8([]byte(want)); got != want {
			t.Fatalf("ASCII испорчен: %q", got)
		}
	})
}

// TestFirstLine — из многострочного вывода берётся первая осмысленная строка.
func TestFirstLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"\r\n\r\n", ""},
		{"\r\n  ответ  \r\nвторой", "ответ"},
		{"первый\nвторой", "первый"},
	}
	for _, c := range cases {
		if got := firstLine(c.in); got != c.want {
			t.Fatalf("firstLine(%q) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
}

// TestParseServiceQuery — разбор ответа sc query.
//
// Самая непрозрачная часть обнаружения, и проверяется она здесь, а не на
// Windows, именно потому, что воспроизводится только там. Главное свойство —
// третье состояние: «службы нет» и «опросить не смогли» обязаны различаться,
// иначе отказ в правах выглядел бы чистой обстановкой.
func TestParseServiceQuery(t *testing.T) {
	cases := []struct {
		name                  string
		out                   string
		running, notInstalled bool
	}{
		{
			name:    "служба работает (английская система)",
			out:     "SERVICE_NAME: zapret\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING",
			running: true,
		},
		{
			name: "служба работает (слово переведено)",
			// Ровно тот случай, ради которого разбор опирается на код, а не на
			// слово: на русской системе RUNNING печатается по-русски.
			out:     "SERVICE_NAME: zapret\n        STATE              : 4  РАБОТАЕТ",
			running: true,
		},
		{
			name: "служба остановлена",
			out:  "SERVICE_NAME: zapret\n        STATE              : 1  STOPPED",
		},
		{
			name:         "службы нет вовсе",
			out:          "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\nУказанная служба не установлена.",
			notInstalled: true,
		},
		{
			name: "отказано в доступе — это не ответ «не запущена»",
			out:  "[SC] OpenSCManager FAILED 5:\n\nОтказано в доступе.",
			// Ни running, ни notInstalled: оба ложны, и вызывающий обязан
			// счесть опрос несостоявшимся.
		},
		{
			name: "имя с цифрой 4 не считается работающей службой",
			// WinDivert14 в остановленном состоянии: цифра 4 есть в имени, но
			// состояние другое. Прежняя проверка на подстроку «4» здесь бы
			// ошиблась, поэтому ищется «: 4».
			out: "SERVICE_NAME: WinDivert14\n        STATE              : 1  STOPPED",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			running, notInstalled := parseServiceQuery(c.out)
			if running != c.running || notInstalled != c.notInstalled {
				t.Fatalf("разбор дал running=%v notInstalled=%v, ожидалось running=%v notInstalled=%v",
					running, notInstalled, c.running, c.notInstalled)
			}
		})
	}
}

// TestContainsFold — сравнение имён без учёта регистра.
//
// Нужно потому, что имена процессов и служб в Windows регистр не различают, а
// системные команды печатают их как им угодно: tasklist отдаёт «winws.exe», а
// фильтр мог задаваться как «WinWS.exe».
func TestContainsFold(t *testing.T) {
	cases := []struct {
		s, sub string
		want   bool
	}{
		{"Image Name\nWinWS.EXE  1234", "winws.exe", true},
		{"winws.exe", "WINWS.EXE", true},
		{"нет запущенных задач", "winws.exe", false},
		{"", "winws.exe", false},
		{"winws.exe", "", true},
	}
	for _, c := range cases {
		if got := containsFold(c.s, c.sub); got != c.want {
			t.Fatalf("containsFold(%q, %q) = %v, ожидалось %v", c.s, c.sub, got, c.want)
		}
	}
}
