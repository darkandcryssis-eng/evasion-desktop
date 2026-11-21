package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
)

// readFileForTest читает файл примера. Отдельная обёртка, чтобы путь
// вычислялся одинаково в обоих тестах.
func readFileForTest(path string) ([]byte, error) {
	return os.ReadFile(filepath.Clean(path))
}

// examplePath — путь к примеру конфига из репозитория.
const examplePath = "../../examples/config.json"

// TestExampleConfigLoads проверяет, что пример конфига из репозитория
// действительно работает.
//
// Тест нужен потому, что пример — это обещание. Он попадает в руки человека
// раньше любого кода, и если он перестал разбираться (переименовали поле,
// сменили токен, добавили обязательный раздел), первое знакомство с движком
// кончается ошибкой разбора. Такую поломку не поймает ни один тест, кроме
// этого: пример лежит вне пакетов и ни на что не влияет, пока его не прочтут.
//
// Разбор здесь настоящий, через Load, то есть с чтением файла и всеми
// проверками. Именно так его прочитает движок.
func TestExampleConfigLoads(t *testing.T) {
	cfg, err := Load(filepath.Clean(examplePath))
	if err != nil {
		t.Fatalf("пример конфига не разбирается: %v", err)
	}

	// Проверяется не «что-то загрузилось», а то, ради чего пример существует:
	// он обязан показывать настроенный радиус, стратегию и точку наблюдения.
	// Пример, в котором нечего применять, учил бы неверному.
	if len(cfg.Groups) == 0 {
		t.Fatal("в примере нет групп доменов: радиус поражения не показан")
	}
	if cfg.Strategy == nil {
		t.Fatal("в примере нет стратегии: применять было бы нечего")
	}
	if cfg.Vantage.Operator == "" || cfg.Vantage.Region == "" {
		t.Fatal("в примере не задана точка наблюдения, а без неё оценки некуда отнести (6.1)")
	}
	if cfg.Vantage.Access == core.AccessUnknown {
		t.Fatal("в примере не задан тип доступа")
	}
	if len(cfg.ControlTargets) == 0 {
		t.Fatal("в примере нет контрольных целей, а по ним измеряется побочный вред (4.5)")
	}

	// Стратегия примера должна быть исполнима на этапе 0, иначе первый же
	// запуск кончится прозрачным пропуском и выглядеть это будет как
	// неработающий обход.
	if cfg.Autopilot.TrialPermille > trialPermilleCeilingForExample() {
		t.Fatalf("доля проверки в примере %d промилле выше потолка", cfg.Autopilot.TrialPermille)
	}
}

// trialPermilleCeilingForExample возвращает потолок доли проверки, чтобы тест
// не повторял число из control.
func trialPermilleCeilingForExample() int {
	return DefaultAutopilot().TrialPermille
}

// TestExampleConfigHasNoBOM: метка BOM в JSON запрещена — строгий разбор в Go
// на ней падает. Запрет уже проверяется пакетом repohygiene по всему
// репозиторию, но пример стоит отдельного упоминания: его правят руками чаще
// всего, а в PowerShell 5.1 метка добавляется сама (Set-Content).
func TestExampleConfigHasNoBOM(t *testing.T) {
	data, err := readFileForTest(examplePath)
	if err != nil {
		t.Fatalf("чтение примера: %v", err)
	}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		t.Fatal("в примере конфига метка BOM: строгий разбор JSON на ней падает")
	}
}

// TestExampleStrategiesLoad проверяет, что ВСЕ кандидаты стратегий из
// examples/strategies/ разбираются через Load. Они кладутся в репозиторий,
// чтобы не создавать JSON руками; тест ловит опечатку в токене или структуре
// (в т.ч. в новых приёмах md5sig/ipv6_ext) раньше, чем файл попадёт в руки
// человека на боевом прогоне.
func TestExampleStrategiesLoad(t *testing.T) {
	paths, err := filepath.Glob("../../examples/strategies/*.json")
	if err != nil {
		t.Fatalf("поиск примеров стратегий: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("в examples/strategies не найдено ни одного .json")
	}
	for _, p := range paths {
		cfg, err := Load(filepath.Clean(p))
		if err != nil {
			t.Errorf("%s не разбирается: %v", filepath.Base(p), err)
			continue
		}
		if cfg.Strategy == nil {
			t.Errorf("%s: нет стратегии", filepath.Base(p))
		}
	}
}
