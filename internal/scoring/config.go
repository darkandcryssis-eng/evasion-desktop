package scoring

import (
	"errors"
	"fmt"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
)

// Config задаёт параметры оценки.
//
// Все значения принадлежат конфигурации движка (10.1). Значения по умолчанию
// следуют заданию (5.5, 5.7) и собраны в DefaultConfig, чтобы в одном месте
// было видно, чем движок руководствуется.
type Config struct {
	// HalfLife — полужизнь оценки: за это время вклад наблюдения уменьшается
	// вдвое. Задаёт скорость забывания.
	HalfLife time.Duration

	// Weights — веса исходов. Градуированы, а не двоичны: замедление — не то
	// же самое, что обрыв.
	WeightOK           float64
	WeightThrottled    float64
	WeightFail         float64
	WeightInconclusive float64

	// MinObservations, MaxObservations — границы требуемого объёма наблюдений
	// для перехода «кандидат → проверяется» (5.5).
	//
	// Границы жёсткие. Ниже нижней короткую удачную серию легко набрать
	// случайно; выше верхней проверка одного кандидата становится дороже
	// пользы от него.
	MinObservations int
	MaxObservations int

	// PromoteLowerBound — нижняя граница доверительного интервала доли
	// успехов, необходимая для повышения.
	PromoteLowerBound float64

	// Confidence — уровень доверия для интервала, в единицах стандартного
	// отклонения. Например, 1.96 соответствует примерно 95%.
	ConfidenceZ float64

	// SuperiorityMargin — насколько претендент должен быть лучше действующей
	// стратегии, чтобы его вообще рассматривали к смене.
	SuperiorityMargin float64

	// BaselineMargin — насколько стратегия должна превосходить базовую линию
	// цели, чтобы успех засчитали ей, а не доступности цели.
	//
	// Без этого порога положительный исход двусмыслен: движок не отличает
	// «стратегия обошла DPI» от «цель и так не блокировалась», и бандит
	// поднимает оценку за чужую заслугу. Ровно это и случилось на первом
	// измерении: discord.gg прошёл рукопожатие со стратегией, но он доступен и
	// без неё.
	BaselineMargin float64

	// FailureStreak — сколько провалов подряд считать срывом. Быстрый контур
	// реакции: ждать затухания оценки в этом случае слишком долго.
	FailureStreak int

	// InconclusiveShareEscalate — доля неопределённых исходов, выше которой
	// требуемый объём наблюдений поднимается до верхней границы.
	InconclusiveShareEscalate float64
}

// DefaultConfig возвращает значения по умолчанию из задания (5.5, 5.7).
func DefaultConfig() Config {
	return Config{
		HalfLife: 6 * time.Hour,

		WeightOK:           1,
		WeightThrottled:    -0.7,
		WeightFail:         -1,
		WeightInconclusive: 0,

		MinObservations: 20,
		MaxObservations: 60,

		PromoteLowerBound: 0.8,
		// Примерно 95% доверия. Значение именно такое, а не «круглое»,
		// потому что это квантиль нормального распределения, а не настройка
		// вкуса.
		ConfidenceZ: 1.96,

		SuperiorityMargin: 0.15,
		FailureStreak:     3,

		// Задание такого числа не называет: базовой пробы в нём нет вовсе, она
		// выведена из двусмысленности первого измерения.
		//
		// Значение подтверждено прогоном, а не расчётом на бумаге
		// (TestBaselineVolumeRegulatesItself): при нём и при прочих значениях
		// по умолчанию безупречный кандидат (25 успехов из 25) получает кредит
		// после двух подряд провалов базовой пробы, а после одного — ещё нет.
		// Единственного провала и не должно хватать: он случается при обычном
		// обрыве связи. Кандидату послабее требуется больше провалов базовой
		// линии, и это правильно — порог сравнивает разницу, в которую входит
		// неопределённость обеих сторон.
		BaselineMargin: 0.2,

		// Треть неопределённых исходов — уже повод не верить измерению и
		// требовать больше наблюдений.
		InconclusiveShareEscalate: 0.33,
	}
}

// validate проверяет согласованность параметров.
//
// Проверка нужна потому, что несогласованные пороги не ломают работу явно, а
// тихо меняют поведение автопилота: например, при нижней границе объёма больше
// верхней ни один кандидат никогда не будет повышен, и выяснялось бы это по
// отсутствию результата, а не по ошибке.
func (c Config) validate() error {
	switch {
	case c.HalfLife <= 0:
		return errors.New("scoring: полужизнь оценки должна быть положительной")
	case c.MinObservations <= 0:
		return errors.New("scoring: нижняя граница объёма наблюдений должна быть положительной")
	case c.MaxObservations < c.MinObservations:
		return fmt.Errorf("scoring: верхняя граница объёма %d меньше нижней %d",
			c.MaxObservations, c.MinObservations)
	case c.PromoteLowerBound <= 0 || c.PromoteLowerBound >= 1:
		return fmt.Errorf("scoring: порог доли успехов %v вне интервала (0, 1)", c.PromoteLowerBound)
	case c.ConfidenceZ <= 0:
		return errors.New("scoring: уровень доверия должен быть положительным")
	case c.FailureStreak <= 0:
		return errors.New("scoring: срыв по провалам должен быть положительным")
	case c.WeightOK <= 0:
		return errors.New("scoring: вес успеха должен быть положительным")
	case c.WeightFail >= 0:
		return errors.New("scoring: вес провала должен быть отрицательным")
	case c.InconclusiveShareEscalate <= 0 || c.InconclusiveShareEscalate > 1:
		return fmt.Errorf("scoring: доля неопределённых %v вне интервала (0, 1]",
			c.InconclusiveShareEscalate)
	case c.BaselineMargin <= 0 || c.BaselineMargin >= 1:
		// Нулевой порог запрещён намеренно: он означал бы «любое превосходство
		// над базовой линией считается», то есть возвращал бы ту самую
		// двусмысленность, против которой порог и введён. Единица и выше
		// недостижимы — превзойти базовую линию на всю шкалу нельзя.
		return fmt.Errorf("scoring: порог превосходства над базовой линией %v вне интервала (0, 1)",
			c.BaselineMargin)
	}
	return nil
}

// weightOf возвращает вес исхода.
func (c Config) weightOf(o core.Outcome) float64 {
	switch o {
	case core.OutcomeOK:
		return c.WeightOK
	case core.OutcomeThrottled:
		return c.WeightThrottled
	case core.OutcomeFail:
		return c.WeightFail
	default:
		return c.WeightInconclusive
	}
}
